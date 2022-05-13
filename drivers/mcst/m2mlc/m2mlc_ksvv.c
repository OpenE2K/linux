/**
 * m2mlc_ksvv.c - M2MLC module device driver
 *
 * Network part
 */

#include <linux/jiffies.h>
#include <linux/crc32.h>

#include "m2mlc.h"
#include "m2mlc_ksvv.h"


/* 1024 msgs; 10 bit address; 11 bit ptrs */
#define MSGS_10BIT_MSK ((1 << 10) - 1)

/* 4096 dones; 13 bit address; 12 bit ptrs */
#define MSGS_12BIT_MSK ((1 << 12) - 1)

#define KSVV_GET_TYPE(u) ((((u).type_size) & 0xf000) >> 12)
#define KSVV_GET_SIZE(u) ((((u).type_size) & 0xfff) + 1)
#define KSVV_TYPE_SIZE(type, size) \
	((uint16_t)((((type) & 0xf) << 12) + (((size) - 1) & 0xfff)))


/**
 ******************************************************************************
 * INIT
 ******************************************************************************
 **/

/*
 * size parameter in 4K pages; not more 4 MB at once
 * Todo: add check of NUMA memory location (nume_movepages 0?)
 */
static void *ksvv_alloc_mem(m2mlc_npriv_t *npriv, uint32_t size, void **virt,
			    void **phys)
{
	void *useraddr = NULL;
	m2mlc_mem_ptrs_t mem_ptrs;
	ksvv_endpoint_t *endpoint = &npriv->ksvvendpoint;
	struct net_device *ndev = npriv->p_priv->ndev;


	if (endpoint->cur_mem >= KSVV_MEM_SEGMENTS) {
		dev_err(&ndev->dev, "ERROR: max mem count reached\n");
		return NULL;
	}
	/* not more 256 MB */
	if ((size <= 0) || (size > 1024)) {
		dev_err(&ndev->dev,
			"ERROR: size %d too high (min 1 page; " \
			"max 1024 pages; page=4K)\n", size);
		return NULL;
	}
	useraddr = dma_alloc_coherent(&ndev->dev, size * 4 * 1024,
				      (dma_addr_t *)(&(mem_ptrs.dmaaddr)),
				      GFP_KERNEL);
	if (!useraddr) {
		dev_err(&ndev->dev, "ERROR: Can't allocate memory\n");
		return NULL;
	}
	mem_ptrs.useraddr = (uint64_t)useraddr;
	mem_ptrs.bytes = size * 4 * 1024;

	DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev,
		"Alloc Mem: dmaaddr=0x%llX virtaddr=0x%llX " \
		"size=0x%llX(%lld), %d\n",
		mem_ptrs.dmaaddr, mem_ptrs.useraddr,
		mem_ptrs.len, mem_ptrs.len, endpoint->cur_mem);

	/* use data on buffer */
	endpoint->mems_ptrs[endpoint->cur_mem] = mem_ptrs;
	endpoint->cur_mem++;
	if (virt)
		*virt = (void *)(uintptr_t)mem_ptrs.useraddr;
	if (phys)
		*phys = (void *)(uintptr_t)mem_ptrs.dmaaddr;

	return (void *)(uintptr_t)mem_ptrs.useraddr;
} /* ksvv_alloc_mem */

static void ksvv_free_all_mem(m2mlc_npriv_t *npriv)
{
	ksvv_endpoint_t *endpoint = &npriv->ksvvendpoint;
	struct net_device *ndev = npriv->p_priv->ndev;
	m2mlc_mem_ptrs_t mem_ptrs;
	int i;


	for (i = 0; i < endpoint->cur_mem; i++) {
		mem_ptrs = endpoint->mems_ptrs[i];

		DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev,
			"Free Mem: dmaaddr=0x%llX virtaddr=0x%llX " \
			"size=0x%llX(%lld) nents=%ld, [%d]\n",
			mem_ptrs.dmaaddr, mem_ptrs.useraddr,
			mem_ptrs.len, mem_ptrs.len, mem_ptrs.nents, i);

		if (mem_ptrs.useraddr)
			dma_free_coherent(&ndev->dev, mem_ptrs.bytes,
					  (void *)mem_ptrs.useraddr,
					  mem_ptrs.dmaaddr);
	}
} /* ksvv_free_all_mem */

/*
 * Read initial values of ptrs
 */
static int ksvv_reinit_queue_ptr(m2mlc_npriv_t *npriv)
{
	int status = 0;
	ksvv_endpoint_t *endpoint = &npriv->ksvvendpoint;
	struct net_device *ndev = npriv->p_priv->ndev;
	volatile uint32_t *endpoint_regs = endpoint->endpoint_regs;


	endpoint->dma_0.r = endpoint_regs[M2MLC_RB_DMA_STR_PTRS >> 2];
	endpoint->dmadone_0.r = endpoint_regs[M2MLC_RB_DMA_DONE_PTRS >> 2];
	endpoint->mb_0.r = endpoint_regs[M2MLC_RB_MB_STR_PTRS >> 2];
	endpoint->mbdone_0.r = endpoint_regs[M2MLC_RB_MB_DONE_PTRS >> 2];
	endpoint->db_0.r = endpoint_regs[M2MLC_RB_DB_PTRS >> 2];

	if (endpoint->dma_0.p.r_tail != endpoint->dma_0.p.w_head) {
		dev_err(&ndev->dev,
			"ERROR: DMA Queue is not empty; tail=%d head=%d\n",
			endpoint->dma_0.p.r_tail,
			endpoint->dma_0.p.w_head);
		status = 4;
		goto exit_reg_init;
	}
	if (endpoint->dmadone_0.p.w_tail != endpoint->dmadone_0.p.r_head) {
		dev_err(&ndev->dev,
			"ERROR: DMA Done Queue is not empty; tail=%d head=%d\n",
			endpoint->dmadone_0.p.w_tail,
			endpoint->dmadone_0.p.r_head);
		status = 5;
		goto exit_reg_init;
	}
#if 0
	if (endpoint->mb_0.p.w_tail != endpoint->mb_0.p.r_head) {
		dev_err(&ndev->dev,
			"ERROR: Mailbox Queue is not empty; tail=%d head=%d\n",
			endpoint->mb_0.p.w_tail,
			endpoint->mb_0.p.r_head);
		status = 6;
		goto exit_reg_init;
	}
	if (endpoint->mbdone_0.p.w_tail != endpoint->mbdone_0.p.r_head) {
		dev_err(&ndev->dev,
			"ERROR: Mailbox done Queue is not empty; " \
			"tail=%d head=%d\n",
			endpoint->mbdone_0.p.w_tail,
			endpoint->mbdone_0.p.r_head);
		status = 7;
		goto exit_reg_init;
	}
#else
	endpoint->mb_0.p.w_tail = endpoint->mb_0.p.r_head;
	endpoint->mbdone_0.p.w_tail = endpoint->mbdone_0.p.r_head;

	endpoint_regs[M2MLC_RB_MB_STR_PTRS >> 2] = endpoint->mb_0.r;
	endpoint_regs[M2MLC_RB_MB_DONE_PTRS >> 2] = endpoint->mbdone_0.r;
#endif /* 0 */

	if (endpoint->db_0.p.w_tail != endpoint->db_0.p.r_head) {
		dev_err(&ndev->dev,
			"ERROR: Doorbell Queue is not empty; " \
			"tail=%d head=%d\n",
			endpoint->db_0.p.w_tail,
			endpoint->db_0.p.r_head);
		status = 8;
		goto exit_reg_init;
	}

	/* Enable Shadow copy */
	endpoint->dmadone_0.p.sce = 1;
	endpoint->mbdone_0.p.sce = 1;
	endpoint->db_0.p.sce = 1;
	endpoint_regs[M2MLC_RB_DMA_DONE_PTRS >> 2] = endpoint->dmadone_0.r;
	endpoint_regs[M2MLC_RB_MB_DONE_PTRS >> 2] = endpoint->mbdone_0.r;
	endpoint_regs[M2MLC_RB_DB_PTRS >> 2] = endpoint->db_0.r;
	/* Repeat write to get actual values in the Shadow Copy in mem */
	endpoint_regs[M2MLC_RB_DMA_DONE_PTRS >> 2] = endpoint->dmadone_0.r;
	endpoint_regs[M2MLC_RB_MB_DONE_PTRS >> 2] = endpoint->mbdone_0.r;
	endpoint_regs[M2MLC_RB_DB_PTRS >> 2] = endpoint->db_0.r;

	DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev,
		"PTRS[%d] SCE done; *_0: dma=%08x dmadone=%08x (SC:%08x) " \
		"mb=%08x mbdone=%08x (SC:%08x) db=%08x (SC:%08x)\n",
		CDEV_ENDPOINT_NET,
		endpoint->dma_0.r, endpoint->dmadone_0.r,
		endpoint->done_regs->dma_head_done_ptr,
		endpoint->mb_0.r, endpoint->mbdone_0.r,
		endpoint->done_regs->mb_write_done_ptr,
		endpoint->db_0.r, endpoint->done_regs->db_write_done_ptr);
	DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev,
		"PTRS[%d] SCE done; endp dma=%08x dmadone=%08x (SC:%08x) " \
		"mb=%08x mbdone=%08x (SC:%08x) db=%08x (SC:%08x)\n",
		CDEV_ENDPOINT_NET,
		endpoint_regs[M2MLC_RB_DMA_STR_PTRS>>2],
		endpoint_regs[M2MLC_RB_DMA_DONE_PTRS>>2],
		endpoint->done_regs->dma_head_done_ptr,
		endpoint_regs[M2MLC_RB_MB_STR_PTRS>>2],
		endpoint_regs[M2MLC_RB_MB_DONE_PTRS>>2],
		endpoint->done_regs->mb_write_done_ptr,
		endpoint_regs[M2MLC_RB_DB_PTRS>>2],
		endpoint->done_regs->db_write_done_ptr);

exit_reg_init:
	return status;
} /* ksvv_reinit_queue_ptr */

/*
 * Open endpoint
 * allocate endpoint and return in case of success
 */
int ksvv_open_endpoint(m2mlc_npriv_t *npriv)
{
	int status = 0;
	ksvv_endpoint_t *endpoint = &npriv->ksvvendpoint;
	struct net_device *ndev = npriv->p_priv->ndev;
	volatile uint32_t *endpoint_regs;
	int i;


	/* ENDPOINT Registers (BAR1) */
	endpoint_regs = npriv->p_priv->reg_base + RB_N(CDEV_ENDPOINT_NET);
	endpoint->endpoint_regs = endpoint_regs;

	/* FIXME: 20150713 */
	/* READ DMA Queue size [06:00] */
	endpoint_regs[M2MLC_RB_DMA_QUE_SIZE >> 2] = 64; /* 4096 */
	switch (endpoint_regs[M2MLC_RB_DMA_QUE_SIZE >> 2] & 0x7f) {
	case  0:
		endpoint->dma_queue_size = 32;
		break;
	case  1:
		endpoint->dma_queue_size = 64;
		break;
	case  2:
		endpoint->dma_queue_size = 128;
		break;
	case  4:
		endpoint->dma_queue_size = 256;
		break;
	case  8:
		endpoint->dma_queue_size = 512;
		break;
	case 16:
		endpoint->dma_queue_size = 1024;
		break;
	case 32:
		endpoint->dma_queue_size = 2048;
		break;
	case 64:
		endpoint->dma_queue_size = 4096;
		break;
	}
	endpoint->dma_queue_mask = endpoint->dma_queue_size - 1;
	endpoint->dma_queue_mask1 = (endpoint->dma_queue_size * 2) - 1;

#if 0
	/* PIO Payload Base Address (BAR2, 256b) */
	endpoint->pio_payload = \
		npriv->p_priv->buf_base + RB_N(CDEV_ENDPOINT_NET);

	endpoint->pio_done_queue = npriv->p_priv->pio_done_que_buff +
#ifdef USE_MUL2ALIGN
				   npriv->p_priv->pio_done_que_offset +
#endif /* USE_MUL2ALIGN */
				   RB_N(CDEV_ENDPOINT_NET);

	endpoint->pio_data_queue = npriv->p_priv->pio_data_que_buff +
#ifdef USE_MUL2ALIGN
				   npriv->p_priv->pio_data_que_offset +
#endif /* USE_MUL2ALIGN */
				   RB_N(CDEV_ENDPOINT_NET);
#endif /* 0 */

	/* Status flags & Done pointers (RAM, 3 * 4b = 12b) */
	endpoint->done_regs = npriv->p_priv->mdd_ret_buff[CDEV_ENDPOINT_NET];

#if 0
	/* Doorbell Queue Base Address (RAM, 256*8b) */
	endpoint->db_queue = npriv->p_priv->db_start_buff[CDEV_ENDPOINT_NET];
#endif /* 0 */

	/* DMA Descrs Queue Base Address (RAM) */
#ifdef USE_MUL2ALIGN
	endpoint->dma_desc_queue = \
		npriv->p_priv->dma_start_buff[CDEV_ENDPOINT_NET] +
		npriv->p_priv->dma_start_offset[CDEV_ENDPOINT_NET];
#else
	endpoint->dma_desc_queue = \
		npriv->p_priv->dma_start_buff[CDEV_ENDPOINT_NET];
#endif /* USE_MUL2ALIGN */

	/* DMA DONE Queue Base Address (RAM) */
#ifdef USE_MUL2ALIGN
	endpoint->dma_done_queue = \
		npriv->p_priv->dma_done_que_buff[CDEV_ENDPOINT_NET] +
		npriv->p_priv->dma_done_offset[CDEV_ENDPOINT_NET];
#else
	endpoint->dma_done_queue = \
		npriv->p_priv->dma_done_que_buff[CDEV_ENDPOINT_NET];
#endif /* USE_MUL2ALIGN */

	/* Mailbox DONE Queue Base Address (RAM) */
#ifdef USE_MUL2ALIGN
	endpoint->mb_done_queue = \
		npriv->p_priv->mb_done_que_buff[CDEV_ENDPOINT_NET] +
		npriv->p_priv->mb_done_offset[CDEV_ENDPOINT_NET];
#else
	endpoint->mb_done_queue = \
		npriv->p_priv->mb_done_que_buff[CDEV_ENDPOINT_NET];
#endif /* USE_MUL2ALIGN */

	/* Mailbox Base Address (RAM) */
#ifdef USE_MUL2ALIGN
	endpoint->mbox = npriv->p_priv->mb_struct_buff[CDEV_ENDPOINT_NET] +
			 npriv->p_priv->mb_struct_offset[CDEV_ENDPOINT_NET];
#else
	endpoint->mbox = npriv->p_priv->mb_struct_buff[CDEV_ENDPOINT_NET];
#endif /* USE_MUL2ALIGN */


	/* Init memory allocation structures */
	endpoint->cur_mem = 0;
	memset(&(endpoint->mems_ptrs), 0,
	       KSVV_MEM_SEGMENTS * sizeof(m2mlc_mem_ptrs_t));
	if (NULL == ksvv_alloc_mem(npriv, KSVV_MEM_SIZE,
	   &(endpoint->dma1_virt), &(endpoint->dma1_phys))) {
		dev_err(&ndev->dev,
			"ERROR: Can't allocate DMA memory of %d pages, " \
			"region 1\n",
			KSVV_MEM_SIZE);
		status = 1;
		goto exit_oe_err;
	}
	if (NULL == ksvv_alloc_mem(npriv, KSVV_MEM_SIZE,
	   &(endpoint->dma2_virt), &(endpoint->dma2_phys))) {
		dev_err(&ndev->dev,
			"ERROR: Can't allocate DMA memory of %d pages, " \
			"region 2\n",
			KSVV_MEM_SIZE);
		status = 2;
		goto exit_oe_err;
	}
	if (NULL == ksvv_alloc_mem(npriv, KSVV_MEM_SIZE,
	   &(endpoint->dma3_virt), &(endpoint->dma3_phys))) {
		dev_err(&ndev->dev,
			"ERROR: Can't allocate DMA memory of %d pages, " \
			"region 3\n",
			KSVV_MEM_SIZE);
		status = 3;
		goto exit_oe_err;
	}


	/* Init local copies of queue registers */
	if ((status = ksvv_reinit_queue_ptr(npriv)) != 0) {
		goto exit_oe_err;
	}

	/* Zero out reordering window masks */
	for (i = 0; i < KSVV_MBOX_WIN_SIZE; i++)
		endpoint->mbox_window[i] = 0;

	for (i = 0; i < KSVV_DMA_WIN_SIZE; i++)
		endpoint->dma_window[i] = 0;

	endpoint->mbox_window_pending = 0;

	DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev,
		"ksvv_open_endpoint SUCCESS\n");

	return status;

exit_oe_err:
	ksvv_free_all_mem(npriv);
	return status;
} /* ksvv_open_endpoint */

int ksvv_poll(m2mlc_npriv_t *npriv);

int ksvv_close_endpoint(m2mlc_npriv_t *npriv)
{
	int status = 0;
	struct net_device *ndev = npriv->p_priv->ndev;
	unsigned long timestart;


	timestart = jiffies;
	while (ksvv_poll(npriv) != 0) {
		dev_err(&ndev->dev,
			"ERROR: ksvv_close_endpoint; nonzero poll\n");
		if (time_after(jiffies, timestart + HZ))
			break;
	}

	/* TODO: check queues, delete pending dones? */
	if ((status = ksvv_reinit_queue_ptr(npriv)) != 0) {
		/* FIXME: do some cleaning? */
		dev_err(&ndev->dev,
			"ERROR: KSVV_REINIT_QUEUE_PTR failed with %d code\n",
			status);
		if ((status = ksvv_reinit_queue_ptr(npriv)) != 0) {
			dev_err(&ndev->dev,
				"ERROR: KSVV_REINIT_QUEUE_PTR failed " \
				"for second time with %d code\n",
				status);
		}
	}

	/* free DMA memory (TODO: in case of crash delegate free to ksvvd?) */
	ksvv_free_all_mem(npriv);

	return 0;
} /* ksvv_close_endpoint */


/**
 ******************************************************************************
 * RECEIVE
 ******************************************************************************
 **/

void m2mlc_hw_rx(struct net_device *ndev, char *data, ssize_t size);

static ksvv_mb_done_t ksvv_consume_mb_done(m2mlc_npriv_t *npriv,
					   ksvv_mb_done_regs_t mbdone)
{
	const uint32_t mb_mask = MSGS_10BIT_MSK;
	ksvv_mb_done_t done;
	ksvv_endpoint_t *endpoint = &npriv->ksvvendpoint;
	volatile uint32_t *endpoint_regs = endpoint->endpoint_regs;
	struct net_device *ndev = npriv->p_priv->ndev;


	done.r = endpoint->mb_done_queue[endpoint->mbdone_0.p.w_tail & mb_mask];
	if (done.p.live != 1) {
		done.r = endpoint->mb_done_queue[endpoint->mbdone_0.p.w_tail \
						 & mb_mask];
	}

	/* TODO: add many read !!! */
	if (done.p.live != 1) {
		done.r = endpoint->mb_done_queue[endpoint->mbdone_0.p.w_tail \
						 & mb_mask];
	}
	if (done.p.live != 1) {
		mbdone.r = endpoint_regs[M2MLC_RB_MB_DONE_PTRS >> 2];
		done.r = endpoint->mb_done_queue[mbdone.p.w_tail & mb_mask];
	}
	if (done.p.live != 1) {
		dev_err(&ndev->dev,
			"ERROR: ksvv_poll: GOT MB_DONE without live flag\n");
		return done;
	}

	/* Should reset live flag */
	endpoint->mb_done_queue[mbdone.p.w_tail & mb_mask] = 0;

	endpoint->mbdone_0.p.w_tail++;
	mbdone.r = endpoint->mbdone_0.r;

	DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev,
		"SET MB_DONE (head=%d, tail=%d) %08x\n",
		mbdone.p.r_head, mbdone.p.w_tail, mbdone.r);

	/* TODO Amortization */
	endpoint_regs[M2MLC_RB_MB_DONE_PTRS >> 2] = mbdone.r;
	return done;
} /* ksvv_consume_mb_done */

static int ksvv_consume_mb(m2mlc_npriv_t *npriv, ksvv_mb_done_t done)
{
	const uint32_t mb_mask = MSGS_10BIT_MSK;
	ksvv_mb_regs_t mb;
	int consumed = 0;
	ksvv_packet_t *pkt;
	char *pkt_data;
	uint16_t gotcrc;
	int size;
	ksvv_endpoint_t *endpoint = &npriv->ksvvendpoint;
	volatile uint32_t *endpoint_regs = endpoint->endpoint_regs;
	struct net_device *ndev = npriv->p_priv->ndev;
#ifdef DEBUG
	int j;
#endif /* DEBUG */


	if (done.p.live != 1) {
		dev_err(&ndev->dev,
			"ERROR: ksvv_consume_mb - done without live");
		return 0;
	}
	mb.r = endpoint->mb_0.r; /* endpoint_regs[M2MLC_RB_MB_STR_PTRS>>2]; */
	endpoint->mbox_window[done.p.mb_ptr & mb_mask] = done.r;
	endpoint->mbox_window_pending++;


	/*
	 * loop over not consumed packets in window;
	 * try to consume this type = if success - mark as consumed
	 * connected - in order? datagram out of order?
	 * loop from tail
	 */
	while (endpoint->mbox_window[mb.p.w_tail & mb_mask] != 0) {
		DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev, "ksvv_consume_mb");

		done.r = endpoint->mbox_window[mb.p.w_tail & mb_mask];
		endpoint->mbox_window[mb.p.w_tail & mb_mask] = 0;

		pkt = (ksvv_packet_t *)\
			&((uint8_t *)(endpoint->mbox))[4096 * done.p.mb_ptr];
		pkt_data = ((char *)pkt) + sizeof(ksvv_packet_t);

		/* TODO: crc32 */
		gotcrc = pkt->crc16;
		pkt->crc16 = (uint16_t)crc32(0, (unsigned char *)pkt_data,
						 KSVV_GET_SIZE(*pkt));
		if (pkt->crc16 != gotcrc) {
			dev_err(&ndev->dev,
				"ERROR: MSG CRC mismatch, " \
				"got %04x in msg, " \
				"computed %04x for size %d\n",
				gotcrc, pkt->crc16,
				KSVV_GET_SIZE(*pkt));
		}
		size = KSVV_GET_SIZE(*pkt) + sizeof(ksvv_packet_t);
		size = (size + 63) / 64;
		if (((size == 64) && (done.p.packet_num != 0)) ||
		    ((size != 64) && (size != done.p.packet_num))) {
			dev_err(&ndev->dev,
				"ERROR: PKT size / done size mismatch, "\
				"got 0x%04x bytes in msg, " \
				"computed %d pkts; got %d x 64 byte " \
				"pkts in done\n",
				KSVV_GET_SIZE(*pkt), size,
				done.p.packet_num);
		}
		/*
		 * add accounting (recv_bytes/recv_packets)
		 * post msg to stream with size GET_SIZE
		 * Don't work on dead message
		 */
		if (done.p.dead == 0) {
			DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev,
				"ksvv_consume_mb - pack received");
			/* pack received !!! */
#ifdef DEBUG
			printk(KERN_DEBUG "------------------------------\n");
			for (j = 0;
			     j < (KSVV_GET_SIZE(*pkt) + sizeof(ksvv_packet_t));
			     j++) {
				printk("%02X ", *(((unsigned char *)pkt) + j));
			}
			printk(KERN_DEBUG "\n------------------------------\n");
#endif /* DEBUG */
			m2mlc_hw_rx(ndev, pkt_data, KSVV_GET_SIZE(*pkt));
		} else {
			dev_err(&ndev->dev,
				"ERROR: DEAD!=0 incoming packet " \
				"in mb_ptr %d sz %d of typesize %04x " \
				"pkt= %016llx %016llx " \
				"%016llx\n done is %016llx: " \
				"live=%d dead=%d\n",
				done.p.mb_ptr, done.p.packet_num,
				pkt->type_size,
				((uint64_t *)pkt)[0],
				((uint64_t *)pkt)[1],
				((uint64_t *)pkt)[2], done.r,
				done.p.live, done.p.dead);
		}

		mb.p.w_tail++;
		consumed++;
		endpoint->mbox_window_pending--;

		/* TODO: correct exit */
		/*
			unsigned long timestart;
			timestart = jiffies;
			if (time_after(jiffies, timestart + HZ)) return -1;
		*/
	} /* while */

	/* Save new value of mb tail */
	endpoint->mb_0.r = mb.r;
	/* TODO: Amortization */
	endpoint_regs[M2MLC_RB_MB_STR_PTRS >> 2] = mb.r;

	return consumed;
} /* ksvv_consume_mb */

/**
 * Poll incoming queues: mb_done, dma_done?, db?, pio_done??
 *
 * return 1 for some work done
 */
int ksvv_poll(m2mlc_npriv_t *npriv)
{
	int consumed;
	ksvv_mb_done_regs_t mbdone;
	ksvv_mb_done_t done;
	ksvv_endpoint_t *endpoint = &npriv->ksvvendpoint;
	volatile uint32_t *endpoint_regs = endpoint->endpoint_regs;


	/* mbdone.r = endpoint->done_regs->mb_write_done_ptr; */
	mbdone.r = endpoint_regs[M2MLC_RB_MB_DONE_PTRS>>2];
	/* ^ HW BUG ^ */
	if (mbdone.p.r_head == endpoint->mbdone_0.p.w_tail)
		return 0;

	done = ksvv_consume_mb_done(npriv, mbdone);
	consumed = ksvv_consume_mb(npriv, done);

	return consumed;
} /* ksvv_poll */


/**
 ******************************************************************************
 * SEND
 ******************************************************************************
 **/

/**
 * Post DMA descriptor to send queue
 *
 * return descriptor id
 */
static int ksvv_post_dma_desc(m2mlc_npriv_t *npriv, ksvv_dma_desc_t *desc)
{
	int saved_head;
	ksvv_dma_regs_t dma;
	ksvv_endpoint_t *endpoint = &npriv->ksvvendpoint;
	volatile uint32_t *endpoint_regs = endpoint->endpoint_regs;


	/* use local copy */
	dma.r = endpoint->dma_0.r;

	saved_head = dma.p.w_head & endpoint->dma_queue_mask;
	/* new descriptor is added */
	dma.p.w_head = (dma.p.w_head + 1) & endpoint->dma_queue_mask1;
	/* copydesc */
	memcpy((void *)&(endpoint->dma_desc_queue[(saved_head) * 8]),
	       (void *)desc, sizeof(ksvv_dma_desc_t));

	__sync_synchronize();
	/* Post PIO write to the H/W to read out descriptor */
	endpoint_regs[M2MLC_RB_DMA_STR_PTRS >> 2] = dma.r;
	/* update local copy */
	endpoint->dma_0.r = dma.r;

	return saved_head;
} /* ksvv_post_dma_desc */

/**
 * Wait for current DMA Descriptor (out-of-order is not implemented)
 *
 * return 1 if sent; <=0 if error
 */
static int ksvv_wait_dma_done(m2mlc_npriv_t *npriv, int desc_id)
{
	const uint32_t dma_done_mask = MSGS_12BIT_MSK;
	ksvv_dma_done_regs_t dmadone;
	ksvv_dma_done_t done;
	ksvv_endpoint_t *endpoint = &npriv->ksvvendpoint;
	volatile uint32_t *endpoint_regs = endpoint->endpoint_regs;
	struct net_device *ndev = npriv->p_priv->ndev;
	unsigned long timestart;


	done.r = 0;
	/* dmadone.r = endpoint->done_regs->dma_head_done_ptr; */
	dmadone.r = endpoint_regs[M2MLC_RB_DMA_DONE_PTRS >> 2];
	/* ^ HW bug ^ */
	timestart = jiffies;
	while (dmadone.p.r_head == endpoint->dmadone_0.p.w_tail) {
		/* dmadone.r = endpoint->done_regs->dma_head_done_ptr; */
		dmadone.r = endpoint_regs[M2MLC_RB_DMA_DONE_PTRS >> 2];
		/* ^ HW bug ^ */
		if (time_after(jiffies, timestart + HZ))
			return -1;
	}

	done.r = endpoint->dma_done_queue[endpoint->dmadone_0.p.w_tail \
					  & dma_done_mask];
	if (!done.p.live) {
		done.r = endpoint->dma_done_queue[endpoint->dmadone_0.p.w_tail \
						  & dma_done_mask];
	}
	if (!done.p.live) {
		done.r = endpoint->dma_done_queue[endpoint->dmadone_0.p.w_tail \
						  & dma_done_mask];
	}
	if (!done.p.live) {
		dmadone.r = endpoint_regs[M2MLC_RB_DMA_DONE_PTRS >> 2];
		done.r = endpoint->dma_done_queue[endpoint->dmadone_0.p.w_tail \
						  & dma_done_mask];
	}
	if (!done.p.live) {
		dev_err(&ndev->dev,
			"ERROR: ksvv_wait_dma_done: GOT DMA_DONE " \
			"without live flag (3 retries)\n");
		return -(256 + 1);
	}
	endpoint->dma_done_queue[endpoint->dmadone_0.p.w_tail \
				 & dma_done_mask] = 0;

	endpoint->dmadone_0.p.w_tail = (endpoint->dmadone_0.p.w_tail + 1);
	dmadone.r = endpoint->dmadone_0.r;

	/* Amortization */
	endpoint_regs[M2MLC_RB_DMA_DONE_PTRS >> 2] = dmadone.r;

	/* parse dma done */
	if (done.p.cplstatus != 0) {
		dmadone.r = endpoint_regs[M2MLC_RB_DMA_DONE_PTRS >> 2];
		dev_err(&ndev->dev,
			"ERROR: DMA_DONE with nonzero CplStatus " \
			"(head=%d, tail=%d): %08x : live: %d, " \
			"CplStat: 0x%02X, DescID:%d\n",
			dmadone.p.r_head, dmadone.p.w_tail, done.r,
			done.p.live, done.p.cplstatus, done.p.desc_id);
		return -done.p.cplstatus;
	}
	if (done.p.desc_id != desc_id) {
		dev_err(&ndev->dev,
			"ERROR: DMA_DONE for different dma desc_id %d " \
			"(expected %d)\n", done.p.desc_id, desc_id);
		return -(256 + 2);
	}

	return 1;
} /* ksvv_wait_dma_done */

/**
 * Send one packet
 * @pkt_sz: in bytes, unaligned
 *
 * return 1 if sent; <=0 if error;
 */
static int ksvv_send_pkt(m2mlc_npriv_t *npriv, int rem_node_id, int rem_endp_id,
			 size_t pkt_offset_dma1, uint32_t pkt_sz)
{
	int status;
	ksvv_dma_desc_t desc;
	ksvv_target_ptr_msg_t ptr;
	uint64_t req_ptr;
	int desc_id;
	ksvv_endpoint_t *endpoint = &npriv->ksvvendpoint;


	ptr.r = 0;
	ptr.p.Mbox = rem_endp_id;
	desc.Target_ptr = ptr.r;

	req_ptr = (uint64_t)((uintptr_t)endpoint->dma1_phys + pkt_offset_dma1);

	desc.Request_ptr = req_ptr;
	desc.Format.r = 0;
	desc.Format.p.InOrder = 1; /* Wait for end of early descriptors */
	desc.Format.p.RemIntReq = 0;
	desc.Format.p.LocIntReq = 0;
	desc.Format.p.Format_Type = M2MLC_FMT_TYPE_MSGL;
	desc.Transfer_size = (pkt_sz + 3) / 4; /* Convert bytes to words */
	desc.Parameter.r = 0;
	desc.Parameter.p.BEmaskLBE = 0xF;
	desc.Parameter.p.BEmaskFBE = 0xF;
	desc.Parameter.p.DestId = rem_node_id;
	desc.Parameter.p.Route = 0;
	desc.Remote_Doorbell = 0;

	desc_id = ksvv_post_dma_desc(npriv, &desc);
	status = ksvv_wait_dma_done(npriv, desc_id);

	return status;
} /* ksvv_send_pkt */

/**
 * Send data using stream (and dma?)
 *
 * return amount of sent data
 */
uint32_t ksvv_send(m2mlc_npriv_t *npriv, int rem_node_id, int rem_endp_id,
		   void *data, uint32_t send_size)
{
	int i;
	int status = 0;
	int retry = 0;
	char *pkt_data;
	ksvv_packet_t *packet;
	ksvv_endpoint_t *endpoint = &npriv->ksvvendpoint;
	struct net_device *ndev = npriv->p_priv->ndev;
	unsigned long timestart;
#ifdef DEBUG
	int j;
#endif /* DEBUG */


	for (i = 0; i < send_size;) {
		int pkt_size;
		packet = (ksvv_packet_t *)(endpoint->dma1_virt + \
					   endpoint->dma1_pos * 4096);
		endpoint->dma1_pos = (endpoint->dma1_pos + 1) % 1024;
		pkt_data = ((char *)packet) + sizeof(ksvv_packet_t);

		if (KSVV_MSG_PAYLOAD_SIZE < send_size) {
			dev_err(&ndev->dev,
				"ERROR: Can't send packet to destination, " \
				"%u bytes > PAYLOAD_SIZE %lu\n",
				send_size, KSVV_MSG_PAYLOAD_SIZE);
			return 0;
		} else {
			pkt_size = send_size + sizeof(ksvv_packet_t);
		}
		packet->type_size = KSVV_TYPE_SIZE(KSVV_PKT_NET, send_size);
		packet->crc16 = 0;

		DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev,
			"pkt data copy memcpy(%p, %p, %d)\n",
			pkt_data, data, send_size);

		memcpy(pkt_data, data, send_size);
		packet->crc16 = (uint16_t)crc32(0, pkt_data, send_size);

#ifdef DEBUG
		printk(KERN_DEBUG "------------------------------\n");
		for (j = 0; j < pkt_size; j++) {
			printk("%02X ", *(((unsigned char *)packet) + j));
		}
		printk(KERN_DEBUG "\n------------------------------\n");
#endif /* DEBUG */

		DEV_DBG(M2MLC_DBG_MSK_NET, &ndev->dev,
			"send => send_pkt(%p, %d, %d, %08lx, %d)\n",
			endpoint, rem_node_id, rem_endp_id,
			((char *)packet) - ((char *)endpoint->dma1_virt),
			pkt_size);

		status = ksvv_send_pkt(npriv, rem_node_id, rem_endp_id,
			((char *)packet) - ((char *)endpoint->dma1_virt),
			pkt_size);
		if (status == 1) {
			/* success dma_done as ack */
			i += send_size;
			retry = 0;
		} else if ((status == -0x40) || (status == -0x48)) {
			/* Recv Mailbox full retry */
			dev_err(&ndev->dev, "ERROR: RETRY %d\n", retry);
			retry++;

			/* usleep(10000 * retry); */
			timestart = jiffies;
			do {} while (!time_after(jiffies,
						 timestart + (HZ * retry)));

			if (retry > 5) {
				dev_err(&ndev->dev,
					"ERROR: Can't send packet" \
					" to destination, 5 x %d (%02x)" \
					" status from ksvv_send_pkt at" \
					" byte %d of %d bytes\n",
					-status, -status, i, send_size);
				return i;
			}
		} else {
			/* TODO RETRY? */
			dev_err(&ndev->dev,
				"ERROR: Can't send packet to destination, " \
				"%d (%02x) status from ksvv_send_pkt " \
				"at byte %d of %d bytes\n",
				-status, -status, i, send_size);
			return i;
		}
	}

	return i;
} /* ksvv_send */

/* EOF */
