/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#define	 MGA2_BB_SZ		0x400
/*
 *******************************************************************************
 * MMIO BitBlt Module Registers
 *******************************************************************************
 */
#define REG_BB_CTRL	0x1000	/* BitBlt module control register (write only) */
#define REG_BB_STAT	0x1000	/* BitBlt module status register (read only) */

#define REG_BB_WINDOW	0x1004	/* Operation geometry */
#define REG_BB_SADDR	0x1008	/* Source start address */
#define REG_BB_DADDR	0x100c	/* Destination start address */
#define REG_BB_PITCH	0x1010	/* */
#define REG_BB_BG	0x1014	/* Background color */
#define REG_BB_FG	0x1018	/* Foreground color */

/* BitBlt status register bits */
#define BB_STAT_PROCESS	(0x1<<31)	/* 1 - processing operation, 0 - idle */
#define BB_STAT_FULL	(0x1<<30)	/* 1 - pipeline full */
#define BB_STAT_DMA	(0x1<<26)	/* DMA support */

#define BB_CTRL_CMD_MASK	0xC0000000
#define BB_CTRL_CMD_START		(0x1<<31)
#define BB_CTRL_CMD_ABORT		(0x1<<30)


#define BB_CTRL_BITS_IN_BYTE_TWISTER	(0x1<<22)

#define BB_CTRL_DDMA_EN			(0x1<<21)
#define BB_CTRL_SDMA_EN			(0x1<<20)
#define BB_CTRL_SOFFS_MASK	(0x7<<16)

/* Binary raster operations */
#define BB_CTRL_ROP_MASK		0x0000F000

#define BB_CTRL_ROP_0			(0x0<<12)	/* clear */
#define BB_CTRL_ROP_AND			(0x1<<12)	/* and */
#define BB_CTRL_ROP_NOT_SRC_AND_DST	(0x2<<12)	/* andReverse */
#define BB_CTRL_ROP_DST			(0x3<<12)	/* copy */
#define BB_CTRL_ROP_SRC_AND_NOT_DST	(0x4<<12)	/* andInverted */
#define BB_CTRL_ROP_SRC			(0x5<<12)	/* noop */
#define BB_CTRL_ROP_XOR			(0x6<<12)	/* xor */
#define BB_CTRL_ROP_OR			(0x7<<12)	/* or */
#define BB_CTRL_ROP_NOR			(0x8<<12)	/* nor */
#define BB_CTRL_ROP_NXOR		(0x9<<12)	/* equiv */
#define BB_CTRL_ROP_NOT_SRC		(0xa<<12)	/* invert */
#define BB_CTRL_ROP_NOT_SRC_OR_DST	(0xb<<12)	/* orReverse */
#define BB_CTRL_ROP_NOT_DST		(0xc<<12)	/* copyInverted */
#define BB_CTRL_ROP_SRC_OR_NOT_DST	(0xd<<12)	/* orInverted */
#define BB_CTRL_ROP_NAND		(0xe<<12)	/* nand */
#define BB_CTRL_ROP_1			(0xf<<12)	/* set */

#define BB_CTRL_HDIR	(0x1<<5)
#define BB_CTRL_VDIR	(0x1<<6)

#define BB_CTRL_CE_EN		(0x1<<0)
#define BB_CTRL_PAT_EN		(0x1<<1)
#define BB_CTRL_SFILL_EN	(0x1<<2)
#define BB_CTRL_TR_EN		(0x1<<4)

#define BB_CTRL_SRC_MODE	(0x1<<7)

#define BB_CTRL_TERM_00		(0x0<<8)
#define BB_CTRL_TERM_01		(0x1<<8)
#define BB_CTRL_TERM_10		(0x2<<8)

#define BB_CTRL_BPP_8	        (0x0<<10)
#define BB_CTRL_BPP_16	        (0x1<<10)
#define BB_CTRL_BPP_24	        (0x2<<10)
#define BB_CTRL_BPP_32	        (0x3<<10)
#ifdef __BIG_ENDIAN
#define BB_CTRL_BPP_CD_8	(BB_CTRL_BPP_8)
#define BB_CTRL_BPP_CD_16	(BB_CTRL_BPP_16 | 0x0800000)
#define BB_CTRL_BPP_CD_24	(BB_CTRL_BPP_24 | 0x1800000)
#define BB_CTRL_BPP_CD_32	(BB_CTRL_BPP_32 | 0x1800000)
#elif defined(__LITTLE_ENDIAN)
#define BB_CTRL_BPP_CD_8	BB_CTRL_BPP_8
#define BB_CTRL_BPP_CD_16	BB_CTRL_BPP_16
#define BB_CTRL_BPP_CD_24	BB_CTRL_BPP_24
#define BB_CTRL_BPP_CD_32	BB_CTRL_BPP_32
#else
#error byte order not defined
#endif


#define MGA2_BB_R0	0x01000
#define MGA2_BB_R7	0x0101C	/* base registers of MGA-compatible blitter */
#define MGA2_BB_FMTCFG	0x01020	/* pixel format control for alpha-op */
#define MGA2_BB_ASRC	0x01024	/* Fs calculation */
#define MGA2_BB_ADST	0x01028	/* Fd calculation */
#define MGA2_BB_PALADDR	0x0102C	/* set LUT address (palette) for 1bpp/4bpp/8bpp formats */
#define MGA2_BB_PALDATA	0x01030	/* write data to LUT element (palette) for 1bpp/4bpp/8bpp formats */
#define REG_BB_SADDR64	0x01034	/* high part of 64-bit DMA address */
				/* in system memory for source channel */
#define REG_BB_DADDR64	0x01038	/* low part of 64-bit DMA address */
				/* in system memory for destination channel */


static u32 mga2_get_busy(struct mga2 *mga2)
{
	u32 busy = rfb(REG_BB_CTRL) & BB_STAT_PROCESS;
	if (busy)
		return busy;
	if (mga20(mga2->dev_id)) {
		busy = (rfb(MGA2_BCTRL_STATUS) & MGA2_BCTRL_B_BUSY) ||
		    (rfb(MGA2_SYSMUX_BITS) & MGA2_SYSMUX_BLT_WR_BUSY) ||
		    (rfb(MGA2_VIDMUX_BITS) & MGA2_VIDMUX_BLT_WR_BUSY);
	} else if (mga25(mga2->dev_id)) {
		busy = (rfb(MGA2_AUC2_CTRLSTAT) & MGA2_AUC2_B_BUSY) ||
			(rfb(REG_BB_CTRL + MGA2_BB_SZ) & BB_STAT_PROCESS) ||
			rfb(MGA25_SYSMUX_BITS) ||
			rfb(MGA25_VMMUX_BITS) ||
			(rfb(MGA2_BCTRL_STATUS) & MGA2_BCTRL_B_BUSY);
	}
	return busy;
}

static int ___mga2_sync(struct mga2 *mga2)
{
	int ret = 0, i;
	int timeout_usec = mga2_timeout(mga2) * 1000;
	if (mga2_nofbaccel)
		return 0;
	for (i = 0; i < timeout_usec; i++) {
		u32 busy = mga2_get_busy(mga2);

		if (!busy)
			break;
		udelay(1);
	}

	if (i == timeout_usec) {
		mga2->flags |= MGA2_BCTRL_OFF;
		mga2_nofbaccel = 1;
		DRM_ERROR("sync timeout\n");
		ret = -ETIME;
	}
	return ret;
}

static u64 mga2_get_current_desc(struct mga2 *mga2)
{
	if (mga25(mga2->dev_id))
		return auc2_get_current_desc(mga2);
	else
		return bctrl_get_current_desc(mga2);
}

int __mga2_sync(struct mga2 *mga2)
{
	long ret = 0, timeout = msecs_to_jiffies(mga2_timeout(mga2));
	int n = circ_dec(mga2->head);
	struct dma_fence *fence = mga2->mga2_fence[n];
	u64 current_desc = mga2_get_current_desc(mga2);
	if (mga2->flags & MGA2_BCTRL_OFF)
		goto cant_sleep;

	mga2_update_ptr(mga2);

	if (circ_idle(mga2))
		return 0;

	if (in_atomic() || in_dbg_master() || irqs_disabled())
		goto cant_sleep;

	while (0 == (ret = dma_fence_wait_timeout(fence, true, timeout))) {
		/* Timeout */
		u64 d = mga2_get_current_desc(mga2);
		if (d == current_desc) /* AUC's stuck */
			break;
		/* AUC is still working, let's wait. */
		current_desc = d;
	}
	if (ret == 0) {
		ret = -ETIMEDOUT;
		mga2->flags |= MGA2_BCTRL_OFF;
		mga2_nofbaccel = 1;
		dma_fence_signal(fence);
		DRM_ERROR("fence %d wait timed out.\n", n);
	} else if (ret < 0) {
		DRM_DEBUG("fence %d wait failed (%ld).\n", n, ret);
	} else {
		ret = 0;
	}
	return ret;
cant_sleep:
	return ___mga2_sync(mga2);
}

struct mga2_fence {
	struct dma_fence base;
	struct mga2 *mga2;
};

static inline struct mga2_fence *to_mga2_fence(struct dma_fence *f)
{
	return container_of(f, struct mga2_fence, base);
}

static inline struct mga2 *fence_to_mga2(struct dma_fence *f)
{
	return to_mga2_fence(f)->mga2;
}

/*
 * Common fence implementation
 */

static const char *mga2_fence_get_driver_name(struct dma_fence *fence)
{
	return "mga2";
}

static const char *mga2_fence_get_timeline_name(struct dma_fence *f)
{
	return "mga2-auc";
}

/**
 * mga2_irq_sw_irq_get - enable software interrupt
 *
 * @mga2: mga2 device pointer
 *
 * Enables the software interrupt for the ring.
 * The software interrupt is used to signal a fence on
 * the ring.
 */
static void mga2_irq_sw_irq_get(struct mga2 *mga2)
{
	if (atomic_inc_return(&mga2->ring_int) == 1)
		enable_irq(mga2->irq);
}

/**
 * mga2_irq_sw_irq_put - disable software interrupt
 *
 * @mga2: mga2 device pointer
 *
 * Disables the software interrupt for the ring.
 * The software interrupt is used to signal a fence on
 * the ring.
 */
static void mga2_irq_sw_irq_put(struct mga2 *mga2)
{
	if (atomic_dec_and_test(&mga2->ring_int))
		disable_irq_nosync(mga2->irq);
}


#define MGA2_FENCE_IRQ_EN	DMA_FENCE_FLAG_USER_BITS

/**
 * mga2_fence_enable_signaling - enable signalling on fence
 * @fence: fence
 *
 * This function is called with fence_queue lock held, and adds a callback
 * to fence_queue that checks if this fence is signaled, and if so it
 * signals the fence and removes itself.
 */
static bool mga2_fence_enable_signaling(struct dma_fence *f)
{
	struct mga2 *mga2 = fence_to_mga2(f);
	set_bit(MGA2_FENCE_IRQ_EN, &f->flags);
	mga2_irq_sw_irq_get(mga2);

	return true;
}

/**
 * mga2_fence_release - callback that fence can be freed
 *
 * @fence: fence
 *
 * This function is called when the reference count becomes zero.
 */
static void mga2_fence_release(struct dma_fence *f)
{
	kfree(to_mga2_fence(f));
}

static const struct dma_fence_ops mga2_fence_ops = {
//FIXME:	.use_64bit_seqno = true,
	.get_driver_name = mga2_fence_get_driver_name,
	.get_timeline_name = mga2_fence_get_timeline_name,
	.enable_signaling = mga2_fence_enable_signaling,
	.release = mga2_fence_release,
};


static void __mga2_update_ptr(struct mga2 *mga2)
{
	if (mga25(mga2->dev_id) && !mga2->bctrl_active)
		auc2_update_ptr(mga2);
	else
		bctrl_update_ptr(mga2);
}

void mga2_update_ptr(struct mga2 *mga2)
{
	int h, t;
	unsigned long flags;
	spin_lock_irqsave(&mga2->fence_lock, flags);
	h = mga2->tail;
	__mga2_update_ptr(mga2);
	t = circ_inc(mga2->tail);

	for (; __circ_space(h, t); h = circ_inc(h)) {
		struct dma_fence *f = mga2->mga2_fence[h];
		if (test_and_clear_bit(MGA2_FENCE_IRQ_EN, &f->flags))
			mga2_irq_sw_irq_put(mga2);
		dma_fence_signal_locked(f);
	}
	spin_unlock_irqrestore(&mga2->fence_lock, flags);
}

static int wait_for_ring(struct mga2 *mga2)
{
	struct dma_fence *fence;
	long ret = 0;
	int n, timeout = msecs_to_jiffies(mga2_timeout(mga2));

	mga2_update_ptr(mga2);
	if (circ_space(mga2))
		return 0;

	if (in_atomic() || in_dbg_master() || irqs_disabled()) {
		ret = ___mga2_sync(mga2);
		if (ret)
			return ret;
		mga2_update_ptr(mga2);
		if (!circ_space(mga2))
			return -ENOSPC;
	}
	n = mga2->tail;
	fence = mga2->mga2_fence[n];
	ret = dma_fence_wait_timeout(fence, true, timeout);
	if (ret == 0) {
		ret = -ETIMEDOUT;
		mga2->flags |= MGA2_BCTRL_OFF;
		dma_fence_signal(fence);
		DRM_ERROR("fence %d wait timed out.\n", n);
	} else if (ret < 0) {
		DRM_DEBUG("fence %d wait failed (%ld).\n", n, ret);
	} else {
		ret = 0;
	}

	return ret;
}

static int __get_free_desc(struct mga2 *mga2)
{
	int ret, h;
	unsigned seqno;
	struct mga2_fence *fence;
	struct dma_fence *f, *old;
	if (!circ_space(mga2)) {
		if ((ret = wait_for_ring(mga2)))
			return ret;
	}
	h = mga2->head;
	/* Can not freely reuse mga2_fence memory:
	 * the lifetime of the fence depends on a dma_resv it was added to,
	 * so we have to use alloc/dma_fence_put/free mechanism */
	fence = kzalloc(sizeof(*fence), GFP_KERNEL);
	if (!fence)
		return -ENOMEM;
	fence->mga2 = mga2;
	f = &fence->base;
	seqno = mga2->fence_seqno;
	BUG_ON(h != seqno % MGA2_RING_SIZE);
	dma_fence_init(f, &mga2_fence_ops, &mga2->fence_lock, 0, seqno);

	old = mga2->mga2_fence[h];
	mga2->mga2_fence[h] = f;
	dma_fence_put(old);

	if (mga25(mga2->dev_id)) {
		struct desc1 *c = &mga2->desc1[h];
		memset(c, 0, sizeof(*c));
	}
	return h;
}

static int get_free_desc(struct mga2 *mga2)
{
	if (mga2->flags & MGA2_BCTRL_OFF) {
		__mga2_sync(mga2);
		return 0;
	}
	return __get_free_desc(mga2);
}

static int append_desc(struct mga2 *mga2, struct mga2_gem_object *mo)
{
	if (mga2->flags & MGA2_BCTRL_OFF)
		return 0;
	if (mga25(mga2->dev_id) && mga2->bctrl_active) {
		mga2_update_ptr(mga2);
		mga2->bctrl_active = false;
	}

	if (mga25(mga2->dev_id))
		return auc2_append_desc(mga2, mo);

	bctrl_append_desc(mga2, mo);

	return 0;
}


