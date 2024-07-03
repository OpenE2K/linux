/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#define	 MGA2_BCTRL_LBASEPTR		0x01800
#define	 MGA2_BCTRL_HBASEPTR		0x01804
#define	 MGA2_BCTRL_START		0x01808
# define MGA2_BCTRL_B_START		(1 << 0)
#define	 MGA2_BCTRL_CURLPTR		0x0180C
#define	 MGA2_BCTRL_STATUS		0x01810
# define MGA2_BCTRL_B_BUSY		(1 << 0)

#define	 MGA2_BCTRL_DUMMY		0x01814

#define	 MGA2_BCTRL_TAIL		(0x800 + MGA2_DC0_VGAWINOFFS) /* use it as tail pointer */

#define	 MGA2_VIDMUX_BITS	0x03404
# define	 MGA2_VIDMUX_BLT_WR_BUSY	(1 << 5)
# define	 MGA2_SYSMUX_BLT_WR_BUSY	(1 << 1)

#define		MGA2_SYSMUX_BITS		0x03804
#define		MGA2_SYSMUX_BLT_WR_BUSY		(1 << 1)


#define	MGA25_SYSMUX_BITS	0x03004
#define	MGA25_FBMUX_BITS	0x03404
#define	MGA25_VMMUX_BITS	0x03804

#define CIRC_SIZE MGA2_RING_SIZE
#define CIRC_MASK (CIRC_SIZE - 1)
#define circ_idle(circ)     ((circ)->head == (circ)->tail)
#define __circ_space(head, tail)      CIRC_SPACE(head, tail, CIRC_SIZE)
#define circ_space(circ)      __circ_space((circ)->head, (circ)->tail)
#define circ_cnt(circ)       CIRC_CNT((circ)->head, (circ)->tail, CIRC_SIZE)
#define circ_clear(circ)	((circ)->tail = (circ)->head)
#define circ_add(__v, __i)	(((__v) + (__i)) & CIRC_MASK)
#define circ_inc(__v)	circ_add(__v, 1)
#define circ_dec(__v)	circ_add(__v, -1)


struct bctrl_base {
	u64 current_desc;
	u32 status;
	u32 reserved;
} __packed;

#define BCTRL_CMD_NR	16

struct bctrl_desc {
	u32 next_lo;
	u32 next_hi;
	struct bctrl_cmd {
		u16 ctrl;
		u16 reg;
		u32 data;
	} cmd[BCTRL_CMD_NR] __packed;
} __packed;

/* ctrl bitmasks */
#define MGA2_BCTRL_LST_CMD		(1 << 15)
#define MGA2_BCTRL_WAIT_ROP3		(1 << 3)
#define MGA2_BCTRL_WAIT_ROP2		(1 << 1)


struct bctrl {
	struct bctrl_base base;
	struct bctrl_desc desc[MGA2_RING_SIZE];
	struct bctrl_desc fence[MGA2_RING_SIZE];
} __packed;

static u64 bctrl_get_current_desc(struct mga2 *mga2)
{
	struct bctrl_base *base = &mga2->bctrl->base;
	return le64_to_cpu(READ_ONCE(base->current_desc));
}

static dma_addr_t idx_to_addr(struct mga2 *mga2, int i)
{
	dma_addr_t base = mga2->bctrl_dma + offsetof(struct bctrl, desc);
	return base + i * sizeof(struct bctrl_desc);
}

static dma_addr_t idx_to_fence_addr(struct mga2 *mga2, int i)
{
	dma_addr_t base = mga2->bctrl_dma + offsetof(struct bctrl, fence);
	return base + i * sizeof(struct bctrl_desc);
}

static inline void write_desc(void *p, dma_addr_t addr)
{
	volatile dma_addr_t *d = p;
	if (sizeof(dma_addr_t) == 32)
		*d = cpu_to_le32(addr);
	else
		*d = cpu_to_le64(addr);
}

static inline dma_addr_t read_desc(void *p)
{
	dma_addr_t ret;
	volatile dma_addr_t *d = p;
	if (sizeof(dma_addr_t) == 32)
		ret = cpu_to_le32(*d);
	else
		ret = le64_to_cpu(*d);
	return ret;
}

static void bctrl_update_ptr(struct mga2 *mga2)
{
	mga2->tail = rfb(MGA2_BCTRL_TAIL) >> 16;
}

static void __mga2_wdesc(struct bctrl_cmd *c, u32 data, u32 reg,
			   bool first, bool last)
{
	u16 v = 0;
	if (last)
		v |= MGA2_BCTRL_LST_CMD;
	if (first)
		v |= MGA2_BCTRL_WAIT_ROP2;
	c->ctrl = cpu_to_le16(v);
	c->data = cpu_to_le32(data);
	c->reg  = cpu_to_le16(reg / 4);
}

static void mga2_wdesc(struct mga2 *mga2, int n, u32 data, u32 reg,
			   bool first, bool last)
{
	struct bctrl_cmd *c = &mga2->bctrl->desc[mga2->head].cmd[n];
	__mga2_wdesc(c, data, reg, first, last);
}

static void __fence_wdesc(struct mga2 *mga2, int n, u32 data, u32 reg,
			   bool first, bool last)
{
	struct bctrl_cmd *c = &mga2->bctrl->fence[mga2->head].cmd[n];
	__mga2_wdesc(c, data, reg, first, last);
}

#define fence_wdesc(__cmd, __data, __reg, __first, __last) \
	__fence_wdesc(mga2, __cmd, __data, __reg, __first, __last);

static int mga2_append_desc(struct mga2 *mga2, struct mga2_gem_object *mo)
{
	long ret = 0, timeout = msecs_to_jiffies(mga2_timeout(mga2));
	int h = mga2->head, l = circ_dec(h);
	struct bctrl_base *base = &mga2->bctrl->base;
	struct bctrl_desc *desc = mo ? mo->vaddr : &mga2->bctrl->desc[h];
	dma_addr_t addr = mo ? mo->dma_addr : idx_to_addr(mga2, h);
	struct bctrl_desc *fence = &mga2->bctrl->fence[h];
	dma_addr_t fence_addr = idx_to_fence_addr(mga2, h);
	dma_addr_t last_addr = idx_to_fence_addr(mga2, l), current_desc;
	struct bctrl_desc *last_fence = &mga2->bctrl->fence[l];
	struct dma_fence *dfence = mga2->mga2_fence[l];
	u32 status;
	u32 v = mga25(mga2) ? MGA25_INT_B_SOFTINT : MGA2_INT_B_SOFTINT;

	fence_wdesc(0, circ_inc(h) << 16, MGA2_BCTRL_TAIL, 1, 0);
	fence_wdesc(1, MGA2_INT_B_SETRST | v,
			mga2->info->int_regs_base + MGA2_INTREQ, 0, 1);

	write_desc(fence, 0);
	write_desc(desc, fence_addr);
	wmb(); /* descriptor is written */
	write_desc(last_fence, addr);  /* link the descriptor */

	mga2->head = circ_inc(h);
	mga2->fence_seqno++;

	/* mga2 writes desc first, then the status */
	status = le32_to_cpu(READ_ONCE(base->status));
	current_desc = le64_to_cpu(READ_ONCE(base->current_desc));

	if (!(status & MGA2_BCTRL_B_BUSY))
		goto uptdate_ptr;
	else if (current_desc && current_desc != last_addr)
		goto out;
	/* Now we don't know if mga2 has read the desc.
	   Let's wait for previous one and see */
	ret = dma_fence_wait_timeout(dfence, true, timeout);
	if (ret == 0) {
		ret = -ETIMEDOUT;
		mga2->flags |= MGA2_BCTRL_OFF;
		dma_fence_signal(dfence);
		DRM_ERROR("fence %d wait timed out.\n", l);
	} else if (ret < 0) {
		DRM_DEBUG("fence %d wait failed (%ld).\n", l, ret);
	} else {
		ret = 0;
	}
uptdate_ptr:
	mga2_update_ptr(mga2);
	if (circ_idle(mga2))
		goto out;
	write_desc(base, addr);
	wfb(MGA2_BCTRL_B_START, MGA2_BCTRL_START);
out:
	return ret;
}

#ifdef CONFIG_DEBUG_FS
int mga2_debugfs_bctrl(struct seq_file *s, void *data)
{
	struct drm_info_node *node = (struct drm_info_node *)s->private;
	struct drm_device *drm = node->minor->dev;
	struct mga2 *mga2 = drm->dev_private;
	seq_printf(s, "head: %x, tail: %x (%x)\n",
		mga2->tail, mga2->head, rfb(MGA2_BCTRL_TAIL));

	seq_hex_dump(s, "", DUMP_PREFIX_OFFSET, 32, 4,
		     mga2->bctrl, sizeof(*mga2->bctrl), false);

	return 0;
}
#endif

int __mga2fb_bctrl_hw_init(struct mga2 *mga2)
{
	u64 addr = mga2->bctrl_dma;
	wfb(mga2->tail << 16, MGA2_BCTRL_TAIL);
	wfb(addr, MGA2_BCTRL_LBASEPTR);
	wfb(addr >> 32, MGA2_BCTRL_HBASEPTR);
	return 0;
}

static int __mga2fb_bctrl_init(struct mga2 *mga2)
{
	mga2->bctrl = dma_alloc_coherent(mga2->drm->dev, sizeof(*mga2->bctrl),
			&mga2->bctrl_dma, GFP_KERNEL);
	if (!mga2->bctrl)
		return -ENOMEM;
	return 0;
}

static int __mga2fb_bctrl_fini(struct mga2 *mga2)
{
	BUILD_BUG_ON(BCTRL_CMD_NR >= (1 << 16));
	dma_free_coherent(mga2->drm->dev, sizeof(*mga2->bctrl),
				mga2->bctrl, mga2->bctrl_dma);
	return 0;
}

int mga2_bctrl_ioctl(struct drm_device *drm, void *data, struct drm_file *file)
{
	struct mga2 *mga2 = drm->dev_private;
	struct mga2_gem_object *mo;
	int ret = 0;
	if (mga2->flags & MGA2_BCTRL_OFF)
		return -ENODEV;

	mutex_lock(&mga2->bctrl_mu);
	if ((ret = __mga2_sync(mga2)))
		goto out;

	if (mga25(mga2) && !mga2->bctrl_active) {
		mga2_update_ptr(mga2);
		wfb(mga2->tail << 16, MGA2_BCTRL_TAIL);
		mga2->bctrl_active = true;
	}

	mo = mga2_auc_ioctl(drm, data, file);
	if (IS_ERR(mo)) {
		ret = PTR_ERR(mo);
		goto out;
	}

	mga2_append_desc(mga2, mo);
out:
	mutex_unlock(&mga2->bctrl_mu);
	return ret;
}
