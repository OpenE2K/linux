/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/* AUC2 updates status before descriptors completion,
 * so we have to add empty task every time to ensure that
 * the previous task is finished */
#define MGA2_HW_RING_SIZE (MGA2_RING_SIZE * 2)
#define mga25_hw_to_ptr(__p) (__p / 2)
#define mga25_ptr_to_hw(__p) (__p * 2)

/* AUC2 registers */
#define MGA2_AUC2_QUEUEPTRL  (0x04000 + 0x00)
#define MGA2_AUC2_QUEUEPTRH  (0x04000 + 0x04)
#define MGA2_AUC2_STATUSPTRL (0x04000 + 0x08)
#define MGA2_AUC2_STATUSPTRH (0x04000 + 0x0c)
#define MGA2_AUC2_CTRLSTAT   (0x04000 + 0x10)
# define MGA2_AUC2_B_BUSY  (1 << 30)
# define MGA2_AUC2_B_ABORT (1 << 31)
#define MGA2_AUC2_HEADTAIL   (0x04000 + 0x14)
#define MGA2_AUC2_DUMMY      (0x04000 + 0x18)


#define MGA2_AUC2_B_TAIL_SHIFT 16
#define MGA2_AUC2_B_HEAD_MASK 0xffff

#define	DESC0_NOT_LAST			(1ULL << 63)
#define	DESC0_TYPE			(0ULL << 62)
#define	DESC0_WAIT_VBLANK2		(1ULL << 54)
#define	DESC0_WAIT_VBLANK1		(1ULL << 53)
#define	DESC0_WAIT_VBLANK0		(1ULL << 52)
#define	DESC0_WAIT_BLITER_STOP1		(1ULL << 51)
#define	DESC0_WAIT_BLITER_READY1	(1ULL << 50)
#define	DESC0_WAIT_BLITER_STOP0		(1ULL << 49)
#define	DESC0_WAIT_BLITER_READY0	(1ULL << 48)
#define	DESC0_REG_OFFSET		32

struct auc2_st {
	u64 status;
} __packed;

struct desc0 {
	u64	next;
	u64	val;
} __packed;

#define	DESC1_NOT_LAST			(1UL << 63)
#define	DESC1_TYPE			(1UL << 62)
#define	DESC1_BLITTER_OFFSET		54
#define	DESC1_WAIT_ENABLE		(1UL << 52)
#define	DESC1_WAIT_OFFSET		48
#define	DESC1_REG_MASK_OFFSET		32

struct desc1 {
	u64	next;
	union  {
		struct {
			u32 mask;
			u32 regs[15];
		};
		u32 val32[16];
		u64 val64[8];
	};
} __packed;

static u64 auc2_get_current_desc(struct mga2 *mga2)
{
	return le64_to_cpu(READ_ONCE(mga2->status->status)) >> 32;
}

static int blitter_reg_nr(u32 reg)
{
	return (reg / 4) % 16;
}

static void auc2_wdesc(struct mga2 *mga2, u32 data, u32 reg)
{
	struct desc1 *c = &mga2->desc1[mga2->head];

	reg = blitter_reg_nr(reg);

	c->mask |= 1 << reg;
	c->regs[reg] = data;
}

static void auc2_update_ptr(struct mga2 *mga2)
{
	u16 tail = le64_to_cpu(mga2->status->status);
	tail %= MGA2_HW_RING_SIZE;
	mga2->tail = mga25_hw_to_ptr(tail);
}

static void mga25_desc1_serialize(struct desc1 *c)
{
	int i, k = 0, l = 0;
	u64 v[2];
	long mask = (c->mask << 1) | 1;
	c->mask |= (((1UL << DESC1_BLITTER_OFFSET) | DESC1_TYPE) >> 32);

	for_each_set_bit(i, &mask, ARRAY_SIZE(c->val32)) {
		v[l++] = c->val32[i];
		if (l == 2)
			c->val64[k++] = cpu_to_le64((v[0] << 32) | v[1]);
		l %= 2;
	}
	if (l)
		c->val64[k] = cpu_to_le64(v[0] << 32);
}

static int auc2_append_desc(struct mga2 *mga2,
			struct mga25_gem_object *mo)
{
	int ret = 0;
	int h = mga2->head;
	struct desc1 *c = mo ? (struct desc1 *)mo->vaddr : &mga2->desc1[h];
	dma_addr_t dma_addr = mo ? mo->dma_addr :
			mga2->desc1_dma + h * sizeof(*c);

	if (!mo)
		mga25_desc1_serialize(c);

	/* link waiting descriptor */
	c->next = cpu_to_le64(mga2->desc0_waiting_dma);

	mga2->ring[mga25_ptr_to_hw(h)] = cpu_to_le64(dma_addr);
	mga2->head = circ_inc(h);
	mga2->fence_seqno++;
	wfb(mga25_ptr_to_hw(mga2->head), MGA2_AUC2_HEADTAIL);

	return ret;
}

static struct mga25_gem_object *mga25_auc_ioctl(struct drm_device *drm,
					void *data, struct drm_file *file)
{
	int ret = 0;
	void __user *p;
	int head;
	u32 *desc, nr, handle, reltype;
	struct mga25_gem_object *mo;
	struct dma_resv *resv;
	struct dma_fence *fence;
	struct drm_mga2_bctrl *udesc = data;
	struct mga2 *mga2 = drm->dev_private;
	struct drm_mga2_buffers __user *b = (void *)((long)udesc->buffers_ptr);
	struct drm_gem_object *gobj = NULL;

	head = get_free_desc(mga2);
	if (head < 0) {
		ret = -ENOSPC;
		goto out;
	}
	if (!(gobj = drm_gem_object_lookup(file, udesc->desc_handle))) {
		ret = -ENOENT;
		goto out;
	}
	/* drop reference from lookup -
	 fence is used for reference control */
	drm_gem_object_put(gobj);

	mo = to_mga25_obj(gobj);
	if (mo->write_domain != MGA2_GEM_DOMAIN_CPU) {
		ret = -EINVAL;
		goto out;
	}

	desc = mo->vaddr;
	fence = mga2->mga25_fence[head];

	for (p = b; !ret;) {
		struct drm_gem_object *o;
		unsigned long a = -1;
		int i;
		if (get_user(nr, &b->nr) ||
			get_user(reltype, &b->reltype) ||
			get_user(handle, &b->handle)) {
			ret = -EFAULT;
			goto out;
		}
		if (nr == 0)
			break;

		if (!(o = drm_gem_object_lookup(file, handle))) {
			ret = -ENOENT;
			goto out;
		}
		/* drop reference from lookup -
		 fence is used for reference control */
		drm_gem_object_put(o);
		a = to_mga25_obj(o)->dma_addr;
		for (i = 0; i < nr; i++) {
			u32 offset, v;
			if (get_user(offset, &b->offset[i])) {
				ret = -EFAULT;
				goto out;
			}
			offset /= sizeof(*desc);
			v = le32_to_cpu(desc[offset]);
			if (v >= o->size) {
				ret = -EINVAL;
				goto out;
			}
			v += reltype ? a >> 32 : a;
			desc[offset] = cpu_to_le32(v);
		}
		resv = &to_mga25_obj(o)->resv;
		dma_resv_lock(resv, NULL);
		if ((ret = dma_resv_reserve_shared(resv, 1)) == 0)
			dma_resv_add_shared_fence(resv, fence);
		dma_resv_unlock(resv);

		if (0)
			DRM_DEBUG("add fence %lld to %lx\n", fence->seqno, a);

		p += sizeof(*b) + nr * sizeof(u32);
		b = (struct drm_mga2_buffers __user *)p;
	}
	if (ret)
		goto out;

	resv = &mo->resv;
	dma_resv_lock(resv, NULL);
	if ((ret = dma_resv_reserve_shared(resv, 1)) == 0)
		dma_resv_add_shared_fence(resv, fence);
	dma_resv_unlock(resv);
out:
	return ret ? ERR_PTR(ret) : mo;
}

int mga25_auc2_ioctl(struct drm_device *drm, void *data, struct drm_file *file)
{
	struct mga2 *mga2 = drm->dev_private;
	struct mga25_gem_object *mo;
	int ret = 0;
	if (mga20(mga2->dev_id))
		return -ENODEV;
	if (mga2->flags & MGA2_BCTRL_OFF)
		return -ENODEV;

	mutex_lock(&mga2->bctrl_mu);

	mo = mga25_auc_ioctl(drm, data, file);
	if (IS_ERR(mo)) {
		ret = PTR_ERR(mo);
		goto out;
	}
	append_desc(mga2, mo);
out:
	mutex_unlock(&mga2->bctrl_mu);
	return ret;
}

static int mga2fb_auc2_hw_init(struct mga2 *mga2)
{
	wfb(mga2->ring_dma, MGA2_AUC2_QUEUEPTRL);
	wfb((u64)mga2->ring_dma >> 32, MGA2_AUC2_QUEUEPTRH);
	wfb(mga2->status_dma, MGA2_AUC2_STATUSPTRL);
	wfb((u64)mga2->status_dma >> 32, MGA2_AUC2_STATUSPTRH);

	BUILD_BUG_ON(MGA2_HW_RING_SIZE > (1 << 16));
	wfb(MGA2_HW_RING_SIZE, MGA2_AUC2_CTRLSTAT);
	return 0;
}

static int mga2fb_auc2_init(struct mga2 *mga2)
{
	u64 v;
	int sz, i;
	void *b;
	dma_addr_t addr;
	gfp_t f = GFP_KERNEL | __GFP_ZERO;
	struct device *dev = mga2->drm->dev;
	/*TODO:*/
	u64 int_regs_base = mga25(mga2->dev_id) ? 0x1c00 : 0x02000;

	sz = MGA2_HW_RING_SIZE * sizeof(*mga2->ring);
	if (!(b = dmam_alloc_coherent(dev, sz, &addr, f)))
		goto err;
	mga2->ring = b;
	mga2->ring_dma = addr;

	sz = MGA2_RING_SIZE * sizeof(*mga2->desc1);
	if (!(b = dmam_alloc_coherent(dev, sz, &addr, f)))
		goto err;
	mga2->desc1 = b;
	mga2->desc1_dma = addr;

	sz = sizeof(*mga2->desc0_waiting);
	if (!(b = dmam_alloc_coherent(dev, sz, &addr, f)))
		goto err;
	mga2->desc0_waiting = b;
	mga2->desc0_waiting_dma = addr;

	v = DESC0_WAIT_BLITER_STOP0 |
		((((u64)MGA2_AUC2_DUMMY) / 4) << DESC0_REG_OFFSET);
	mga2->desc0_waiting->val = cpu_to_le64(v);

	sz = sizeof(*mga2->desc0_interrupt);
	if (!(b = dmam_alloc_coherent(dev, sz, &addr, f)))
		goto err;
	mga2->desc0_interrupt = b;
	mga2->desc0_interrupt_dma = addr;

	v = DESC0_WAIT_BLITER_STOP1 |
		(((int_regs_base + MGA2_INTREQ) / 4)
			<< DESC0_REG_OFFSET) |
		MGA2_INT_B_SETRST | (1 << mga2->hwirq);
	mga2->desc0_interrupt->val = cpu_to_le64(v);

	for (i = 0, addr = mga2->desc0_interrupt_dma; i < MGA2_RING_SIZE; i++)
		mga2->ring[mga25_ptr_to_hw(i) + 1] = cpu_to_le64(addr);

	sz = sizeof(*mga2->status);
	if (!(b = dmam_alloc_coherent(dev, sz, &addr, f)))
		goto err;
	mga2->status = b;
	mga2->status_dma = addr;

	return 0;
err:
	return -ENOMEM;
}
