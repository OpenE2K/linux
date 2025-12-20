/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

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
	u64	val2;
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

static void mga25_wdesc(struct mga2 *mga2, u32 data, u32 reg)
{
	struct desc1 *c = &mga2->desc1[mga2->head];

	reg = blitter_reg_nr(reg);

	c->mask |= 1 << reg;
	c->regs[reg] = data;
}

static void auc2_update_ptr(struct mga2 *mga2)
{
	u16 tail = le64_to_cpu(mga2->status->status);
	mga2->tail = tail % MGA2_RING_SIZE;
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

static int mga25_append_desc(struct mga2 *mga2, struct mga2_gem_object *mo)
{
	int ret = 0;
	int h = mga2->head;
	struct desc1 *c = mo ? (struct desc1 *)mo->vaddr : &mga2->desc1[h];
	dma_addr_t dma_addr = mo ? mo->dma_addr :
			mga2->desc1_dma + h * sizeof(*c);
	struct desc0 *d = &mga2->desc0[h];
	u64 v;

	if (!mo)
		mga25_desc1_serialize(c);

	c->next = cpu_to_le64(mga2->desc0_dma + h * sizeof(*d));

	memset(d, 0, sizeof(*d));
	v = DESC0_WAIT_BLITER_STOP0 | DESC0_NOT_LAST |
		((((u64)MGA2_AUC2_DUMMY) / 4) << DESC0_REG_OFFSET);
	d->val = cpu_to_le64(v);
	v = DESC0_WAIT_BLITER_STOP1 |
		((((u64)mga2->info->int_regs_base + MGA2_INTREQ) / 4)
			<< DESC0_REG_OFFSET) |
		MGA2_INT_B_SETRST | MGA25_INT_B_SOFTINT;
	d->val2 = cpu_to_le64(v);

	mga2->ring[h] = cpu_to_le64(dma_addr);
	mga2->head = circ_inc(h);
	mga2->fence_seqno++;
	wfb(mga2->head, MGA2_AUC2_HEADTAIL);

	return ret;
}

static struct mga2_gem_object *mga2_auc_ioctl(struct drm_device *drm,
					void *data, struct drm_file *file)
{
	int ret = 0;
	void __user *p;
	int head;
	u32 *desc, nr, handle, reltype;
	struct mga2_gem_object *mo;
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

	mo = to_mga2_obj(gobj);
	if (mo->write_domain != MGA2_GEM_DOMAIN_CPU) {
		ret = -EINVAL;
		goto out;
	}

	desc = mo->vaddr;
	fence = mga2->mga2_fence[head];

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
		a = to_mga2_obj(o)->dma_addr;
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
		resv = &to_mga2_obj(o)->resv;
		dma_resv_lock(resv, NULL);
		if ((ret = dma_resv_reserve_shared(resv, 1)) == 0)
			dma_resv_add_shared_fence(resv, fence);
		dma_resv_unlock(resv);

		if (0)
			DRM_DEBUG("add fence %lld to %lx\n", fence->seqno, a);

		p += sizeof(*b) + nr * sizeof(u32);
		b = (struct drm_mga2_buffers __user *)p;
	}

	resv = &mo->resv;
	dma_resv_lock(resv, NULL);
	if ((ret = dma_resv_reserve_shared(resv, 1)) == 0)
		dma_resv_add_shared_fence(resv, fence);
	dma_resv_unlock(resv);
out:
	return ret ? ERR_PTR(ret) : mo;
}

int mga2_auc2_ioctl(struct drm_device *drm, void *data, struct drm_file *file)
{
	struct mga2 *mga2 = drm->dev_private;
	struct mga2_gem_object *mo;
	int ret = 0;
	if (mga2_p2(mga2))
		return -ENODEV;
	if (mga2->flags & MGA2_BCTRL_OFF)
		return -ENODEV;

	mutex_lock(&mga2->bctrl_mu);

	mo = mga2_auc_ioctl(drm, data, file);
	if (IS_ERR(mo)) {
		ret = PTR_ERR(mo);
		goto out;
	}
	append_desc(mga2, mo);
out:
	mutex_unlock(&mga2->bctrl_mu);
	return ret;
}

static int mga2fb_auc2_fini(struct mga2 *mga2)
{
	int sz;
	struct device *dev = mga2->drm->dev;

	sz = MGA2_RING_SIZE * sizeof(*mga2->ring);
	dma_free_coherent(dev, sz, mga2->ring, mga2->ring_dma);

	sz = MGA2_RING_SIZE * sizeof(*mga2->desc1);
	dma_free_coherent(dev, sz, mga2->desc1, mga2->desc1_dma);

	sz = MGA2_RING_SIZE * sizeof(*mga2->desc0);
	dma_free_coherent(dev, sz, mga2->desc0, mga2->desc0_dma);

	sz = sizeof(*mga2->status);
	dma_free_coherent(dev, sz, mga2->status, mga2->status_dma);
	return 0;
}

static int mga2fb_auc2_hw_init(struct mga2 *mga2)
{
	wfb(mga2->ring_dma, MGA2_AUC2_QUEUEPTRL);
	wfb((u64)mga2->ring_dma >> 32, MGA2_AUC2_QUEUEPTRH);
	wfb(mga2->status_dma, MGA2_AUC2_STATUSPTRL);
	wfb((u64)mga2->status_dma >> 32, MGA2_AUC2_STATUSPTRH);
	wfb(MGA2_RING_SIZE, MGA2_AUC2_CTRLSTAT);
	return 0;
}

static int mga2fb_auc2_init(struct mga2 *mga2)
{
	dma_addr_t addr;
	int sz = MGA2_RING_SIZE * sizeof(*mga2->ring);
	void *b;
	if (!(b = dma_alloc_coherent(mga2->drm->dev, sz, &addr, GFP_KERNEL)))
		goto err;

	mga2->ring = b;
	mga2->ring_dma = addr;

	sz = MGA2_RING_SIZE * sizeof(*mga2->desc1);
	if (!(b = dma_alloc_coherent(mga2->drm->dev, sz, &addr, GFP_KERNEL)))
		goto err;
	mga2->desc1 = b;
	mga2->desc1_dma = addr;

	sz = MGA2_RING_SIZE * sizeof(*mga2->desc0);
	if (!(b = dma_alloc_coherent(mga2->drm->dev, sz, &addr, GFP_KERNEL)))
		goto err;
	mga2->desc0 = b;
	mga2->desc0_dma = addr;

	sz = sizeof(*mga2->status);
	if (!(b = dma_alloc_coherent(mga2->drm->dev, sz, &addr, GFP_KERNEL)))
		goto err;
	mga2->status = b;
	mga2->status_dma = addr;

	return 0;
err:
	mga2fb_auc2_fini(mga2);
	return -ENOMEM;
}
