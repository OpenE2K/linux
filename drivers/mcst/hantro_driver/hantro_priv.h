/* SPDX-License-Identifier: GPL-2.0 */
/*
 *    Hantro driver private header file.
 *
 *    Copyright (c) 2017, VeriSilicon Inc.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License, version 2, as
 *    published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License version 2 for more details.
 *
 *    You may obtain a copy of the GNU General Public License
 *    Version 2 at the following locations:
 *    https://opensource.org/licenses/gpl-2.0.php
 */

#ifndef HANTRO_PRIV_H
#define HANTRO_PRIV_H
#include "hantro.h"
#include "hantro_device.h"

/* compile options */

#define HANTRO_GEM_FLAG_IMPORT BIT(0)
#define HANTRO_GEM_FLAG_EXPORT BIT(1)
#define HANTRO_GEM_FLAG_EXPORTUSED BIT(2)
#define HANTRO_GEM_FLAG_USEVMALLOC BIT(3)

#if KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE
#define hantro_access_ok(a, b, c) access_ok(b, c)
#if KERNEL_VERSION(5, 19, 0) > LINUX_VERSION_CODE
#define hantro_reserve_obj_shared(a, b) dma_resv_reserve_shared(a, b)
#else
#define hantro_reserve_obj_shared(a, b) dma_resv_reserve_fences(a, b)
#endif
#define hantro_ref_drmobj drm_gem_object_get
#define hantro_unref_drmobj drm_gem_object_put
#else /*KERNEL_VERSION(5, 0, 0) <= LINUX_VERSION_CODE*/
#define hantro_access_ok(a, b, c) access_ok(a, b, c)
#define hantro_reserve_obj_shared(a, b) reservation_object_reserve_shared(a)
#define hantro_ref_drmobj drm_gem_object_reference
#define hantro_unref_drmobj drm_gem_object_unreference_unlocked
#endif

#define NODENAME_DECODER "decoder"
#define NODENAME_ENCODER "encoder"
#define NODENAME_CACHE "cache"
#define NODENAME_DEC400 "dec400"
#define NODENAME_AXIFE "axife"
#define NODENAME_MMU "hantrommu"
#define NODENAME_VCMD "hantrovcmd"
#define NODENAME_IM "hantroIM"
#define NODENAME_DECJPG "decjpg"
#define NODENAME_ENCJPG "encjpg"

#define SET_DEC_CFG_BIT(a) (a)
#define SET_ENC_CFG_BIT(a) ((a << 8))
#define GET_DEC_CFG_BITS(a) (a & 0xff)
#define GET_ENC_CFG_BITS(a) ((a >> 8) & 0xff)

#ifdef VSI_CONFIG_PM
struct hantrodev_data {
	void *data;
	struct hantrodev_data *next;
};
#endif

typedef struct dtbnode {
	struct device_node *ofnode;
	int type;
	phys_addr_t ioaddr;
	phys_addr_t iosize;
	int irq[4];
	int parenttype;
	phys_addr_t parentaddr;
	int sliceidx;
	struct dtbnode *next;
} dtbnode;

struct hantro_device_handle {
	struct platform_device *platformdev; /* parent device */
	struct drm_device *drm_dev;
	u32 config; /* Encoder subs IP info store in bit [9:16] */
#ifdef VSI_CONFIG_PM
	void *hantro_data;
#endif
#ifdef PCIE_EN
	void *dev;
#endif
};

struct hantro_mem_handle {
	unsigned int sliceidx;
	unsigned int size;
	dma_addr_t paddr;
	dma_addr_t mem_base;
	void *vaddr;
};

struct hantro_base_addr {
	unsigned long reg_base;
	unsigned long ddr_base;
};

extern struct hantro_device_handle hantro_dev;
extern const struct dma_buf_ops hantro_dmabuf_ops;
extern struct drm_driver hantro_drm_driver;

extern int dbg_mmap;
#define hantro_mmaplog(fmt, ...) {\
	if (dbg_mmap)	\
		pr_info(fmt, ##__VA_ARGS__);	\
}

#if KERNEL_VERSION(4, 13, 0) > LINUX_VERSION_CODE

#define HANTRO_FENCE_FLAG_ENABLE_SIGNAL_BIT FENCE_FLAG_ENABLE_SIGNAL_BIT
#define HANTRO_FENCE_FLAG_SIGNAL_BIT FENCE_FLAG_SIGNALED_BIT

typedef struct fence hantro_fence_t;
typedef struct fence_ops hantro_fence_op_t;

static inline signed long
hantro_fence_default_wait(hantro_fence_t *fence, bool intr, signed long timeout)
{
	return fence_default_wait(fence, intr, timeout);
}

static inline void hantro_fence_init(hantro_fence_t *fence,
				     const hantro_fence_op_t *ops,
				     spinlock_t *lock, unsigned int context,
				     unsigned int seqno)
{
	return fence_init(fence, ops, lock, context, seqno);
}

static inline unsigned int hantro_fence_context_alloc(unsigned int num)
{
	return fence_context_alloc(num);
}

static inline signed long
hantro_fence_wait_timeout(hantro_fence_t *fence, bool intr, signed long timeout)
{
	return fence_wait_timeout(fence, intr, timeout);
}

static inline struct drm_gem_object *
hantro_gem_object_lookup(struct drm_device *dev, struct drm_file *filp,
			 u32 handle)
{
#if KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE
	return drm_gem_object_lookup(filp, handle);
#else
	return drm_gem_object_lookup(dev, filp, handle);
#endif
}

static inline void hantro_fence_put(hantro_fence_t *fence)
{
	return fence_put(fence);
}

static inline int hantro_fence_signal(hantro_fence_t *fence)
{
	return fence_signal(fence);
}

static inline void ref_page(struct page *pp)
{
#if KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE
	atomic_inc(&pp->_refcount);
#else
	atomic_inc(&pp->_count);
#endif
}

static inline void unref_page(struct page *pp)
{
#if KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE
	atomic_dec(&pp->_refcount);
#else
	atomic_dec(&pp->_count);
#endif
}

static inline bool hantro_fence_is_signaled(hantro_fence_t *fence)
{
	return fence_is_signaled(fence);
}

#else /*version higher */
#define HANTRO_FENCE_FLAG_ENABLE_SIGNAL_BIT DMA_FENCE_FLAG_ENABLE_SIGNAL_BIT
#define HANTRO_FENCE_FLAG_SIGNAL_BIT DMA_FENCE_FLAG_SIGNALED_BIT

typedef struct dma_fence hantro_fence_t;
typedef struct dma_fence_ops hantro_fence_op_t;

static inline signed long
hantro_fence_default_wait(hantro_fence_t *fence, bool intr, signed long timeout)
{
	return dma_fence_default_wait(fence, intr, timeout);
}

static inline void hantro_fence_init(hantro_fence_t *fence,
				     const hantro_fence_op_t *ops,
				     spinlock_t *lock, unsigned int context,
				     unsigned int seqno)
{
	return dma_fence_init(fence, ops, lock, context, seqno);
}

static inline unsigned int hantro_fence_context_alloc(unsigned int num)
{
	return dma_fence_context_alloc(num);
}

static inline signed long
hantro_fence_wait_timeout(hantro_fence_t *fence, bool intr, signed long timeout)
{
	return dma_fence_wait_timeout(fence, intr, timeout);
}

static inline struct drm_gem_object *
hantro_gem_object_lookup(struct drm_device *dev, struct drm_file *filp,
			 u32 handle)
{
	return drm_gem_object_lookup(filp, handle);
}

static inline void hantro_fence_put(hantro_fence_t *fence)
{
	return dma_fence_put(fence);
}

static inline int hantro_fence_signal(hantro_fence_t *fence)
{
	return dma_fence_signal(fence);
}

static inline void ref_page(struct page *pp)
{
	atomic_inc(&pp->_refcount);
	atomic_inc(&pp->_mapcount);
}

static inline void unref_page(struct page *pp)
{
	atomic_dec(&pp->_refcount);
	atomic_dec(&pp->_mapcount);
}

static inline bool hantro_fence_is_signaled(hantro_fence_t *fence)
{
	return dma_fence_is_signaled(fence);
}

#endif

static inline struct drm_gem_hantro_object *
to_drm_gem_hantro_obj(struct drm_gem_object *gem_obj)
{
	return container_of(gem_obj, struct drm_gem_hantro_object, base);
}

struct drm_gem_object *
hantro_get_gem_from_dmabuf(struct dma_buf *dma_buf);

int hantro_setdomain(struct drm_device *dev, void *data,
		     struct drm_file *file_priv);
int hantro_acquirebuf(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);
int hantro_testbufvalid(struct drm_device *dev, void *data,
			struct drm_file *file_priv);
int hantro_releasebuf(struct drm_device *dev, void *data,
		      struct drm_file *file_priv);
int init_hantro_resv(struct dma_resv *presv,
		     struct drm_gem_hantro_object *cma_obj);
void initFenceData(void);
void releaseFenceData(void);

int hantro_memalloc(struct hantro_mem_handle *phandle);
int hantro_memfree(struct hantro_mem_handle *phandle);

int hantro_createsysfsAPI(int sliceidx, struct device *dev);
int hantro_unlinksysfsAPI(void);
int hantro_get_vcmdsup(struct drm_device *dev, void *data,
		       struct drm_file *file_priv);
int hantro_get_irqinfo(struct drm_device *dev, void *data,
		       struct drm_file *file_priv);
int hantro_get_pmsup(struct drm_device *dev, void *data,
		       struct drm_file *file_priv);

int hantro_map_internal_address(struct file *filp, struct vm_area_struct *vma);

void hantro_pm_runtime_get(struct device *kdev);
void hantro_pm_runtime_put(struct device *kdev);
/* debug */
/* #define ENABLE_DEBUG */
#ifdef ENABLE_DEBUG
#define DBG(...) pr_info(__VA_ARGS__)
#else
#define DBG(...)
#endif

#endif /*HANTRO_PRIV_H*/
