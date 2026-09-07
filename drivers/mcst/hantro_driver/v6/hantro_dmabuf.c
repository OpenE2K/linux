// SPDX-License-Identifier: GPL-2.0
/*
 *    Hantro driver DMA_BUF operation.
 *
 *    Copyright (c) 2017, VeriSilicon Inc.
 *
 *    This program is free software; you can redistribute it and/or
 *    modify it under the terms of the GNU General Public License
 *    as published by the Free Software Foundation; either version 2
 *    of the License, or (at your option) any later version.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License for more details.
 *
 *    You may obtain a copy of the GNU General Public License
 *    Version 2 or later at the following locations:
 *    http://www.opensource.org/licenses/gpl-license.html
 *    http://www.gnu.org/copyleft/gpl.html
 */

#include "hantro_priv.h"

int hantro_gem_prime_mmap(struct drm_gem_object *obj,
			  struct vm_area_struct *vma);

static void hantro_gem_dmabuf_release(struct dma_buf *dma_buf)
{
	struct drm_gem_object *obj = hantro_get_gem_from_dmabuf(dma_buf);
	struct drm_device *dev = obj->dev;

	if (obj) {
		hantro_unref_drmobj(obj);
		drm_dev_put(dev);
	}
}

static struct sg_table *
hantro_gem_map_dma_buf(struct dma_buf_attachment *attach,
		       enum dma_data_direction dir)
{
	struct drm_gem_object *obj = hantro_get_gem_from_dmabuf(attach->dmabuf);
	struct sg_table *sgt;

	if (WARN_ON(dir == DMA_NONE))
		return ERR_PTR(-EINVAL);
	if (WARN_ON(!obj))
		return ERR_PTR(-EINVAL);

#if KERNEL_VERSION(5, 11, 0) > LINUX_VERSION_CODE
	sgt = obj->dev->driver->gem_prime_get_sg_table(obj);
#else
	sgt = obj->funcs->get_sg_table(obj);
#endif

	if (!dma_map_sg_attrs(attach->dev, sgt->sgl, sgt->nents, dir,
			      DMA_ATTR_SKIP_CPU_SYNC)) {
		sg_free_table(sgt);
		kfree(sgt);
		sgt = ERR_PTR(-ENOMEM);
	}

	return sgt;
}

static int hantro_gem_dmabuf_mmap(struct dma_buf *dma_buf,
				  struct vm_area_struct *vma)
{
	struct drm_gem_object *obj = hantro_get_gem_from_dmabuf(dma_buf);
	struct drm_device *dev;

	if (!obj)
		return -EINVAL;
	dev = obj->dev;

	return hantro_gem_prime_mmap(obj, vma);
}

#if KERNEL_VERSION(5, 11, 0) > LINUX_VERSION_CODE
static void *hantro_gem_dmabuf_vmap(struct dma_buf *dma_buf)
{
	struct drm_gem_object *obj = hantro_get_gem_from_dmabuf(dma_buf);
	void *vaddr = NULL;

	/*****drm_gem_vmap part*****/
	if (obj)
		vaddr = obj->dev->driver->gem_prime_vmap(obj);
	/****************************/

	return vaddr;
}

static void hantro_gem_dmabuf_vunmap(struct dma_buf *dma_buf, void *vaddr)
{
	struct drm_gem_object *obj = hantro_get_gem_from_dmabuf(dma_buf);

	if (!vaddr)
		return;
	if (obj) {
		if (obj->funcs && obj->funcs->vunmap)
			obj->funcs->vunmap(obj, vaddr);
		else if (obj->dev->driver->gem_prime_vunmap)
			obj->dev->driver->gem_prime_vunmap(obj, vaddr);
	}
}

#else
static int hantro_gem_dmabuf_vmap(struct dma_buf *dma_buf,
#if KERNEL_VERSION(5, 18, 0) > LINUX_VERSION_CODE
				  struct dma_buf_map *map)
#else
				  struct iosys_map *map)
#endif
{
	struct drm_gem_object *obj = hantro_get_gem_from_dmabuf(dma_buf);
	int ret = 0;

	/*****drm_gem_vmap part*****/
	if (obj)
		ret = obj->funcs->vmap(obj, map);
	/****************************/

	return ret;
}

static void hantro_gem_dmabuf_vunmap(struct dma_buf *dma_buf,
#if KERNEL_VERSION(5, 18, 0) > LINUX_VERSION_CODE
				  struct dma_buf_map *map)
#else
				  struct iosys_map *map)
#endif
{
	struct drm_gem_object *obj = hantro_get_gem_from_dmabuf(dma_buf);

	if (obj) {
		if (obj->funcs && obj->funcs->vunmap)
			obj->funcs->vunmap(obj, map);
	}
}

#endif

const struct dma_buf_ops hantro_dmabuf_ops = {
	.cache_sgt_mapping = true,
	.map_dma_buf = hantro_gem_map_dma_buf,
	.unmap_dma_buf = drm_gem_unmap_dma_buf,
	.release = hantro_gem_dmabuf_release,
	.mmap = hantro_gem_dmabuf_mmap,
	.vmap = hantro_gem_dmabuf_vmap,
	.vunmap = hantro_gem_dmabuf_vunmap,
};
