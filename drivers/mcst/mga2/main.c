/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include "drv.h"


struct drm_gem_object *mga2_gem_create_with_handle(struct drm_file *file,
						   struct drm_device *drm,
						   size_t size, u32 domain,
						   u32 *handle)
{
	int ret;
	struct drm_gem_object *gobj = mga2_gem_create(drm, size, domain);
	if (IS_ERR(gobj))
		return gobj;
	/*
	 * allocate a id of idr table where the gobj is registered
	 * and handle has the id what user can see.
	 */
	ret = drm_gem_handle_create(file, gobj, handle);

	if (ret)
		return ERR_PTR(ret);

	/* drop reference from allocate - handle holds it now. */
	drm_gem_object_put(gobj);

	return gobj;
}


static struct sg_table *mga2_gem_get_sg_table(struct drm_gem_object *obj)
{
	struct mga2_gem_object *mga2_gem = to_mga2_gem(obj);
	struct sg_table *sgt;
	int ret;

	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt)
		return NULL;

	ret = dma_get_sgtable(obj->dev->dev, sgt, mga2_gem->vaddr,
			      mga2_gem->dma_addr, obj->size);
	if (ret < 0)
		goto out;
	return sgt;
out:
	kfree(sgt);
	return NULL;
}

static int mga2_gem_vmap(struct drm_gem_object *gobj, struct iosys_map *map)
{
	struct mga2_gem_object *obj = to_mga2_gem(gobj);
	BUG_ON(!obj->vaddr);
	iosys_map_set_vaddr(map, obj->vaddr);
	return 0;
}

/**
 * mga2_prime_vunmap - unmap a MGA2 GEM object from the kernel's virtual
 *     address space
 * @obj: GEM object
 * @vaddr: kernel virtual address where the MGA2 GEM object was mapped
 *
 * This function removes a buffer exported via DRM PRIME from the kernel's
 * virtual address space. This is a no-op because MGA2 buffers cannot be
 * unmapped from kernel space.
 */
static void mga2_gem_vunmap(struct drm_gem_object *gobj, struct iosys_map *map)
{
	/* Nothing to do */
}

static int mga2_gem_mmap(struct drm_gem_object *gobj,
				   struct vm_area_struct *vma)
{
	int ret = 0;
	struct mga2_gem_object *mo = to_mga2_gem(gobj);
	struct mga2 *mga2 = (struct mga2 *)gobj->dev->dev_private;

	/*
	 * Clear the VM_PFNMAP flag that was set by drm_gem_mmap(), and set the
	 * vm_pgoff (used as a fake buffer offset by DRM) to 0 as we want to map
	 * the whole buffer.
	 */
	vma->vm_flags &= ~VM_PFNMAP;
	vma->vm_pgoff = 0;

	switch (mo->write_domain) {
	case MGA2_GEM_DOMAIN_VRAM: {
		struct drm_mm_node *node = &mo->node;
		unsigned long pfn = node->start >> PAGE_SHIFT;
		if (mga2_use_uncached(mga2->dev_id)) {
			BUG();
			pfn = (long)mo->vaddr >> PAGE_SHIFT;
			WARN(!IS_ENABLED(CONFIG_E90S), "FIXME:pfn\n");
		}

		ret = io_remap_pfn_range(vma, vma->vm_start,
					pfn,
					vma->vm_end - vma->vm_start,
					ttm_prot_from_caching(ttm_write_combined,
					vma->vm_page_prot));
		break;
	}
	case MGA2_GEM_DOMAIN_CPU: {
		/* Override writecombine flags, set by drm_gem_mmap_obj() */
		vma->vm_page_prot = vm_get_page_prot(vma->vm_flags);
		ret = dma_mmap_coherent(gobj->dev->dev, vma,
				  mo->vaddr, mo->dma_addr, gobj->size);
		break;
	}
	default:
		BUG();
	}

	if (ret)
		drm_gem_vm_close(vma);

	return ret;
}

static void mga2_gem_free(struct drm_gem_object *gobj)
{
	unsigned long now;
	struct drm_device *drm = gobj->dev;
	struct mga2_gem_object *mo = to_mga2_gem(gobj);
	struct drm_mm_node *node = &mo->node;
	struct mga2 *mga2 = (struct mga2 *)gobj->dev->dev_private;
	long ret = 0, to = msecs_to_jiffies(mga2_timeout(mga2));
	ret = dma_resv_wait_timeout(&mo->resv,
					DMA_RESV_USAGE_KERNEL,
					false,
					to);
	if (ret == 0) {
		DRM_ERROR("mga2: reservation %d wait timed out.\n", mga2->tail);
	} else if (ret < 0) {
		DRM_ERROR("mga2: reservation wait failed (%ld).\n", ret);
	}
	now = jiffies;
	if (time_before(now, mo->hw_unref_time))
		schedule_timeout_uninterruptible(mo->hw_unref_time - now);

	switch (mo->write_domain) {
	case MGA2_GEM_DOMAIN_VRAM:
		if (mga2_use_uncached(mga2->dev_id)) {
			BUG();
		} else {
			mutex_lock(&mga2->vram_mu);
			drm_mm_remove_node(node);
			mutex_unlock(&mga2->vram_mu);
		}
		break;
	case MGA2_GEM_DOMAIN_CPU:
		if (mo->sgt) { /* created by mga25_virt_to_handle() */
			dma_unmap_sg(drm->dev, mo->sgt->sgl,
				mo->sgt->nents, mo->dma_dir);
			sg_free_table(mo->sgt);
			vunmap(mo->vaddr);
			if (mo->pages && mo->pages[0])
				release_pages(mo->pages, gobj->size / PAGE_SIZE);
		} else if (mo->vaddr) {
			dma_free_coherent(drm->dev, gobj->size,
					mo->vaddr, mo->dma_addr);
		}
		break;
	default:
		WARN_ON(1);
	}
	dma_resv_fini(&mo->resv);
	drm_gem_object_release(gobj);
	kfree(mo);
}

static const struct vm_operations_struct mga2_gem_vm_ops = {
	.open  = drm_gem_vm_open,
	.close = drm_gem_vm_close,
};

static const struct drm_gem_object_funcs mga2_gem_object_funcs = {
	.free   = mga2_gem_free,
	.export = drm_gem_prime_export,
	.get_sg_table = mga2_gem_get_sg_table,
	.vmap   = mga2_gem_vmap,
	.vunmap = mga2_gem_vunmap,
	.mmap   = mga2_gem_mmap,
	.vm_ops = &mga2_gem_vm_ops,
};

static struct mga2_gem_object *
__mga2_gem_create(struct drm_device *drm, size_t size)
{
	int ret;
	struct mga2_gem_object *obj =
			 kzalloc(sizeof(*obj), GFP_KERNEL);
	struct drm_gem_object *gobj = &obj->base;
	if (!obj)
		return ERR_PTR(-ENOMEM);

	gobj->funcs = &mga2_gem_object_funcs;

	ret = drm_gem_object_init(drm, gobj, size);
	if (ret)
		goto error;

	ret = drm_gem_create_mmap_offset(gobj);
	if (ret) {
		drm_gem_object_release(gobj);
		goto error;
	}

	dma_resv_init(&obj->resv);

	return obj;

error:
	kfree(obj);
	return ERR_PTR(ret);
}

struct drm_gem_object *mga2_gem_create(struct drm_device *drm,
				       size_t size, u32 domain)
{
	int ret;
	struct mga2_gem_object *obj;
	struct drm_gem_object *gobj;
	struct drm_mm_node *node;
	struct mga2 *mga2 = drm->dev_private;
	gfp_t flag = GFP_USER | __GFP_ZERO;

	if (domain == MGA2_GEM_DOMAIN_VRAM && !mga2_has_vram(mga2->dev_id)
					&& !mga2_use_uncached(mga2->dev_id)) {
		domain = MGA2_GEM_DOMAIN_CPU;
		size = PAGE_ALIGN(size);
		if (IS_ENABLED(CONFIG_E2K) && size / PAGE_SIZE > 8) {
			/* align to save tlb entries in iommu */
			size = ALIGN(size, HPAGE_SIZE);
			/* try hard */
			flag |= __GFP_RETRY_MAYFAIL;
		}
	} else {
		size = PAGE_ALIGN(size);
	}
	obj = __mga2_gem_create(drm, size);
	if (IS_ERR(obj))
		return ERR_CAST(obj);

	gobj = &obj->base;
	node = &obj->node;

	switch (domain) {
	case MGA2_GEM_DOMAIN_VRAM:
	if (mga2_use_uncached(mga2->dev_id)) {
		BUG();
	} else {
		mutex_lock(&mga2->vram_mu);
		ret = drm_mm_insert_node(&mga2->vram_mm, node, size);
		mutex_unlock(&mga2->vram_mu);
		if (ret)
			goto fail;

		obj->dma_addr = node->start - mga2->vram_paddr;
		obj->vaddr = (void __force *)ioremap_wc(node->start, size);
		if (!obj->vaddr) {
			ret = -EFAULT;
			goto fail;
		}
		memset_io((void __iomem __force *)obj->vaddr, 0, size);
	}
	break;
	case MGA2_GEM_DOMAIN_CPU: {
		obj->vaddr = dma_alloc_coherent(drm->dev, size,
				&obj->dma_addr, flag);
		if (!obj->vaddr && (flag & __GFP_RETRY_MAYFAIL)) {
			/* Couldn't allocate even after trying hard.
			 * Now we'll try indefinitely...
			 * IMPORTANT: this can hang current process
			 * if memory fragmentation is too high, the
			 * proper way is to use CMA. */
			flag &= ~__GFP_RETRY_MAYFAIL;
			flag |= __GFP_NOFAIL;
			obj->vaddr = dma_alloc_coherent(drm->dev, size,
					&obj->dma_addr, flag);
		}
		if (!obj->vaddr) {
			ret = -ENOMEM;
			goto fail;
		}
		break;
	}
	default:
		WARN_ON(1);
		ret = -EINVAL;
		goto fail;
	}
	obj->write_domain = domain;
	obj->dma_dir = DMA_BIDIRECTIONAL;

	return gobj;
fail:
	drm_gem_object_release(gobj);
	kfree(obj);
	return ERR_PTR(ret);
}

int mga2_dumb_create(struct drm_file *file,
		     struct drm_device *drm, struct drm_mode_create_dumb *args)
{
	struct drm_gem_object *gobj;
	int min_pitch = DIV_ROUND_UP(args->width * args->bpp, 8);
	if (args->pitch < min_pitch)
		args->pitch = min_pitch;

	if (args->size < args->pitch * args->height)
		args->size = args->pitch * args->height;

	gobj = mga2_gem_create_with_handle(file, drm,
					   args->size, MGA2_GEM_DOMAIN_VRAM,
					   &args->handle);

	if (IS_ERR(gobj))
		return PTR_ERR(gobj);

	return 0;
}

/* rm 28020. Copy of drm_gem_dumb_map_offset() (linux-5.4) except of import_attach check */
int mga2_gem_dumb_map_offset(struct drm_file *file, struct drm_device *dev,
			    u32 handle, u64 *offset)
{
	struct drm_gem_object *obj;
	int ret;

	obj = drm_gem_object_lookup(file, handle);
	if (!obj)
		return -ENOENT;
#if 0
	/* Don't allow imported objects to be mapped */
	if (obj->import_attach) {
		ret = -EINVAL;
		goto out;
	}
#endif
	ret = drm_gem_create_mmap_offset(obj);
	if (ret)
		goto out;

	*offset = drm_vma_node_offset_addr(&obj->vma_node);
out:
	drm_gem_object_put(obj);

	return ret;
}

/**
 * mga2_prime_import_sg_table - produce a MGA2 GEM object from another
 *     driver's scatter/gather table of pinned pages
 * @dev: device to import into
 * @attach: DMA-BUF attachment
 * @sgt: scatter/gather table of pinned pages
 *
 * This function imports a scatter/gather table exported via DMA-BUF by
 * another driver. Imported buffers must be physically contiguous info memory
 * (i.e. the scatter/gather table must contain a single entry).
 *
 * Returns:
 * A pointer to a newly created GEM object or an ERR_PTR-encoded negative
 * error code on failure.
 */
struct drm_gem_object *mga2_prime_import_sg_table(struct drm_device *dev,
				     struct dma_buf_attachment *attach,
				     struct sg_table *sgt)
{
	struct mga2_gem_object *mo;
	/* check if the entries in the sg_table are contiguous */
	if (drm_prime_get_contiguous_size(sgt) < attach->dmabuf->size)
		return ERR_PTR(-EINVAL);

	mo = __mga2_gem_create(dev, attach->dmabuf->size);
	if (IS_ERR(mo))
		return (struct drm_gem_object *)mo;


	mo->write_domain = MGA2_GEM_DOMAIN_CPU;
	mo->dma_addr = sg_dma_address(sgt->sgl);

	return &mo->base;
}

#if 0
int mga2_gem_object_cpu_prep_ioctl(struct drm_device *drm, void *data,
				  struct drm_file *file)
{
	struct drm_mga2_gem_cpu_prep *a = data;
	struct mga2_gem_object *mo;
	struct mga2 *mga2 = drm->dev_private;
	struct drm_gem_object *gobj;
	bool wait = !(a->flags & MGA2_GEM_CPU_PREP_NOWAIT);
	int err = 0;

	if (a->flags & ~(MGA2_GEM_CPU_PREP_READ |
			    MGA2_GEM_CPU_PREP_WRITE |
			    MGA2_GEM_CPU_PREP_NOWAIT)) {
		return -EINVAL;
	}

	if (!(gobj = drm_gem_object_lookup(file, a->handle)))
		return -ENOENT;

	mo = to_mga2_gem(gobj);

	if (wait) {
		long lerr, to = msecs_to_jiffies(mga2_timeout(mga2));
		lerr = dma_resv_wait_timeout(&mo->resv,
						DMA_RESV_USAGE_KERNEL,
						true,
						to);
		if (lerr == 0) {
			err = -ETIMEDOUT;
			DRM_ERROR("gem object %d wait timed out.\n", a->handle);
		} else if (lerr < 0) {
			err = lerr;
		}
	} else if (!dma_resv_test_signaled(&mo->resv, DMA_RESV_USAGE_KERNEL)) {
		err = -EBUSY;
	}

	drm_gem_object_put(gobj);

	return err;
}

int mga2_gem_object_cpu_fini_ioctl(struct drm_device *drm, void *data,
				  struct drm_file *file)
{
	struct drm_mga2_gem_cpu_fini *a = data;
	struct mga2_gem_object *mo;
	struct drm_gem_object *gobj;
	int err = 0;

	if (a->pad)
		return -EINVAL;

	if (!(gobj = drm_gem_object_lookup(file, a->handle)))
		return -ENOENT;

	mo = to_mga2_gem(gobj);

	drm_gem_object_put(gobj);

	return err;
}
#endif


/*
 * mga2_mmap - (struct file_operation)->mmap callback function
 */
int mga2_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct drm_file *priv = file->private_data;
	struct drm_device *dev = priv->minor->dev;
	struct drm_gem_object *gobj;
	int ret = 0;

	ret = drm_gem_mmap(file, vma);
	if (ret)
		return ret;

	/* HACK: check whether it is not gma object and drm_gem_mmap()
		has already handled it.
	 */
	drm_vma_offset_lock_lookup(dev->vma_offset_manager);
	if (!drm_vma_offset_lookup_locked(dev->vma_offset_manager,
					   vma->vm_pgoff,
					   vma_pages(vma))) {

		drm_vma_offset_unlock_lookup(dev->vma_offset_manager);
		return 0;
	}
	drm_vma_offset_unlock_lookup(dev->vma_offset_manager);

	gobj = vma->vm_private_data;

	return mga2_gem_mmap(gobj, vma);
}

int mga2_gem_create_ioctl(struct drm_device *drm, void *data,
			  struct drm_file *file)
{
	struct drm_mga2_gem_create *args = data;
	struct drm_gem_object *gobj =
		mga2_gem_create_with_handle(file, drm,
					args->size, args->domain,
					&args->handle);

	if (IS_ERR(gobj))
		return PTR_ERR(gobj);

	return 0;
}

int mga2_gem_mmap_ioctl(struct drm_device *drm, void *data,
			struct drm_file *file)
{
	struct drm_mga2_gem_mmap *args = data;
	return drm_gem_dumb_map_offset(file, drm, args->handle,
						&args->offset);
}

int mga2_virt_to_handle(struct drm_device *drm, void *data,
			struct drm_file *file)
{
	int ret;
	struct sg_table *sgt = NULL;
	struct mga2_gem_object *mo;
	struct drm_gem_object *gobj;
	struct drm_mga2_virt_to_hndl *a = data;
	int n = a->nr_pages;

	a->handle = 0;

	mo = __mga2_gem_create(drm, n * PAGE_SIZE);
	if (IS_ERR(mo))
		return PTR_ERR(mo);

	gobj = &mo->base;

	ret = drm_gem_handle_create(file, gobj, &a->handle);
	if (ret)
		goto err;
	/* drop reference from allocate - handle holds it now. */
	drm_gem_object_put(gobj);

	mo->write_domain = MGA2_GEM_DOMAIN_CPU;
	mo->dma_dir = a->rw ? DMA_BIDIRECTIONAL :
				DMA_TO_DEVICE;
	sgt = kzalloc(sizeof(*sgt), GFP_KERNEL);
	if (!sgt) {
		ret = -ENOMEM;
		goto err;
	}
	mo->sgt = sgt;

	mo->pages = kvmalloc_array(n, sizeof(struct page *), GFP_KERNEL);
	if (!mo->pages) {
		ret = -ENOMEM;
		goto err;
	}
	mo->pages[0] = NULL; /*for mga2_gem_free()*/

	ret = get_user_pages(a->virt & PAGE_MASK, n, a->rw ? FOLL_WRITE : 0, mo->pages, NULL);
	if (ret != n) {
		if (ret >= 0) {
			release_pages(mo->pages, ret);
			a->nr_pages = ret;
			ret = -ERANGE;
		}
		mo->pages[0] = NULL; /*for mga2_gem_free()*/
		goto err;
	}

	mo->vaddr = vmap(mo->pages, n, VM_MAP, PAGE_KERNEL);
	if (!mo->vaddr) {
		ret = -EFAULT;
		goto err;
	}

	ret = sg_alloc_table_from_pages(sgt, mo->pages, n, 0,
				      n << PAGE_SHIFT,
				      GFP_KERNEL);
	if (ret)
		goto err;

	ret = dma_map_sg(drm->dev, sgt->sgl, sgt->nents, mo->dma_dir);
	if (ret != 1) {
		ret = -EFAULT;
		goto err;
	}
	ret = 0;

	mo->dma_addr = sg_dma_address(sgt->sgl);

	return 0;
err:
	if (a->handle)
		drm_gem_handle_delete(file, a->handle);
	else
		drm_gem_object_put(gobj);
	return ret;
}
