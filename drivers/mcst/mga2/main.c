#include "drv.h"

static void mga2_user_framebuffer_destroy(struct drm_framebuffer *fb)
{
	struct mga2_framebuffer *mga2_fb = to_mga2_framebuffer(fb);
	drm_framebuffer_cleanup(fb);
	drm_gem_object_put_unlocked(mga2_fb->gobj);
	kfree(fb);
}

static int mga2_user_framebuffer_create_handle(struct drm_framebuffer *fb,
					       struct drm_file *file,
					       unsigned int *handle)
{
	return -EINVAL;
}

static const struct drm_framebuffer_funcs mga2_fb_funcs = {
	.destroy = mga2_user_framebuffer_destroy,
	.create_handle = mga2_user_framebuffer_create_handle,
};

int mga2_framebuffer_init(struct drm_device *drm,
			  struct mga2_framebuffer *mga2_fb,
			  struct drm_mode_fb_cmd2 *mode_cmd,
			  struct drm_gem_object *gobj)
{
	int ret;
	drm_helper_mode_fill_fb_struct(drm, &mga2_fb->base, mode_cmd);

	ret = drm_framebuffer_init(drm, &mga2_fb->base, &mga2_fb_funcs);
	if (ret) {
		DRM_ERROR("framebuffer init failed %d\n", ret);
		return ret;
	}
	mga2_fb->gobj = gobj;
	return 0;
}

static struct mga2_gem_object *
__mga2_gem_create(struct drm_device *drm, size_t size)
{
	int ret;
	struct mga2_gem_object *obj;
	struct drm_gem_object *gobj =
			 kzalloc(sizeof(*obj), GFP_KERNEL);
	if (!gobj)
		return ERR_PTR(-ENOMEM);
	obj = container_of(gobj, struct mga2_gem_object, base);

	ret = drm_gem_object_init(drm, gobj, size);
	if (ret)
		goto error;

	ret = drm_gem_create_mmap_offset(gobj);
	if (ret) {
		drm_gem_object_release(gobj);
		goto error;
	}

	return obj;

error:
	kfree(obj);
	return ERR_PTR(ret);
}

struct gen_pool *mga2_uncached_pool;
unsigned long mga2_uncached_pool_first_pa;

/*
 * Add a new chunk of uncached memory pages to the specified pool.
 *
 * @pool: pool to add new chunk of uncached memory to
 * @nid: node id of node to allocate memory from, or -1
 *
 * This is accomplished by first allocating a granule of cached memory pages
 * and then converting them to uncached memory pages.
 */
static int mga2_uncached_add_chunk(struct mga2 *mga2,
				   struct gen_pool *uc_pool, int nid)
{
	int ret;
	unsigned long pa;
	struct page *page = __alloc_pages_node(nid, GFP_KERNEL | __GFP_THISNODE,
							MAX_ORDER - 1);
	if (!page)
		return -1;
	pa = page_to_phys(page);
	if (mga2->uncached_pool_first_pa)
		WARN_ON(pa >> 32 != mga2->uncached_pool_first_pa >> 32);
	else
		mga2->uncached_pool_first_pa = pa;

	ret = gen_pool_add(uc_pool, pa,
			    PAGE_SIZE << (MAX_ORDER - 1), nid);
	if (ret)
		goto failed;
	/*FIXME: NUMA */
#ifdef CONFIG_E90S
	e90s_flush_l2_cache();
#elif defined(CONFIG_E2K)
	write_back_cache_all();
#else
	WARN("FIXME: add flush cache\n");
#endif
	return 0;
failed:
	__free_pages(page, MAX_ORDER - 1);
	return -1;
}

/*
 * mga2_uncached_alloc_page
 *
 * @nid: node id, or -1
 * @n_pages: number of contiguous pages to allocate
 *
 * Allocate the specified number of contiguous uncached pages on the
 * the requested node.
 */
static unsigned long mga2_uncached_alloc_page(struct mga2 *mga2,
						int nid, int n_pages)
{
	unsigned long uc_addr;
	struct gen_pool *uc_pool = mga2->uncached_pool;

	do {
		uc_addr = gen_pool_alloc(uc_pool, n_pages * PAGE_SIZE);
		if (uc_addr != 0)
			return uc_addr;
	} while (mga2_uncached_add_chunk(mga2, uc_pool, nid) == 0);

	return 0;
}

/*
 * uncached_free_page
 *
 * @uc_addr: uncached address of first page to free
 * @n_pages: number of contiguous pages to free
 *
 * Free the specified number of uncached pages.
 */
static void mga2_uncached_free_page(struct mga2 *mga2,
				unsigned long uc_addr, int n_pages)
{
	struct gen_pool *pool = mga2->uncached_pool;
	gen_pool_free(pool, uc_addr, n_pages * PAGE_SIZE);
}


static void *mga2_alloc_uncached(struct device *dev, size_t size,
		dma_addr_t *dma_handle, gfp_t gfp)
{
	void *v;
	struct drm_device *drm = dev_get_drvdata(dev);
	struct mga2 *mga2 = drm->dev_private;
	int pages = PAGE_ALIGN(size) / PAGE_SIZE;
	unsigned long p = mga2_uncached_alloc_page(mga2,
					dev_to_node(dev), pages);
	if (p == 0)
		return NULL;

	v = ioremap_wc(p, size);
	if (!v) {
		mga2_uncached_free_page(mga2, dev_to_node(dev), pages);
		return NULL;
	}

	memset_io(v, 0, size);
	*dma_handle = p - (mga2->uncached_pool_first_pa & (~0UL << 32));

	return v;
}

static void mga2_free_uncached(struct device *dev, size_t size,
		void *cpu_addr, dma_addr_t dma_handle)
{
	int pages = PAGE_ALIGN(size) / PAGE_SIZE;
	struct drm_device *drm = dev_get_drvdata(dev);
	struct mga2 *mga2 = drm->dev_private;
	iounmap(cpu_addr);
	dma_handle += mga2->uncached_pool_first_pa & (~0UL << 32);
	mga2_uncached_free_page(mga2, dma_handle, pages);
}

static void mga2_free_chunk(struct gen_pool *pool,
			      struct gen_pool_chunk *chunk, void *data)
{
	__free_pages(phys_to_page(chunk->start_addr), MAX_ORDER - 1);
}

void mga2_pool_destroy(struct gen_pool *pool, struct device *dev)
{
	if (!pool)
		return;
	/* this is quite ugly but no better idea */
	gen_pool_for_each_chunk(pool, mga2_free_chunk, dev);
	gen_pool_destroy(pool);
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
	case MGA2_GEM_DOMAIN_VRAM: if (mga2_use_uncached(mga2->dev_id)) {
		obj->vaddr = mga2_alloc_uncached(drm->dev, size,
				&obj->dma_addr, flag);
		if (!obj->vaddr) {
			ret = -ENOMEM;
			goto fail;
		}
	} else {
		mutex_lock(&mga2->vram_mu);
		ret = drm_mm_insert_node(&mga2->vram_mm, node, size);
		mutex_unlock(&mga2->vram_mu);
		if (ret)
			goto fail;

		obj->dma_addr = node->start - mga2->vram_paddr;
		obj->vaddr = ioremap_wc(node->start, size);
		if (!obj->vaddr) {
			ret = -EFAULT;
			goto fail;
		}
		memset_io(obj->vaddr, 0, size);
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
	dma_resv_init(&obj->resv);

	return gobj;
      fail:
	drm_gem_object_release(gobj);
	kfree(obj);
	return ERR_PTR(ret);
}

void mga2_gem_free_object(struct drm_gem_object *gobj)
{
	struct drm_device *drm = gobj->dev;
	struct mga2_gem_object *mo = to_mga2_obj(gobj);
	struct drm_mm_node *node = &mo->node;
	struct dma_resv *resv = &mo->resv;
	struct mga2 *mga2 = (struct mga2 *)gobj->dev->dev_private;
	long ret = 0, timeout_msec = mga2_timeout(mga2);

	if (0)
		DRM_DEBUG("freeing %llx with %d\n", mo->dma_addr,
			resv->fence ? resv->fence->shared_count : 0);
	ret = dma_resv_wait_timeout_rcu(resv, true, false,
					msecs_to_jiffies(timeout_msec));
	if (ret == 0) {
		DRM_ERROR("mga2: reservation %d wait timed out.\n", mga2->tail);
	} else if (ret < 0) {
		DRM_ERROR("mga2: reservation wait failed (%ld).\n", ret);
	}

	drm_gem_free_mmap_offset(gobj);

	switch (mo->write_domain) {
	case MGA2_GEM_DOMAIN_VRAM:
		if (mga2_use_uncached(mga2->dev_id)) {
			mga2_free_uncached(drm->dev, gobj->size,
					mo->vaddr, mo->dma_addr);
		} else {
			mutex_lock(&mga2->vram_mu);
			drm_mm_remove_node(node);
			mutex_unlock(&mga2->vram_mu);
		}
		break;
	case MGA2_GEM_DOMAIN_CPU: {
		 if (gobj->import_attach) {
			drm_prime_gem_destroy(gobj, mo->sgt);
			vunmap(mo->vaddr);
		} else if (mo->vaddr) {
			dma_free_coherent(drm->dev, gobj->size,
					mo->vaddr, mo->dma_addr);
		}
		break;
	}
	default:
		WARN_ON(1);
	}
	dma_resv_fini(&mo->resv);
	drm_gem_object_release(gobj);
	kvfree(mo->pages);
	kfree(mo);
}

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

	/* drop reference from allocate - handle holds it now. */
	drm_gem_object_put_unlocked(gobj);
	if (ret)
		return ERR_PTR(ret);
	return gobj;
}

static int mga2_gem_object_mmap(struct drm_gem_object *gobj,
				   struct vm_area_struct *vma)
{
	int ret = 0;
	struct mga2_gem_object *mo = to_mga2_obj(gobj);
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
			pfn = (long)mo->vaddr >> PAGE_SHIFT;
			WARN(!IS_ENABLED(CONFIG_E90S), "FIXME:pfn\n");
		}

		ret = io_remap_pfn_range(vma, vma->vm_start,
					pfn,
					vma->vm_end - vma->vm_start,
					ttm_io_prot(TTM_PL_FLAG_WC,
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

/*
 * mga2_gem_mmap - (struct file_operation)->mmap callback function
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
	return mga2_gem_object_mmap(gobj, vma);
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

#ifdef CONFIG_E2K
static void mga2_flush_cache_range(void *start, void *end)
{
	flush_DCACHE_range(start, (u64)start - (u64)end);
}
#else
#define mga2_flush_cache_range(a, b)
#endif

/* low-level interface prime helpers */

/**
 * mga2_prime_get_sg_table - provide a scatter/gather table of pinned
 *     pages for a MGA2 GEM object
 * @obj: GEM object
 *
 * This function exports a scatter/gather table suitable for PRIME usage by
 * calling the standard DMA mapping API.
 *
 * Returns:
 * A pointer to the scatter/gather table of pinned pages or NULL on failure.
 */
struct sg_table *mga2_prime_get_sg_table(struct drm_gem_object *obj)
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

	mga2_flush_cache_range(mga2_gem->vaddr, mga2_gem->vaddr + obj->size);

	return sgt;

out:
	kfree(sgt);
	return NULL;
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
struct drm_gem_object *
mga2_prime_import_sg_table(struct drm_device *dev,
				     struct dma_buf_attachment *attach,
				     struct sg_table *sgt)
{
	struct mga2_gem_object *mo;
	int npages;
	int ret;

	mo = __mga2_gem_create(dev, attach->dmabuf->size);
	if (IS_ERR(mo)) {
		ret = PTR_ERR(mo);
		return ERR_PTR(ret);
	}

	npages = DIV_ROUND_UP(mo->base.size, PAGE_SIZE);
	mo->pages = kvmalloc_array(npages,
				sizeof(struct page *), GFP_KERNEL);
	if (!mo->pages) {
		ret = -ENOMEM;
		goto err;
	}

	ret = drm_prime_sg_to_page_addr_arrays(sgt, mo->pages, NULL,
					       npages);
	if (ret < 0)
		goto err_free_large;

	mo->vaddr = vmap(mo->pages, npages, VM_MAP, PAGE_KERNEL);
	if (!mo->vaddr) {
		ret = -EFAULT;
		goto err_free_large;
	}
	mo->write_domain = MGA2_GEM_DOMAIN_CPU;
	mo->dma_addr = sg_dma_address(sgt->sgl);
	mo->sgt = sgt;

	return &mo->base;

err_free_large:
	kvfree(mo->pages);
err:
	drm_gem_object_release(&mo->base);
	kfree(mo);
	return ERR_PTR(ret);
}

/**
 * mga2_prime_mmap - memory-map an exported GEM object
 * @obj: GEM object
 * @vma: VMA for the area to be mapped
 *
 * This function maps a buffer imported via DRM PRIME into a userspace
 * process's address space.
 *
 * Returns:
 * 0 on success or a negative error code on failure.
 */
int mga2_prime_mmap(struct drm_gem_object *gobj,
			   struct vm_area_struct *vma)
{
	int ret;

	ret = drm_gem_mmap_obj(gobj, gobj->size, vma);
	if (ret < 0)
		return ret;

	return mga2_gem_object_mmap(gobj, vma);
}

/**
 * mga2_prime_vmap - map a GEM object into the kernel's virtual
 *     address space
 * @obj: GEM object
 *
 * This function maps a buffer exported via DRM PRIME into the kernel's
 * virtual address space. Since the MGA2 buffers are already mapped into the
 * kernel virtual address space this simply returns the cached virtual
 * address.
 *
 * Returns:
 * The kernel virtual address of the MGA2 GEM object's backing store.
 */
void *mga2_prime_vmap(struct drm_gem_object *gobj)
{
	struct mga2_gem_object *obj = to_mga2_obj(gobj);

	return obj->vaddr;
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
void mga2_prime_vunmap(struct drm_gem_object *gobj, void *vaddr)
{
	/* Nothing to do */
}

#ifdef CONFIG_DEBUG_FS
static int mga2_debugfs_framebuffers(struct seq_file *s, void *data)
{
	struct drm_info_node *node = (struct drm_info_node *)s->private;
	struct drm_device *drm = node->minor->dev;
	struct drm_framebuffer *fb;

	mutex_lock(&drm->mode_config.fb_lock);

	list_for_each_entry(fb, &drm->mode_config.fb_list, head) {
		seq_printf(s, "%3d: user size: %d x %d, depth %d, %d bpp, refcount %d\n",
			   fb->base.id, fb->width, fb->height,
			   fb->format->depth,
			   fb->format->cpp[0] * 8,
			   drm_framebuffer_read_refcount(fb));
	}

	mutex_unlock(&drm->mode_config.fb_lock);

	return 0;
}

static int mga2_debugfs_iova(struct seq_file *s, void *data)
{
	struct drm_info_node *node = (struct drm_info_node *)s->private;
	struct drm_device *drm = node->minor->dev;
	struct mga2 *mga2 = drm->dev_private;
	struct drm_printer p = drm_seq_file_printer(s);

	drm_mm_print(&mga2->vram_mm, &p);

	return 0;
}

static int mga2_debugfs_gem_bo_info(int id, void *ptr, void *data)
{
	struct drm_gem_object *gobj = ptr;
	struct mga2_gem_object *obj = to_mga2_obj(gobj);
	struct drm_mm_node *node = &obj->node;
	struct seq_file *m = data;

	const char *placement = "BUG";

	switch (obj->write_domain) {
	case MGA2_GEM_DOMAIN_VRAM:
		placement = "VRAM";
		break;
	case MGA2_GEM_DOMAIN_CPU:
		placement = " CPU";
		break;
	}
	seq_printf(m, "\t0x%08x: %12ld byte %s @ 0x%010llx\n",
		   id, gobj->size, placement, node->start);

	return 0;
}

static int mga2_debugfs_gem_info(struct seq_file *m, void *data)
{
	struct drm_info_node *node = (struct drm_info_node *)m->private;
	struct drm_device *dev = node->minor->dev;
	struct drm_file *file;
	struct mga2 *mga2 = dev->dev_private;
	int r;

	r = mutex_lock_interruptible(&mga2->vram_mu);
	if (r)
		return r;

	list_for_each_entry(file, &dev->filelist, lhead) {
		struct task_struct *task;

		/*
		 * Although we have a valid reference on file->pid, that does
		 * not guarantee that the task_struct who called get_pid() is
		 * still alive (e.g. get_pid(current) => fork() => exit()).
		 * Therefore, we need to protect this ->comm access using RCU.
		 */
		rcu_read_lock();
		task = pid_task(file->pid, PIDTYPE_PID);
		seq_printf(m, "pid %8d command %s:\n", pid_nr(file->pid),
			   task ? task->comm : "<unknown>");
		rcu_read_unlock();

		spin_lock(&file->table_lock);
		idr_for_each(&file->object_idr, mga2_debugfs_gem_bo_info, m);
		spin_unlock(&file->table_lock);
	}

	mutex_unlock(&mga2->vram_mu);
	return 0;
}

static struct drm_info_list mga2_debugfs_list[] = {
	{ "mga2_framebuffers", mga2_debugfs_framebuffers},
	{ "mga2_vram_mm"     , mga2_debugfs_iova},
	{ "mga2_gem_info"    , &mga2_debugfs_gem_info},
	{ "mga2-bctrl"       , &mga2_debugfs_bctrl},
};

int mga2_debugfs_init(struct drm_minor *minor)
{
	return drm_debugfs_create_files(mga2_debugfs_list,
					ARRAY_SIZE(mga2_debugfs_list),
					minor->debugfs_root, minor);
}
#endif
