#include "mga2_drv.h"

static void mga2_user_framebuffer_destroy(struct drm_framebuffer *fb)
{
	struct mga2_framebuffer *mga2_fb = to_mga2_framebuffer(fb);
	if (mga2_fb->gobj)
		drm_gem_object_unreference_unlocked(mga2_fb->gobj);

	drm_framebuffer_cleanup(fb);
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

	ret = drm_framebuffer_init(drm, &mga2_fb->base, &mga2_fb_funcs);
	if (ret) {
		DRM_ERROR("framebuffer init failed %d\n", ret);
		return ret;
	}
	drm_helper_mode_fill_fb_struct(&mga2_fb->base, mode_cmd);
	mga2_fb->gobj = gobj;
	return 0;
}

static struct drm_framebuffer *mga2_user_framebuffer_create(struct drm_device
							    *drm, struct drm_file
							    *file, struct
							    drm_mode_fb_cmd2
							    *mode_cmd)
{
	struct drm_gem_object *gobj;
	struct mga2_framebuffer *mga2_fb;
	int ret;

	gobj = drm_gem_object_lookup(drm, file, mode_cmd->handles[0]);
	if (gobj == NULL)
		return ERR_PTR(-ENOENT);

	mga2_fb = kzalloc(sizeof(*mga2_fb), GFP_KERNEL);
	if (!mga2_fb) {
		drm_gem_object_unreference_unlocked(gobj);
		return ERR_PTR(-ENOMEM);
	}

	ret = mga2_framebuffer_init(drm, mga2_fb, mode_cmd, gobj);
	if (ret) {
		drm_gem_object_unreference_unlocked(gobj);
		kfree(mga2_fb);
		return ERR_PTR(ret);
	}
	return &mga2_fb->base;
}

static const struct drm_mode_config_funcs mga2_mode_funcs = {
	.fb_create = mga2_user_framebuffer_create,
};

int mga2_driver_load(struct drm_device *drm, unsigned long flags)
{
	struct mga2 *mga2;
	int ret = 0, irq = 0;
	char *irqname;

	mga2 = kzalloc(sizeof(struct mga2), GFP_KERNEL);
	if (!mga2)
		return -ENOMEM;

	drm->dev_private = mga2;
	mga2->drm = drm;
	mga2->vram_paddr = pci_resource_start(drm->pdev, 0);

	mga2->regs = pci_iomap(drm->pdev, 2, 0);
	if (!mga2->regs) {
		ret = -EIO;
		goto out_free;
	}

	mga2->subdevice = 0xffff;
	pci_read_config_word(drm->pdev, PCI_SUBSYSTEM_ID, &mga2->subdevice);
	DRM_INFO("subdevice ID: %x\n", mga2->subdevice);

	if (mga2_p2(mga2)) {
#define PCI_VCFG	0x40
#define PCI_MGA2_RESET	(1 << 2)
		u16 cmd, vcfg;

		pci_read_config_word(drm->pdev, PCI_COMMAND, &cmd);
		pci_write_config_word(drm->pdev, PCI_COMMAND,
				      cmd & ~PCI_COMMAND_MASTER);

		pci_read_config_word(drm->pdev, PCI_VCFG, &vcfg);
		vcfg &= ~PCI_MGA2_RESET;
		pci_write_config_word(drm->pdev, PCI_VCFG,
				      vcfg | PCI_MGA2_RESET);
		udelay(1);
		pci_write_config_word(drm->pdev, PCI_VCFG, vcfg);
		pci_write_config_word(drm->pdev, PCI_COMMAND, cmd);
	}
	pci_set_master(drm->pdev);

	mutex_init(&mga2->bctrl_mu);
	rwlock_init(&mga2->vram_lock);

	drm_mm_init(&mga2->vram_mm, pci_resource_start(drm->pdev, 0),
		    pci_resource_len(drm->pdev, 0));

	drm_mode_config_init(drm);

	drm->mode_config.funcs = (void *)&mga2_mode_funcs;
	drm->mode_config.min_width = 0;
	drm->mode_config.min_height = 0;
	drm->mode_config.preferred_depth = 24;
	drm->mode_config.prefer_shadow = 1;

	drm->mode_config.max_width = 1920;
	drm->mode_config.max_height = 2048;

	ret = mga2_mode_init(drm);
	if (ret)
		goto out_free;

	ret = mga2_fbdev_init(drm);
	if (ret)
		goto out_free;

	if (!pci_dev_msi_enabled(drm->pdev))
		ret = pci_enable_msi_block(drm->pdev, mga2_p2(mga2) ? 2 : 1);

	irq = drm->pdev->irq;
	if (mga2_p2(mga2)) {
		if (pci_dev_msi_enabled(drm->pdev))
			irq++;
		else
			irq = 25;
	}

	if (drm->devname)
		irqname = drm->devname;
	else
		irqname = drm->driver->name;
	ret = request_irq(irq, drm->driver->irq_handler,
			  IRQF_NO_THREAD, irqname, drm);

	if (!ret)
		drm->irq_enabled = 1;

	return ret;
      out_free:
	kfree(mga2);
	drm->dev_private = NULL;
	return ret;
}

int mga2_driver_unload(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;

	drm_irq_uninstall(drm);
	pci_disable_msi(drm->pdev);

	mga2_mode_fini(drm);
	mga2_fbdev_fini(drm);
	drm_mode_config_cleanup(drm);
	drm_mm_takedown(&mga2->vram_mm);
	pci_iounmap(drm->pdev, mga2->regs);
	kfree(mga2);
	return 0;
}

void mga2_lastclose(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;
	drm_modeset_lock_all(drm);
	drm_fb_helper_restore_fbdev_mode(&mga2->fbdev->helper);
	drm_modeset_unlock_all(drm);
}

struct drm_gem_object *mga2_gem_create(struct drm_device *drm,
				       size_t size, u32 domain)
{
	int ret;
	struct mga2 *mga2 = drm->dev_private;
	struct drm_gem_object *gobj;
	struct drm_mm_node *node = NULL;

	if (!(gobj = kzalloc(sizeof(*gobj), GFP_KERNEL)) ||
	    !(node = kzalloc(sizeof(*node), GFP_KERNEL))) {
		ret = -ENOMEM;
		goto fail;
	}

	ret = drm_gem_object_init(drm, gobj, size);
	if (ret)
		goto fail;

	ret = drm_gem_create_mmap_offset(gobj);
	if (ret) {
		drm_gem_object_release(gobj);
		goto fail;
	}

	switch (domain) {
	case MGA2_GEM_DOMAIN_VRAM:{
			mutex_lock(&mga2->drm->struct_mutex);
			if ((ret =
			     drm_mm_insert_node(&mga2->vram_mm, node, size,
						0, DRM_MM_SEARCH_DEFAULT))) {
				mutex_unlock(&mga2->drm->struct_mutex);
				goto fail;
			}
			mutex_unlock(&mga2->drm->struct_mutex);
			break;
		}
	case MGA2_GEM_DOMAIN_CPU:{
			dma_addr_t dma;
			void *a = dma_alloc_coherent(drm->dev, size,
						     &dma,
						     GFP_KERNEL | GFP_DMA);
			if (unlikely(!a)) {
				ret = -ENOMEM;
				goto fail;
			}
			node->start = __pa(a);
			node->size = (unsigned long)dma;
			break;
		}
	default:
		drm_gem_object_release(gobj);
		ret = -EINVAL;
		goto fail;
	}
	gobj->write_domain = domain;
	gobj->driver_private = node;

	return gobj;
      fail:
	kfree(gobj);
	kfree(node);
	return ERR_PTR(ret);
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
	drm_gem_object_unreference_unlocked(gobj);
	if (ret) {
		drm_gem_object_unreference_unlocked(gobj);
		return ERR_PTR(ret);
	} else {
		return gobj;
	}
}

void mga2_gem_free_object(struct drm_gem_object *gobj)
{
	struct drm_device *drm = gobj->dev;
	struct drm_mm_node *node = gobj->driver_private;

	drm_gem_free_mmap_offset(gobj);
	drm_gem_object_release(gobj);

	switch (gobj->write_domain) {
	case MGA2_GEM_DOMAIN_VRAM:{
			drm_mm_remove_node(node);
			break;
		}
	case MGA2_GEM_DOMAIN_CPU:{
			dma_addr_t dma = (dma_addr_t) node->size;
			void *va = __va(node->start);
			dma_free_coherent(drm->dev, gobj->size, va, dma);
			break;
		}
	default:
		BUG();
	}
	kfree(gobj);
	kfree(node);
}

/*
 * mga2_gem_mmap - (struct file_operation)->mmap callback function
 */
int mga2_mmap(struct file *file, struct vm_area_struct *vma)
{
	struct drm_gem_object *gobj;
	struct drm_mm_node *node;
	int ret = 0;
#ifdef __sparc__
	pgprot_t vm_page_prot = vma->vm_page_prot;
#endif

	ret = drm_gem_mmap(file, vma);
	if (ret)
		return ret;

	gobj = vma->vm_private_data;
	node = gobj->driver_private;

	switch (gobj->write_domain) {
	case MGA2_GEM_DOMAIN_VRAM:{
			ret =
			    io_remap_pfn_range(vma, vma->vm_start,
					       node->start >> PAGE_SHIFT,
					       vma->vm_end - vma->vm_start,
					       vma->vm_page_prot);
			break;
		}
	case MGA2_GEM_DOMAIN_CPU:{
#ifdef __sparc__
			vma->vm_page_prot = vm_page_prot;
#endif
			ret =
			    remap_pfn_range(vma, vma->vm_start,
					    node->start >> PAGE_SHIFT,
					    vma->vm_end - vma->vm_start,
					    vma->vm_page_prot);
			break;
		}
	default:
		BUG();
	}
	if (ret)
		drm_gem_vm_close(vma);

	return ret;
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

int mga2_dumb_destroy(struct drm_file *file,
		      struct drm_device *drm, uint32_t handle)
{
	return drm_gem_handle_delete(file, handle);
}

int mga2_dumb_mmap_offset(struct drm_file *file,
			  struct drm_device *drm, uint32_t handle,
			  uint64_t *offset)
{
	struct drm_gem_object *gobj;

	mutex_lock(&drm->struct_mutex);

	gobj = drm_gem_object_lookup(drm, file, handle);
	if (!gobj) {
		dev_err(drm->dev, "failed to lookup gem object\n");
		mutex_unlock(&drm->struct_mutex);
		return -EINVAL;
	}

	*offset = drm_vma_node_offset_addr(&gobj->vma_node);

	drm_gem_object_unreference(gobj);

	mutex_unlock(&drm->struct_mutex);

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

	return mga2_dumb_mmap_offset(file, drm, args->handle, &args->offset);
}
