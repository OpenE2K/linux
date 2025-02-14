// SPDX-License-Identifier: GPL-2.0-or-later
/*
 *  Copyright (c) by Jaroslav Kysela <perex@perex.cz>
 *                   Takashi Iwai <tiwai@suse.de>
 * 
 *  Generic memory allocators
 */

#include <linux/slab.h>
#include <linux/mm.h>
#include <linux/dma-mapping.h>
#include <linux/genalloc.h>
#ifdef CONFIG_MCST
#include <linux/pci.h>
#endif
#if defined CONFIG_X86 || defined CONFIG_E2K
#include <asm/set_memory.h>
#endif
#include <sound/memalloc.h>

/*
 *
 *  Bus-specific memory allocators
 *
 */

#ifdef CONFIG_HAS_DMA
#ifdef CONFIG_MCST
static const struct pci_device_id snd_dma_bug_ids[] = {
	{PCI_VDEVICE(CMEDIA, PCI_DEVICE_ID_CMEDIA_CM8338A), 0},
	{PCI_VDEVICE(CMEDIA, PCI_DEVICE_ID_CMEDIA_CM8338B), 0},
	{PCI_VDEVICE(CMEDIA, PCI_DEVICE_ID_CMEDIA_CM8738), 0},
	{PCI_VDEVICE(CMEDIA, PCI_DEVICE_ID_CMEDIA_CM8738B), 0},
	{PCI_VDEVICE(AL, PCI_DEVICE_ID_CMEDIA_CM8738), 0},
	{0,},
};

static int add_pad_for_buggy_cards(struct device *dev)
{
	if (dev_is_pci(dev) &&
		pci_match_id(snd_dma_bug_ids, to_pci_dev(dev))) {
		return PAGE_SIZE;
	}
	return 0;
}
#endif /*CONFIG_MCST*/

/* allocate the coherent DMA pages */
static void snd_malloc_dev_pages(struct snd_dma_buffer *dmab, size_t size)
{
	gfp_t gfp_flags;

	gfp_flags = GFP_KERNEL
		| __GFP_COMP	/* compound page lets parts be mapped */
		| __GFP_NORETRY /* don't trigger OOM-killer */
		| __GFP_NOWARN; /* no stack trace print - this call is non-critical */

#ifdef CONFIG_MCST
	size += add_pad_for_buggy_cards(dmab->dev.dev);
#endif
	dmab->area = dma_alloc_coherent(dmab->dev.dev, size, &dmab->addr,
					gfp_flags);
#if defined CONFIG_X86 || defined CONFIG_E2K
	if (dmab->area && dmab->dev.type == SNDRV_DMA_TYPE_DEV_UC)
		set_memory_wc((unsigned long)dmab->area,
			      PAGE_ALIGN(size) >> PAGE_SHIFT);
#endif
}

/* free the coherent DMA pages */
static void snd_free_dev_pages(struct snd_dma_buffer *dmab)
{
#ifdef CONFIG_MCST
	size_t size = dmab->bytes + add_pad_for_buggy_cards(dmab->dev.dev);
#endif
#ifdef CONFIG_X86
	if (dmab->dev.type == SNDRV_DMA_TYPE_DEV_UC)
		set_memory_wb((unsigned long)dmab->area,
			      PAGE_ALIGN(dmab->bytes) >> PAGE_SHIFT);
#endif
#ifdef CONFIG_E2K
	if (dmab->dev.type == SNDRV_DMA_TYPE_DEV_UC)
		set_memory_wb((unsigned long)dmab->area,
			      PAGE_ALIGN(size) >> PAGE_SHIFT);
#endif
#ifdef CONFIG_MCST
	dma_free_coherent(dmab->dev.dev, size, dmab->area, dmab->addr);
#else
	dma_free_coherent(dmab->dev.dev, dmab->bytes, dmab->area, dmab->addr);
#endif
}

#ifdef CONFIG_GENERIC_ALLOCATOR
/**
 * snd_malloc_dev_iram - allocate memory from on-chip internal ram
 * @dmab: buffer allocation record to store the allocated data
 * @size: number of bytes to allocate from the iram
 *
 * This function requires iram phandle provided via of_node
 */
static void snd_malloc_dev_iram(struct snd_dma_buffer *dmab, size_t size)
{
	struct device *dev = dmab->dev.dev;
	struct gen_pool *pool = NULL;

	dmab->area = NULL;
	dmab->addr = 0;

	if (dev->of_node)
		pool = of_gen_pool_get(dev->of_node, "iram", 0);

	if (!pool)
		return;

	/* Assign the pool into private_data field */
	dmab->private_data = pool;

	dmab->area = gen_pool_dma_alloc_align(pool, size, &dmab->addr,
					PAGE_SIZE);
}

/**
 * snd_free_dev_iram - free allocated specific memory from on-chip internal ram
 * @dmab: buffer allocation record to store the allocated data
 */
static void snd_free_dev_iram(struct snd_dma_buffer *dmab)
{
	struct gen_pool *pool = dmab->private_data;

	if (pool && dmab->area)
		gen_pool_free(pool, (unsigned long)dmab->area, dmab->bytes);
}
#endif /* CONFIG_GENERIC_ALLOCATOR */
#endif /* CONFIG_HAS_DMA */

/*
 *
 *  ALSA generic memory management
 *
 */


/**
 * snd_dma_alloc_pages - allocate the buffer area according to the given type
 * @type: the DMA buffer type
 * @device: the device pointer
 * @size: the buffer size to allocate
 * @dmab: buffer allocation record to store the allocated data
 *
 * Calls the memory-allocator function for the corresponding
 * buffer type.
 *
 * Return: Zero if the buffer with the given size is allocated successfully,
 * otherwise a negative value on error.
 */
int snd_dma_alloc_pages(int type, struct device *device, size_t size,
			struct snd_dma_buffer *dmab)
{
	if (WARN_ON(!size))
		return -ENXIO;
	if (WARN_ON(!dmab))
		return -ENXIO;
	if (WARN_ON(!device))
		return -EINVAL;

	dmab->dev.type = type;
	dmab->dev.dev = device;
	dmab->bytes = 0;
	switch (type) {
	case SNDRV_DMA_TYPE_CONTINUOUS:
		dmab->area = alloc_pages_exact(size,
					       (__force gfp_t)(unsigned long)device);
		dmab->addr = 0;
		break;
#ifdef CONFIG_HAS_DMA
#ifdef CONFIG_GENERIC_ALLOCATOR
	case SNDRV_DMA_TYPE_DEV_IRAM:
		snd_malloc_dev_iram(dmab, size);
		if (dmab->area)
			break;
		/* Internal memory might have limited size and no enough space,
		 * so if we fail to malloc, try to fetch memory traditionally.
		 */
		dmab->dev.type = SNDRV_DMA_TYPE_DEV;
#endif /* CONFIG_GENERIC_ALLOCATOR */
		/* fall through */
	case SNDRV_DMA_TYPE_DEV:
	case SNDRV_DMA_TYPE_DEV_UC:
		snd_malloc_dev_pages(dmab, size);
		break;
#endif
#ifdef CONFIG_SND_DMA_SGBUF
	case SNDRV_DMA_TYPE_DEV_SG:
	case SNDRV_DMA_TYPE_DEV_UC_SG:
		snd_malloc_sgbuf_pages(device, size, dmab, NULL);
		break;
#endif
	default:
		pr_err("snd-malloc: invalid device type %d\n", type);
		dmab->area = NULL;
		dmab->addr = 0;
		return -ENXIO;
	}
	if (! dmab->area)
		return -ENOMEM;
	dmab->bytes = size;
	return 0;
}
EXPORT_SYMBOL(snd_dma_alloc_pages);

/**
 * snd_dma_alloc_pages_fallback - allocate the buffer area according to the given type with fallback
 * @type: the DMA buffer type
 * @device: the device pointer
 * @size: the buffer size to allocate
 * @dmab: buffer allocation record to store the allocated data
 *
 * Calls the memory-allocator function for the corresponding
 * buffer type.  When no space is left, this function reduces the size and
 * tries to allocate again.  The size actually allocated is stored in
 * res_size argument.
 *
 * Return: Zero if the buffer with the given size is allocated successfully,
 * otherwise a negative value on error.
 */
int snd_dma_alloc_pages_fallback(int type, struct device *device, size_t size,
				 struct snd_dma_buffer *dmab)
{
	int err;

	while ((err = snd_dma_alloc_pages(type, device, size, dmab)) < 0) {
		if (err != -ENOMEM)
			return err;
		if (size <= PAGE_SIZE)
			return -ENOMEM;
		size >>= 1;
		size = PAGE_SIZE << get_order(size);
	}
	if (! dmab->area)
		return -ENOMEM;
	return 0;
}
EXPORT_SYMBOL(snd_dma_alloc_pages_fallback);


/**
 * snd_dma_free_pages - release the allocated buffer
 * @dmab: the buffer allocation record to release
 *
 * Releases the allocated buffer via snd_dma_alloc_pages().
 */
void snd_dma_free_pages(struct snd_dma_buffer *dmab)
{
	switch (dmab->dev.type) {
	case SNDRV_DMA_TYPE_CONTINUOUS:
		free_pages_exact(dmab->area, dmab->bytes);
		break;
#ifdef CONFIG_HAS_DMA
#ifdef CONFIG_GENERIC_ALLOCATOR
	case SNDRV_DMA_TYPE_DEV_IRAM:
		snd_free_dev_iram(dmab);
		break;
#endif /* CONFIG_GENERIC_ALLOCATOR */
	case SNDRV_DMA_TYPE_DEV:
	case SNDRV_DMA_TYPE_DEV_UC:
		snd_free_dev_pages(dmab);
		break;
#endif
#ifdef CONFIG_SND_DMA_SGBUF
	case SNDRV_DMA_TYPE_DEV_SG:
	case SNDRV_DMA_TYPE_DEV_UC_SG:
		snd_free_sgbuf_pages(dmab);
		break;
#endif
	default:
		pr_err("snd-malloc: invalid device type %d\n", dmab->dev.type);
	}
}
EXPORT_SYMBOL(snd_dma_free_pages);
