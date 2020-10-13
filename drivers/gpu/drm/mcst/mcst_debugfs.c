/*
 * Copyright (C) 2009 Red Hat <bskeggs@redhat.com>
 * Copyright (c) 2012-2013 ZAO "MCST". All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining
 * a copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sublicense, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial
 * portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
 * EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF
 * MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT.
 * IN NO EVENT SHALL THE COPYRIGHT OWNER(S) AND/OR ITS SUPPLIERS BE
 * LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION
 * OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION
 * WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 */

/*
 * Authors:
 *  Ben Skeggs <bskeggs@redhat.com>
 *  Alexander Troosh <troosh@mcst.ru>
 */

#include <linux/debugfs.h>

#include "drmP.h"
#include "mcst_drv.h"

#include <ttm/ttm_page_alloc.h>
#include <linux/seq_file.h> /* for seq_printf */

static int
mcst_debugfs_channel_info(struct seq_file *m, void *data)
{
	struct drm_info_node *node = (struct drm_info_node *) m->private;
	struct mcst_channel *chan = node->info_ent->data;

	seq_printf(m, "channel id    : %d\n", chan->id);
#if 0
	seq_printf(m, "cpu fifo state:\n");
	seq_printf(m, "		 base: 0x%10llx\n", chan->pushbuf_base);
	seq_printf(m, "		  max: 0x%08x\n", chan->dma.max << 2);
	seq_printf(m, "		  cur: 0x%08x\n", chan->dma.cur << 2);
	seq_printf(m, "		  put: 0x%08x\n", chan->dma.put << 2);
	seq_printf(m, "		 free: 0x%08x\n", chan->dma.free << 2);
	if (chan->dma.ib_max) {
		seq_printf(m, "        ib max: 0x%08x\n", chan->dma.ib_max);
		seq_printf(m, "        ib put: 0x%08x\n", chan->dma.ib_put);
		seq_printf(m, "       ib free: 0x%08x\n", chan->dma.ib_free);
	}

	seq_printf(m, "gpu fifo state:\n");
	seq_printf(m, "		  get: 0x%08x\n",
					nvchan_rd32(chan, chan->user_get));
	seq_printf(m, "		  put: 0x%08x\n",
					nvchan_rd32(chan, chan->user_put));
	if (chan->dma.ib_max) {
		seq_printf(m, "        ib get: 0x%08x\n",
			   nvchan_rd32(chan, 0x88));
		seq_printf(m, "        ib put: 0x%08x\n",
			   nvchan_rd32(chan, 0x8c));
	}
#endif
	return 0;
}

int
mcst_debugfs_channel_init(struct mcst_channel *chan)
{
	struct mcst_private *dev_priv = chan->dev->dev_private;
	struct drm_minor *minor = chan->dev->primary;
	int ret;

	if (!dev_priv->debugfs.channel_root) {
		dev_priv->debugfs.channel_root =
			debugfs_create_dir("channel", minor->debugfs_root);
		if (!dev_priv->debugfs.channel_root)
			return -ENOENT;
	}

	snprintf(chan->debugfs.name, 32, "%d", chan->id);
	chan->debugfs.info.name = chan->debugfs.name;
	chan->debugfs.info.show = mcst_debugfs_channel_info;
	chan->debugfs.info.driver_features = 0;
	chan->debugfs.info.data = chan;

	ret = drm_debugfs_create_files(&chan->debugfs.info, 1,
				       dev_priv->debugfs.channel_root,
				       chan->dev->primary);
	if (ret == 0)
		chan->debugfs.active = true;
	return ret;
}

void
mcst_debugfs_channel_fini(struct mcst_channel *chan)
{
	struct mcst_private *dev_priv = chan->dev->dev_private;

	if (!chan->debugfs.active)
		return;

	drm_debugfs_remove_files(&chan->debugfs.info, 1, chan->dev->primary);
	chan->debugfs.active = false;

	if (chan == dev_priv->channel) {
		debugfs_remove(dev_priv->debugfs.channel_root);
		dev_priv->debugfs.channel_root = NULL;
	}
}

static int
mcst_debugfs_chipset_info(struct seq_file *m, void *data)
{
#if 0
	struct drm_info_node *node = (struct drm_info_node *) m->private;
	struct drm_minor *minor = node->minor;
	struct drm_device *dev = minor->dev;
	struct mcst_private *dev_priv = dev->dev_private;
	uint32_t ppci_0;

	ppci_0 = nv_rd32(dev, dev_priv->chipset >= 0x40 ? 0x88000 : 0x1800);

	seq_printf(m, "PMC_BOOT_0: 0x%08x\n", nv_rd32(dev, NV03_PMC_BOOT_0));
	seq_printf(m, "PCI ID	 : 0x%04x:0x%04x\n",
		   ppci_0 & 0xffff, ppci_0 >> 16);
#endif
	return 0;
}

static int
mcst_debugfs_memory_info(struct seq_file *m, void *data)
{
	struct drm_info_node *node = (struct drm_info_node *) m->private;
	struct drm_minor *minor = node->minor;
	struct mcst_private *dev_priv = minor->dev->dev_private;

	seq_printf(m, "VRAM total: %dKiB\n", (int)(dev_priv->vram_size >> 10));
	return 0;
}

static int
mcst_debugfs_vbios_image(struct seq_file *m, void *data)
{
#if 0
	struct drm_info_node *node = (struct drm_info_node *) m->private;
	struct mcst_private *dev_priv = node->minor->dev->dev_private;
	int i;

	for (i = 0; i < dev_priv->vbios.length; i++)
		seq_printf(m, "%c", dev_priv->vbios.data[i]);
#endif
	return 0;
}

static int
mcst_debugfs_evict_vram(struct seq_file *m, void *data)
{
	struct drm_info_node *node = (struct drm_info_node *) m->private;
	struct mcst_private *dev_priv = node->minor->dev->dev_private;
	int ret;

	ret = ttm_bo_evict_mm(&dev_priv->ttm.bdev, TTM_PL_VRAM);
	if (ret)
		seq_printf(m, "failed: %d", ret);
	else
		seq_printf(m, "succeeded\n");
	return 0;
}

static struct drm_info_list mcst_debugfs_list[] = {
	{ "evict_vram",        mcst_debugfs_evict_vram,    0, NULL },
	{ "chipset",	       mcst_debugfs_chipset_info,  0, NULL },
	{ "memory",	       mcst_debugfs_memory_info,   0, NULL },
	{ "vbios.rom",	       mcst_debugfs_vbios_image,   0, NULL },
	{ "ttm_page_pool",     ttm_page_alloc_debugfs,	   0, NULL },
	{ "ttm_dma_page_pool", ttm_dma_page_alloc_debugfs, 0, NULL },
};
#define mcst_DEBUGFS_ENTRIES ARRAY_SIZE(mcst_debugfs_list)

int
mcst_debugfs_init(struct drm_minor *minor)
{
	drm_debugfs_create_files(mcst_debugfs_list, mcst_DEBUGFS_ENTRIES,
				 minor->debugfs_root, minor);
	return 0;
}

void
mcst_debugfs_takedown(struct drm_minor *minor)
{
	drm_debugfs_remove_files(mcst_debugfs_list, mcst_DEBUGFS_ENTRIES,
				 minor);
}
