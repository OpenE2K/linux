// SPDX-License-Identifier: GPL-2.0
/*
 *    Hantro driver main entrance.
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

#include <linux/io.h>
#include <linux/sched.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/shmem_fs.h>
#include <linux/module.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/pm_runtime.h>
#include <drm/drm_modeset_helper.h>
#ifdef __amd64__
#include <asm/set_memory.h>
#endif
/* Our header */
#include "hantro_priv.h"
#include "hx280enc.h"
#include "hantrodec.h"
#include "hantrocache.h"
#include "hantrodec400.h"
#include "hantro_axife.h"
#include "hantrommu.h"
#include <linux/of_reserved_mem.h>
#include <linux/of_irq.h>
#ifdef PCIE_EN
#include <linux/pci.h>
#endif

#include "hantro_vcmd.h"

#ifdef VSI_FPGA_MEM
#include "hantro_fpga_mem.h"
#endif

#ifdef PCIE_EN
#include "hantro_pcie.h"
#endif

struct hantro_device_handle hantro_dev;
static int useirq = 1;
int dbg_mmap;

module_param(useirq, int, 0444);
MODULE_PARM_DESC(useirq, "Use interrupts, default is 1 (enabled)");
module_param(dbg_mmap, int, 0644);

#if KERNEL_VERSION(4, 13, 0) > LINUX_VERSION_CODE
void debug_dma_alloc_coherent(struct device *dev, size_t size,
			      dma_addr_t dma_addr, void *virt)
{
}

void debug_dma_free_coherent(struct device *dev, size_t size, void *virt,
			     dma_addr_t addr)
{
}
#endif

#ifndef virt_to_bus
static inline unsigned long virt_to_bus(void *address)
{
	return (unsigned long)address;
}
#endif

struct drm_gem_object *
hantro_get_gem_from_dmabuf(struct dma_buf *dma_buf)
{
	struct drm_gem_hantro_object *cma_obj =
		(struct drm_gem_hantro_object
			 *)(((struct dmapriv *)dma_buf->priv)->self);

	if (cma_obj)
		return &cma_obj->base;

	return NULL;
}

int hantro_memalloc(struct hantro_mem_handle *phandle)
{
	struct slice_info *pslice = getslicenode(phandle->sliceidx);
	unsigned int config = pslice->config;

	if (!pslice)
		return -EINVAL;
	/*mmu part is not really finished yet since it needs op with MMU HW*/
	phandle->size = PAGE_ALIGN(phandle->size);
	if ((GET_ENC_CFG_BITS(config) & CONFIG_HANTROMMU) ||
		(GET_DEC_CFG_BITS(config) & CONFIG_HANTROMMU)) {
		phandle->vaddr = vmalloc(phandle->size);
		phandle->paddr = page_to_phys(vmalloc_to_page(phandle->vaddr));
		WARN(1, "FIXME E2K");
	} else {
		phandle->vaddr = dma_alloc_coherent(pslice->dev, phandle->size,
						    &phandle->paddr,
						    GFP_KERNEL);
	}
	if (!phandle->vaddr)
		return -ENOMEM;
	else
		return 0;
}

int hantro_memfree(struct hantro_mem_handle *phandle)
{
	struct slice_info *pslice = getslicenode(phandle->sliceidx);
	unsigned int config = pslice->config;

	if (!pslice)
		return -EINVAL;

	if ((GET_ENC_CFG_BITS(config) & CONFIG_HANTROMMU) ||
		(GET_DEC_CFG_BITS(config) & CONFIG_HANTROMMU))
		vfree(phandle->vaddr);
	else
		dma_free_coherent(pslice->dev, phandle->size, phandle->vaddr,
				  phandle->paddr);
	return 0;
}

#ifdef VSI_CONFIG_PM
static int set_platform_drvdata(struct platform_device *pdev)
{
	void *data;
#ifdef HAS_VCMD
	data = (void *)get_vcmd_slice_head();
#else
	data = (void *)getslicenode(0);
#endif
	hantro_dev.hantro_data = data;
	platform_set_drvdata(pdev, hantro_dev.hantro_data);

	return 0;
}
#endif

#ifdef USE_DTB_PROBE

int getnodetype(const char *name)
{
	if (strstr(name, NODENAME_DECODER) == name)
		return HANTRO_CORE_DEC;
	if (strstr(name, NODENAME_ENCODER) == name)
		return HANTRO_CORE_ENC;
	if (strstr(name, NODENAME_CACHE) == name)
		return HANTRO_CORE_CACHE;
	if (strstr(name, NODENAME_DEC400) == name)
		return HANTRO_CORE_DEC400;
	if (strstr(name, NODENAME_AXIFE) == name)
		return HANTRO_CORE_AXIFE;
	if (strstr(name, NODENAME_MMU) == name)
		return HANTRO_CORE_MMU;
	if (strstr(name, NODENAME_VCMD) == name)
		return HANTRO_CORE_VCMD;
	if (strstr(name, NODENAME_IM) == name)
		return HANTRO_CORE_IM;
	if (strstr(name, NODENAME_DECJPG) == name)
		return HANTRO_CORE_DECJPG;
	if (strstr(name, NODENAME_ENCJPG) == name)
		return HANTRO_CORE_ENCJPG;

	return HANTRO_CORE_UNKNOWN;
}

static dtbnode *trycreatenode(struct platform_device *pdev,
			      struct device_node *ofnode, int sliceidx,
			      int parenttype, phys_addr_t parentaddr)
{
	struct fwnode_handle *fwnode;
	struct resource r;
	int i, na, ns, ret;
	int endian = of_device_is_big_endian(ofnode);
	u32 reg_u32[4];
	u64 ioaddress, iosize;

	dtbnode *pnode = kzalloc(sizeof(dtbnode), GFP_KERNEL);

	if (!pnode)
		return NULL;

	pr_info("try create node %s", ofnode->name);
	pnode->type = getnodetype(ofnode->name);
	pnode->parentaddr = parentaddr;
	pnode->parenttype = parenttype;
	pnode->sliceidx = sliceidx;
	pnode->ofnode = ofnode;
	fwnode = &ofnode->fwnode;

	na = of_n_addr_cells(ofnode);
	ns = of_n_size_cells(ofnode);
	if (na > 2 || ns > 2) {
		pr_err("cell size too big");
		kfree(pnode);
		return NULL;
	}

	fwnode_property_read_u32_array(fwnode, "reg", reg_u32, na + ns);
	if (na == 2) {
		if (!endian) {
			ioaddress = reg_u32[0];
			ioaddress <<= 32;
			ioaddress |= reg_u32[1];
		} else {
			ioaddress = reg_u32[1];
			ioaddress <<= 32;
			ioaddress |= reg_u32[0];
		}
	} else {
		ioaddress = reg_u32[0];
	}
	if (ns == 2) {
		if (!endian) {
			iosize = reg_u32[na];
			iosize <<= 32;
			iosize |= reg_u32[na + 1];
		} else {
			iosize = reg_u32[na + 1];
			iosize <<= 32;
			iosize |= reg_u32[na];
		}
	} else {
		iosize = reg_u32[na];
	}
	pnode->ioaddr = ioaddress;
	pnode->iosize = iosize;
	pr_info("node regio =%llx:%llx", ioaddress, iosize);

	for (i = 0; i < 4; i++) {
		pnode->irq[i] = -1;
		if (of_irq_to_resource(ofnode, i, &r) > 0) {
			int irq = of_irq_get(ofnode, i);

			pr_info("irq %d:%s = %lld:%d", i, r.name, r.start, irq);
			if (irq > 0)
				pnode->irq[i] = irq;
		}
	}

	switch (pnode->type) {
	case HANTRO_CORE_DEC:
#ifdef HAS_VCD
		ret = hantrodec_probe(pnode, useirq, 0, NULL);
#endif
		break;
	case HANTRO_CORE_ENC:
#ifdef HAS_VCE
		ret = hantroenc_probe(pnode, useirq, 0, NULL);
#endif
		break;
	case HANTRO_CORE_CACHE:
#ifdef HAS_CACHECORE
		ret = cache_probe(pnode, useirq, 0, NULL);
#endif
		break;
	case HANTRO_CORE_DEC400:
#ifdef HAS_DEC400
		ret = hantro_dec400_probe(pnode, 0, NULL);
#endif
		break;
	case HANTRO_CORE_AXIFE:
#ifdef HAS_AXIFE
		ret = hantro_axife_probe(pnode, 0, NULL);
#endif
		break;
	case HANTRO_CORE_MMU:
#ifdef HAS_MMU
		ret = hantroMMUprobe(pnode, 0, NULL, pdev, 0, 0, NULL);
#endif
		break;
	case HANTRO_CORE_VCMD:
		ret = 0;
		//ret;	//add VCMD node data analyze here
		break;
	default:
		ret = -EINVAL;
		break;
	}
	if (ret < 0) {
		kfree(pnode);
		pnode = NULL;
	}
	return pnode;
}

static int hantro_analyze_subnode(struct platform_device *pdev,
				  struct device_node *slice, int sliceidx)
{
	dtbnode *head, *nhead, *newtail, *node;

	pr_info("dev node %s", slice->name);

	head = kzalloc(sizeof(dtbnode), GFP_KERNEL);
	if (!head)
		return -ENOMEM;
	head->type = HANTRO_CORE_SLICE;
	head->parenttype = HANTRO_CORE_SLICE;
	head->ofnode = slice;
	head->ioaddr = -1;
	head->iosize = 0;
	head->next = NULL;

	/*
	 *this is a wide first tree structure iteration,
	 *result is stored in slice info
	 */
	while (head) {
		newtail = NULL;
		nhead = newtail;
		while (head) {
			struct device_node *child, *ofnode = head->ofnode;

			for_each_child_of_node(ofnode, child) {
				node = trycreatenode(pdev, child, sliceidx,
						     head->type, head->ioaddr);
				if (node) {
					if (!nhead) {
						newtail = node;
						nhead = newtail;
					} else {
						newtail->next = node;
					}
					node->next = NULL;
					newtail = node;
				}
			}
			node = head->next;
			kfree(head);
			head = node;
		}
		head = nhead;
	}
	return 0;
}
#endif //USE_DTB_PROBE

static struct hantro_slice hantro_slice_head[MAX_SLICE_NUM] = { 0 };

int hantro_get_vcmdsup(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	struct hantro_slice *hantro_slice_node;
	hantro_ioctl_id ioctl_id_par;
	u32 slice;

	ioctl_id_par.data = *(unsigned int *)data;
	slice = ioctl_id_par.ID_PAR.node_idx;

	if (slice >= MAX_SLICE_NUM)
		return -1;

	hantro_slice_node = &hantro_slice_head[slice];
	return hantro_slice_node->vcmd_en;
}

#ifdef HAS_VCMD
static int hantro_set_vcmdsup(u32 sliceidx, u32 vcmd_en)
{
	struct hantro_slice *hantro_slice_node;

	if (sliceidx >= MAX_SLICE_NUM)
		return -1;

	hantro_slice_node = &hantro_slice_head[sliceidx];
	hantro_slice_node->vcmd_en = vcmd_en;
	return 1;
}
#endif

int hantro_get_irqinfo(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	return useirq;
}

int hantro_get_pmsup(struct drm_device *dev, void *data,
		       struct drm_file *file_priv)
{
	int pm_support = 0;

#ifdef VSI_CONFIG_PM
	pm_support = 1;
#else
	pm_support = 0;
#endif
	return pm_support;
}

#ifdef USE_DTB_PROBE
static int hantro_check_vcmd(struct platform_device *pdev,
			     struct device_node *slice)
{
	struct device_node *child_level_0, *child_level_1;
	int type;

	for_each_child_of_node(slice, child_level_0) {
		for_each_child_of_node(child_level_0, child_level_1) {
			type = getnodetype(child_level_0->name);
			if (type == HANTRO_CORE_VCMD)
				return 1;
		}
	}
	return 0;
}
#endif //USE_DTB_PROBE

#ifndef HAS_VCMD
static int map_register(struct vm_area_struct *vma, unsigned long busaddr, unsigned long size)
{
	size_t mapsize = (vma->vm_end - vma->vm_start);
	int ret;
#if KERNEL_VERSION(6, 3, 0) < LINUX_VERSION_CODE
	vm_flags_set(vma, VM_IO);
#else
	vma->vm_flags |= VM_IO;
#endif
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
	ret = remap_pfn_range(vma, vma->vm_start, busaddr >> PAGE_SHIFT, mapsize,
		vma->vm_page_prot) ? -EAGAIN : 0;

	hantro_mmaplog("%s:%lx:%ld=%d", __func__, busaddr, size, ret);
	return ret;
}
#endif

#ifdef HAS_VCMD
static int map_memblock(struct device *dev, struct vm_area_struct *vma, void *cpu_addr,
				unsigned long busaddr, unsigned long blocksize)
{
	size_t mapsize = vma->vm_end - vma->vm_start;
	int ret = 0;

	if (!(vma->vm_flags & VM_MAYSHARE))
		ret = -EPERM;
	else {
		ret = dma_mmap_wc(dev, vma, cpu_addr, busaddr, mapsize);
	}
	hantro_mmaplog("%s:%lx:%ld=%d", __func__, busaddr, blocksize, ret);
	return ret;
}
#endif


int hantro_map_internal_address(struct file *filp, struct vm_area_struct *vma)
{
	hantro_ioctl_id coreid;
	u32 maincoretype;

	coreid.data = (u32)vma->vm_pgoff;
	hantro_mmaplog("%s:nodeid=%d,maincore=%d:subtype=%d:coreidx=%d", __func__,
		coreid.ID_PAR.node_idx, coreid.ID_PAR.group_idx, coreid.ID_PAR.sub_mod_idx, coreid.ID_PAR.codec_idx);
	if (coreid.ID_PAR.group_idx == CODEC_DEC_FLGA)
		maincoretype = NODE_TYPE_DEC;
	else if (coreid.ID_PAR.group_idx == CODEC_ENC_FLGA)
		maincoretype = NODE_TYPE_ENC;
	else
		return -ENODEV;
	switch (coreid.ID_PAR.sub_mod_idx) {
#ifndef HAS_VCMD
	case CORE_FLAG:
		if (maincoretype == NODE_TYPE_DEC) {
			struct hantrodec_t *pdec = get_decnodes(coreid.ID_PAR.node_idx, coreid.ID_PAR.codec_idx);

			if (pdec)
				return map_register(vma, pdec->multicorebase_actual, pdec->iosize);
			else
				return -ENODEV;
		}
		if (maincoretype == NODE_TYPE_ENC) {
			struct hantroenc_t *penc = get_encnodes(coreid.ID_PAR.node_idx, coreid.ID_PAR.codec_idx);

			if (penc)
				return map_register(vma, penc->core_cfg.base_addr, penc->core_cfg.iosize);
			else
				return -ENODEV;
		}
		break;
	case DEC400_FLAG:
		{
			struct dec400_t *pdec400 = get_dec400nodebytype(coreid.ID_PAR.node_idx, maincoretype, coreid.ID_PAR.codec_idx);

			if (pdec400)
				return map_register(vma, pdec400->core_cfg.dec400corebase, pdec400->core_cfg.iosize);
			else
				return -ENODEV;
		}
	case CACHE_FLAG:
		{
			struct cache_dev_t *pcache = get_cachenodebytype(coreid.ID_PAR.node_idx, maincoretype, coreid.ID_PAR.codec_idx);

			if (pcache)
				return map_register(vma, pcache->core_cfg.base_addr, pcache->core_cfg.iosize);
			else
				return -ENODEV;
		}
	case MMU0_FLAG:
	case MMU1_FLAG:
		{
			struct mmu_t *pmmu = get_mmunodebytype(coreid.ID_PAR.node_idx, maincoretype);

			if (pmmu)
				return map_register(vma, pmmu->core_cfg.mmucorebase, pmmu->core_cfg.iosize);
			else
				return -ENODEV;
		}
#else
	case VCMD_FLAG:
	case VCMD_BUF_FLAG: {
		struct noncache_mem *m;
		vcmd_dev_str *sd = get_dev_by_sliceidx(coreid.ID_PAR.node_idx,
						coreid.ID_PAR.group_idx);
		if (sd == NULL)
			return -ENODEV;
		if (coreid.ID_PAR.sub_mod_idx == VCMD_FLAG)
			m = sd->vcmd_buf_mem_pool;
		else
			m = sd->vcmd_status_buf_mem_pool;
		vma->vm_pgoff = 0;
		return map_memblock(sd->dev, vma,
				m->virtualAddress,
				m->busAddress, m->size);
	}
#endif
	default:
		return -ENXIO;
	}
	return 0;
}

static int hantro_drm_probe(struct platform_device *pdev)
{
#ifdef USE_DTB_PROBE
	struct device *dev = &pdev->dev;
	int result = 0;
	int sliceidx = -1;

	if (dev->of_node) {
		if (hantro_check_vcmd(pdev, dev->of_node)) {
			sliceidx = hantro_vcmd_probe(pdev, useirq, dev->of_node, 0, 0, -1);
			hantro_set_vcmdsup(sliceidx, 1);
			hantro_dev.config |= get_vcmd_slice_config(sliceidx);
			transfer_vcmdslice_to_norslice(sliceidx);
			hantro_vcmd_init(sliceidx);

		} else {
			//probe from system DTB
			/*try to attach 1st rsv mem to dtb node*/
			result = of_reserved_mem_device_init(dev);
			pr_info("try reserve mem =%d", result);

			if (result == 0)
				sliceidx = addslice(dev, -1, 0);
			else
				/*leave to end of init,
				 *set to default drm platform dev
				 *and default cma area
				 */
				sliceidx = addslice(NULL, -1, 0);

#if USE_HW == 1
			/*go throug all sub dtb node' resources */
			if (sliceidx >= 0 && dev->of_node)
				hantro_analyze_subnode(pdev, dev->of_node,
						       sliceidx);
#endif
			hantro_set_vcmdsup(sliceidx, 0);
		}
	}
#endif//  USE_DTB_PROBE

	pr_info("dev %s probe", pdev->name);

	return 0;
}

#if KERNEL_VERSION(6, 12, 19) > LINUX_VERSION_CODE
static int hantro_drm_remove(struct platform_device *pdev)
{
	return 0;
}
#else
static void hantro_drm_remove(struct platform_device *pdev)
{

}
#endif

static const struct platform_device_id hantro_drm_platform_ids[] = {
	{
		.name = DRIVER_NAME,
	},
	{},
};
#if !defined(CONFIG_MCST)
MODULE_DEVICE_TABLE(platform, hantro_drm_platform_ids);
#endif

static const struct of_device_id hantro_of_match[] = {
	/*to match dtb, else reg io will fail*/
	{
		.compatible = "thunderbay,hantro",
	},
	{ /* sentinel */ }
};

static int hantro_pm_suspend(struct device *kdev)
{
#ifdef VSI_CONFIG_PM
#ifdef HAS_VCMD
	vcmd_slice_str *slice = dev_get_drvdata(kdev);

	while (slice) {
#ifdef HAS_VCD
		if (slice->dec_vcmd.subsys_num != 0)
			vcmd_pm_suspend(&slice->dec_vcmd);
#endif // HAS_VCD
#ifdef HAS_VCE
		if (slice->enc_vcmd.subsys_num != 0)
			vcmd_pm_suspend(&slice->enc_vcmd);
#endif // HAS_VCE
		slice = slice->slice_next;
	}
#else // HAS_VCMD
	struct slice_info *slice = dev_get_drvdata(kdev);

	while (slice) {
#ifdef HAS_VCD
		if (slice->deccore_num != 0)
			dec_pm_suspend(slice->dechdr);
#endif // HAS_VCD
#ifdef HAS_VCE
		if (slice->enccore_num != 0)
			enc_pm_suspend(slice->enchdr);
#endif // HAS_VCE
		slice = slice->slice_next;
	}
#endif // HAS_VCMD
	pr_info("hantro: pm suspend successful!\n");
#endif // VSI_CONFIG_PM
	return 0;
}

static int hantro_pm_resume(struct device *kdev)
{
#ifdef VSI_CONFIG_PM
#ifdef HAS_VCMD
	vcmd_slice_str *slice = dev_get_drvdata(kdev);

	while (slice) {
#ifdef HAS_VCD
		if (slice->dec_vcmd.subsys_num != 0)
			vcmd_pm_resume(&slice->dec_vcmd);
#endif // HAS_VCD
#ifdef HAS_VCE
		if (slice->enc_vcmd.subsys_num != 0)
			vcmd_pm_resume(&slice->enc_vcmd);
#endif // HAS_VCE
		slice = slice->slice_next;
	}
#else // HAS_VCMD
	struct slice_info *slice = dev_get_drvdata(kdev);

	while (slice) {
#ifdef HAS_VCD
		if (slice->deccore_num != 0)
			dec_pm_resume(slice->dechdr);
#endif // HAS_VCD
#ifdef HAS_VCE
		if (slice->enccore_num != 0)
			enc_pm_resume(slice->enchdr);
#endif // HAS_VCE
		slice = slice->slice_next;
	}
#endif // HAS_VCMD
	pr_info("hantro: pm reseume successful!\n");
#endif // VSI_CONFIG_PM
	return 0;
}

static int hantro_pm_runtime_suspend(struct device *kdev)
{
	/* Add CLk contrl*/
	//pr_info("hantro: runtime suspend successful!\n");

	hantro_pm_suspend(kdev);

	return 0;
}

static int hantro_pm_runtime_resume(struct device *kdev)
{
	/* Add CLk contrl*/
	//pr_info("hantro: runtime resume successful!\n");
	return 0;
}

#ifdef VSI_CONFIG_PM
static void hantro_pm_runtime_enable(struct device *kdev)
{
	pm_runtime_enable(kdev);
}


static void hantro_pm_runtime_disable(struct device *kdev)
{
	pm_runtime_disable(kdev);
}
#endif

void hantro_pm_runtime_get(struct device *kdev)
{
	pm_runtime_get_sync(kdev);
}

void hantro_pm_runtime_put(struct device *kdev)
{
	pm_runtime_put_sync(kdev);
}

static const struct dev_pm_ops hantro_pm_ops = {
	/* since we only support S3, only several interfaces should be supported
	 * echo -n "freeze" (or sth else) > /sys/power/state will trigger them
	 * current suspend and resume seem to be enough
	 * maybe suspend_noirq and resume_noirq will be inserted in future
	 */
	//.prepare
	.suspend = hantro_pm_suspend,
	//.suspend_late
	//.suspend_noirq

	//.resume_noirq
	//.resume_early
	.resume = hantro_pm_resume,
	//.complete
	.runtime_suspend = hantro_pm_runtime_suspend,
	.runtime_resume = hantro_pm_runtime_resume,
};

static struct platform_driver hantro_drm_platform_driver = {
	.probe = hantro_drm_probe,
	.remove = hantro_drm_remove,
	.driver = {
			.name = DRIVER_NAME,
			.owner = THIS_MODULE,
			.of_match_table = hantro_of_match,
			.pm = &hantro_pm_ops,
		},
	.id_table = hantro_drm_platform_ids,
};

static struct platform_device_info hantro_platform_info = {
	.name = DRIVER_NAME,
	.id = -1,
	.dma_mask = DMA_BIT_MASK(40),
};

static void release_norslice_node(void)
{
	struct slice_info *post, *prev;
	int i, slicen = get_slicenumber();
	struct hantroenc_t *pcore, *pnext;

	pr_debug("%s slicen %d\n", __func__, slicen);
	for (i = 0; i < slicen; i++) {
		pcore = get_encnodes(i, 0);
		while (pcore) {
			pnext = pcore->next;
			pr_debug("%s vfree\n", __func__);
			vfree(pcore);
			pcore = pnext;
		}
	}

	prev = getslicenode_ininit(0);
	post = prev;
	while (prev) {
		post = prev->next;
		pr_debug("%s kfree\n", __func__);
		kfree(prev);
		prev = post;
	}
}

#if KERNEL_VERSION(4, 10, 0) > LINUX_VERSION_CODE
static int hantro_major = 1; /* dynamic */
#endif

#ifdef CONFIG_MCST
static void hantro_remove(struct pci_dev *pdev)
#else
void __exit hantro_cleanup(void)
#endif
{
	int vcmd_en;
	hantro_ioctl_id ioctl_id_par;

	hantro_dev.config = 0;

	ioctl_id_par.ID_PAR.node_idx = 0;
	vcmd_en = hantro_get_vcmdsup(NULL, &ioctl_id_par.data, NULL);

	if (vcmd_en == 0) {
		hantro_unlinksysfsAPI(); //this must be before slice clean up

#ifdef HAS_VCD
		hantrodec_cleanup();
#endif

#ifdef HAS_VCE
		hantroenc_cleanup();
#endif

#ifdef HAS_CACHECORE
		cache_cleanup();
#endif
#ifdef HAS_DEC400
		hantro_dec400_cleanup();
#endif
#ifdef HAS_MMU
		hantroMMUCleanup();
#endif
#ifdef HAS_AXIFE
		hantro_axife_cleanup();
#endif
		/*this one must be after above ones to maintain list*/
		slice_remove();
	} else {
#ifdef HAS_MMU
		hantroMMUCleanup();
#endif

		release_norslice_node();
#ifdef HAS_VCMD
		hantro_vcmd_cleanup();
#endif
	}

#ifdef VSI_FPGA_MEM
	hantro_fpga_memrelease();
#endif

#ifdef PCIE_EN
	pcie_exit(hantro_dev.dev);
#endif

	releaseFenceData();
	drm_dev_unregister(hantro_dev.drm_dev);
#if !defined(CONFIG_MCST)
#if KERNEL_VERSION(5, 8, 0) > LINUX_VERSION_CODE
	drm_dev_fini(hantro_dev.drm_dev);
#else
	drm_dev_put(hantro_dev.drm_dev);
#endif
#endif
#ifdef VSI_CONFIG_PM
	hantro_pm_runtime_disable(&hantro_dev.platformdev->dev);
#endif
	platform_device_unregister(hantro_dev.platformdev);
	platform_driver_unregister(&hantro_drm_platform_driver);
}

static void __init __attribute((unused)) probe_hantroHW(unsigned long reg_base,
				  int pci_irq,
				  unsigned long ddr_base)
{
	int i, k, coren;
	int ret;

	for (i = 0; i < get_slicenumber(); i++) {
		struct slice_info *pslice = getslicenode_ininit(i);

#ifdef HAS_VCD
		coren = get_slicecorenum(i, HANTRO_CORE_DEC);
		for (k = 0; k < coren; k++) {
			struct hantrodec_t *decnode = get_decnodes(i, k);

			if (!decnode)
				break;
			decnode->multicorebase += reg_base;
			decnode->multicorebase_actual += reg_base;
#ifdef PCIE_EN
			if (pci_irq != -1)
				decnode->irqlist[0] = pci_irq;
#endif
			ret = hantrodec_probe(NULL, useirq, 1, decnode);
			if (ret < 0)
				remove_node(decnode, HANTRO_CORE_DEC);
		}
#endif

#ifdef HAS_VCE
		coren = get_slicecorenum(i, HANTRO_CORE_ENC);
		for (k = 0; k < coren; k++) {
			struct hantroenc_t *encnode = get_encnodes(i, k);

			if (!encnode)
				break;
			encnode->core_cfg.base_addr += reg_base;

			ret = hantroenc_probe(NULL, useirq, 1, encnode);
			if (ret < 0)
				remove_node(encnode, HANTRO_CORE_ENC);
		}
#endif

#ifdef HAS_CACHECORE
		coren = get_slicecorenum(i, HANTRO_CORE_CACHE);
		for (k = 0; k < coren; k++) {
			struct cache_dev_t *cache = get_cachenodes(i, k);

			if (!cache)
				break;
			cache->com_base_addr += reg_base;
			cache->core_cfg.base_addr += reg_base;

			ret = cache_probe(NULL, useirq, 1, cache);
			if (ret < 0)
				remove_node(cache, HANTRO_CORE_CACHE);
		}
#endif

#ifdef HAS_DEC400
		coren = get_slicecorenum(i, HANTRO_CORE_DEC400);
		for (k = 0; k < coren; k++) {
			struct dec400_t *dec400 = get_dec400nodes(i, k);

			if (!dec400)
				break;
			dec400->core_cfg.dec400corebase += reg_base;
			ret = hantro_dec400_probe(NULL, 1, dec400);
			if (ret < 0)
				remove_node(dec400, HANTRO_CORE_DEC400);
		}
#endif

#ifdef HAS_AXIFE
		coren = get_slicecorenum(i, HANTRO_CORE_AXIFE);
		for (k = 0; k < coren; k++) {
			struct axife_t *axife = get_axifenodes(i, k);

			if (!axife)
				break;
			axife->core_cfg.axifecorebase += reg_base;
			ret = hantro_axife_probe(NULL, 1, axife);
			if (ret < 0)
				remove_node(axife, HANTRO_CORE_AXIFE);
		}
#endif

#ifdef HAS_MMU
		coren = get_slicecorenum(i, HANTRO_CORE_MMU);
		for (k = 0; k < coren; k++) {
			struct mmu_t *mmu = get_mmunode(i, k);

			if (!mmu)
				break;
			mmu->core_cfg.mmucorebase += reg_base;
			ret = hantroMMUprobe(NULL, 1, mmu,
					     hantro_dev.platformdev, ddr_base, NULL);
			if (ret < 0)
				remove_node(mmu, HANTRO_CORE_MMU);
		}
#endif
		hantro_dev.config |= pslice->config;
	}
}

#ifdef CONFIG_MCST
static int hantro_probe(struct pci_dev *pdev, const struct pci_device_id *ent)
#else
int __init hantro_init(void)
#endif
{
	int result, i;
	struct hantro_base_addr subsystem_base_addr;
#ifdef PCIE_EN
	struct hantro_pci_t pci_par;
#endif
#ifdef HAS_VCMD
	int slice_num = 0;
#endif
	int pci_irq = -1;

	/*
	 *_init functions will init static vairables,
	 *while probe will init dynamic emelemts from DTB
	 */
	/*slice init must be in first to clear list*/
	slice_init();

#ifdef HAS_VCE
	hantroenc_init();
#endif

#ifdef HAS_VCD
	hantrodec_init();
#endif
#ifdef HAS_CACHECORE
	cache_init();
#endif
#ifdef HAS_DEC400
	hantrodec400_init();
#endif
#ifdef HAS_AXIFE
	hantroaxife_init();
#endif

	hantro_dev.config = 0;

#ifndef USE_DTB_PROBE //static table analyze, dec and enc must be in the front
#ifdef PCIE_EN //get reg/ddr base info
#if defined(CONFIG_MCST)
	if (pcie_init(&pci_par, pdev) < 0) {
		pr_err("%s,%d err pci init failed\n", __func__, __LINE__);
		return -ENODEV;
	}
#else
	if (pcie_init(&pci_par) < 0)
		pr_debug("%s,%d err pci init failed\n", __func__, __LINE__);
#endif
	subsystem_base_addr.reg_base = pci_par.pci_base_reg_hw;
#ifdef PCI_DDR_BAR
	subsystem_base_addr.ddr_base = pci_par.pci_base_ddr_hw;
#endif
	hantro_dev.dev = pci_par.dev;
	hantro_platform_info.parent = &pci_par.dev->dev;
#else
//customer set correctly values
	subsystem_base_addr.reg_base = 0;
	subsystem_base_addr.ddr_base = 0;
	pr_info("Maybe need customized region info in %s, line %d\n", __func__, __LINE__);
#endif
#ifdef PCIE_EN
	pci_irq = pci_par.irq;
#endif

	result = platform_driver_register(&hantro_drm_platform_driver);
	if (result < 0) {
		pr_err("hantro create platform driver fail\n");
		return result;
	}

	/*
	 *this is not a DTB node related platform device.
	 *Use it for drmdev's root node only
	 */

	hantro_dev.platformdev =
		platform_device_register_full(&hantro_platform_info);
	if (!hantro_dev.platformdev) {
		platform_driver_unregister(&hantro_drm_platform_driver);
		pr_err("hantro create platform device fail\n");
		return PTR_ERR(hantro_dev.platformdev);
	}

	/*it must be here instead of in probe*/
	hantro_dev.drm_dev =
		drm_dev_alloc(&hantro_drm_driver, &hantro_dev.platformdev->dev);
	if (IS_ERR(hantro_dev.drm_dev)) {
		DBG("init drm failed\n");
		platform_device_unregister(hantro_dev.platformdev);
		platform_driver_unregister(&hantro_drm_platform_driver);
		return PTR_ERR(hantro_dev.drm_dev);
	}

	hantro_dev.drm_dev->dev = &hantro_dev.platformdev->dev;
	drm_mode_config_init(hantro_dev.drm_dev);
	result = drm_dev_register(hantro_dev.drm_dev, 0);

	if (result < 0) {
		drm_dev_unregister(hantro_dev.drm_dev);
#if KERNEL_VERSION(5, 8, 0) > LINUX_VERSION_CODE
		drm_dev_fini(hantro_dev.drm_dev);
#else
		drm_dev_put(hantro_dev.drm_dev);
#endif
		platform_device_unregister(hantro_dev.platformdev);
		platform_driver_unregister(&hantro_drm_platform_driver);
		return result;
	}
	initFenceData();

#ifdef VSI_FPGA_MEM
	hantro_fpga_meminit((unsigned long)pci_par.pci_base_ddr_hw);
#else
	//customer init memmory region here if needed
	pr_info("Maybe need customized in %s, line %d\n", __func__, __LINE__);
#endif
#ifdef HAS_VCMD
	slice_num = hantro_vcmd_probe(hantro_dev.platformdev, useirq, NULL,
			subsystem_base_addr.ddr_base, subsystem_base_addr.reg_base, pci_irq);
	for (i = 0; i < slice_num; i++) {
		hantro_set_vcmdsup(i, 1);
		hantro_dev.config |= get_vcmd_slice_config(i);
	}

	result = hantro_vcmd_init(&subsystem_base_addr);
	if (result < 0) {
		pr_err("hantro_vcmd_init fail\n");
		return result;
	}
#else

#ifdef HAS_VCD
	result = hantrodec_probe(NULL, useirq, 0, NULL);
#endif
#ifdef HAS_VCE
	result = hantroenc_probe(NULL, useirq, 0, NULL);
#endif
#ifdef HAS_CACHECORE
	result = cache_probe(NULL, useirq, 0, NULL);
#endif
#ifdef HAS_DEC400
	result = hantro_dec400_probe(NULL, 0, NULL);
#endif
#ifdef HAS_AXIFE
	result = hantro_axife_probe(NULL, 0, NULL);
#endif
#ifdef HAS_MMU
	result =
		hantroMMUprobe(NULL, 0, NULL, hantro_dev.platformdev,
					   subsystem_base_addr.ddr_base, NULL);
#endif
#endif

#endif //USE_DTB_PROBE

#ifndef HAS_VCMD
	if (get_slicenumber() == 0)
		addslice(hantro_dev.drm_dev->dev, -1,
			 0); //for PC, no HW, create a default dev
	for (i = 0; i < get_slicenumber(); i++) {
		struct slice_info *pslice = getslicenode_ininit(i);

		if (!pslice->dev)
			pslice->dev = hantro_dev.drm_dev->dev;
		result = hantro_createsysfsAPI(i, pslice->dev);
		if (result != 0)
			pr_info("create sysfs %d fail", i);
	}
	slice_printdebug();

	probe_hantroHW(subsystem_base_addr.reg_base,
		       pci_irq,
		       subsystem_base_addr.ddr_base);
	slice_init_finish();
	slice_printdebug();
#endif
#ifdef VSI_CONFIG_PM
	set_platform_drvdata(hantro_dev.platformdev);
	hantro_pm_runtime_enable(&hantro_dev.platformdev->dev);
#endif // VSI_CONFIG_PM

	pr_info("hantro device created");
	return 0;
}

#if defined(CONFIG_MCST)
static struct pci_device_id hantro_pci_tbl[] = {
	{PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP,
	 PCI_DEVICE_ID_MCST_VC9000D)},
	{},
};

MODULE_DEVICE_TABLE(pci, hantro_pci_tbl);

static struct pci_driver hantro_pci_driver = {
	.name       = DRIVER_NAME,
	.id_table   = hantro_pci_tbl,
	.probe      = hantro_probe,
	.remove     = hantro_remove,
};

void __exit hantro_cleanup(void)
{
	pci_unregister_driver(&hantro_pci_driver);
}

int __init hantro_init(void)
{
	int status = pci_register_driver(&hantro_pci_driver);

	if (status != 0)
		pr_err(KBUILD_MODNAME ": Could not register driver\n");

	return status;
}
#endif

module_init(hantro_init);
module_exit(hantro_cleanup);

MODULE_IMPORT_NS(DMA_BUF);
/* module description */
MODULE_LICENSE("GPL v2");
MODULE_AUTHOR("Verisilicon");
MODULE_DESCRIPTION("Hantro DRM manager");
