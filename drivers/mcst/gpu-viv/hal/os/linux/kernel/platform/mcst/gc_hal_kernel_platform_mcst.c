/****************************************************************************
*
*    The MIT License (MIT)
*
*    Copyright (c) 2014 - 2021 Vivante Corporation
*
*    Permission is hereby granted, free of charge, to any person obtaining a
*    copy of this software and associated documentation files (the "Software"),
*    to deal in the Software without restriction, including without limitation
*    the rights to use, copy, modify, merge, publish, distribute, sublicense,
*    and/or sell copies of the Software, and to permit persons to whom the
*    Software is furnished to do so, subject to the following conditions:
*
*    The above copyright notice and this permission notice shall be included in
*    all copies or substantial portions of the Software.
*
*    THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
*    IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
*    FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
*    AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
*    LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
*    FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER
*    DEALINGS IN THE SOFTWARE.
*
*****************************************************************************
*
*    The GPL License (GPL)
*
*    Copyright (C) 2014 - 2021 Vivante Corporation
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
*    You should have received a copy of the GNU General Public License
*    along with this program; if not, write to the Free Software Foundation,
*    Inc., 51 Franklin Street, Fifth Floor, Boston, MA 02110-1301, USA.
*
*****************************************************************************
*
*    Note: This software is released under dual MIT and GPL licenses. A
*    recipient may use this file under the terms of either the MIT license or
*    GPL License. If you wish to use only one license not the other, you can
*    indicate your decision by deleting one of the above license notices in your
*    version of this file.
*
*****************************************************************************/


#include <linux/pci.h>
#include <linux/async.h>

#include "gc_hal_kernel_linux.h"
#include "gc_hal_kernel_platform.h"
#include "linux/dma-map-ops.h"


#define VRAM_BAR       0
#define GC2500_BAR     3
#define GC8000_BAR     2

#define S1_PROTO	(0x0001)

int dma_allocator_enable;

static struct platform_device *mcst_dev;
static int s1_proto;
static u64 vram_start;
static u64 vram_len;

/*******************************************************************************
**
**  adjustParam
**
**  Override content of arguments, if a argument is not changed here, it will
**  keep as default value or value set by insmod command line.
*/
static gceSTATUS
_AdjustParam (
    IN gcsPLATFORM * Platform,
    OUT gcsMODULE_PARAMETERS *Args
    )
{
    struct pci_dev *pdev;
    int bar, ret;
    int core = gcvCORE_MAJOR;

    if (!mcst_dev || !mcst_dev->dev.parent)
	return gcvSTATUS_NOT_FOUND;

    pdev = to_pci_dev(mcst_dev->dev.parent);

    switch (pdev->device) {
    case PCI_DEVICE_ID_MCST_MGA2:
        bar = GC2500_BAR;
    	Args->irqs[core] = pdev->irq;
    	Args->registerBases[core] = pci_resource_start(pdev, bar);
    	Args->registerSizes[core] = pci_resource_len(pdev, bar);
    	gcmkPRINT("%s: irqs[%d]: %d\n",
              __FUNCTION__, core, Args->irqs[core]);
    	gcmkPRINT("%s: registerBases[%d]: 0x%lx\n",
              __FUNCTION__, core, Args->registerBases[core]);
    	gcmkPRINT("%s: registerSizes[%d]: 0x%lx\n",
              __FUNCTION__, core, Args->registerSizes[core]);
        break;
    case PCI_DEVICE_ID_MCST_3D_VIVANTE_R2000P:
	{
		int i;
		u_long region_base;
		u_long region_length;
		int nr_vecs = pci_msix_vec_count(pdev);
		u16 subdevice;

		pci_read_config_word(pdev, PCI_SUBSYSTEM_ID, &subdevice);
		if (subdevice == S1_PROTO)
			s1_proto = 1;

		if (s1_proto)
			nr_vecs = 1;
		else
			nr_vecs = pci_msix_vec_count(pdev);

		if (nr_vecs > gcvCORE_COUNT)
			nr_vecs = gcvCORE_COUNT;	

		/* r2000+ is a video card(prototype) */
		if (pdev->subsystem_device == 4)
			nr_vecs = 1;

		ret = pci_alloc_irq_vectors(pdev,
			       	nr_vecs, nr_vecs, PCI_IRQ_MSIX);
		if (ret < 0) {
			gcmkPRINT("%s: msix vectors %d alloc failed.\n",
					__FUNCTION__, nr_vecs);
			return gcvSTATUS_OUT_OF_RESOURCES;
		}
		gcmkPRINT("%s: msix vectors: %d\n",
				__FUNCTION__, nr_vecs);

		Platform->flagBits |= gcvPLATFORM_FLAG_MSIX_ENABLED;

		bar = GC8000_BAR;
		region_base = pci_resource_start(pdev, bar);
		region_length = pci_resource_len(pdev, bar);
		gcmkPRINT("%s: bar base: 0x%lx\n",
				__FUNCTION__, region_base);
		gcmkPRINT("%s: bar length: 0x%lx\n",
				__FUNCTION__, region_length);

		region_length /= nr_vecs;
		for (i = 0; i < nr_vecs; i++) {
			int vec = pci_irq_vector(pdev, i);

			Args->irqs[core] = vec;
			Args->registerBases[core] = region_base;
			Args->registerSizes[core] = region_length;
			gcmkPRINT("%s: irqs[%d]: %d\n",
					__FUNCTION__, core, vec);
			gcmkPRINT("%s: registerBases[%d]: 0x%lx\n",
					__FUNCTION__, core, Args->registerBases[core]);
			gcmkPRINT("%s: registerSizes[%d]: 0x%lx\n",
					__FUNCTION__, core, Args->registerSizes[core]);
			core++;
			region_base += region_length;
		}
		/* if r2000+ is a video card */
		if ((pdev->subsystem_device == 3) ||
			(pdev->subsystem_device == 4)) {
			dma_allocator_enable = 1;
			Platform->flagBits |= gcvPLATFORM_FLAG_LIMIT_4G_ADDRESS;

			if (vram_start && vram_len) {
				Args->externalBase[0] = vram_start;
				Args->externalSize[0] = vram_len;
				gcmkPRINT("%s: externalBase[0]: 0x%08lx\n",
					__FUNCTION__, vram_start);
				gcmkPRINT("%s: externalSize[0]: 0x%08lx\n",
					__FUNCTION__, vram_len);
			}
		}
#if defined(CONFIG_E90S)
		if (pdev->revision == 0 && Args->maxOutstandingReads == 0)
			pr_warn("galcore: maxOutstandingReads = 0!\n");
#endif
	}
	break;
    default:
	return gcvSTATUS_INVALID_ARGUMENT;
    }

    /* Do not forget set CONFIG_FORCE_MAX_ZONEORDER=16 ! */
    Args->contiguousSize = (128 << 20);
    Args->bankSize = 65536;

    return gcvSTATUS_OK;
}

#define vcfg_offset 0x40

static gceSTATUS _GetPower(IN gcsPLATFORM * Platform)
{
	if (mcst_dev && mcst_dev->dev.parent) {
		u32 pdata;
		struct pci_dev *pdev = to_pci_dev(mcst_dev->dev.parent);

		if (pdev->device != PCI_DEVICE_ID_MCST_3D_VIVANTE_R2000P)
			return gcvSTATUS_OK;

		if (s1_proto)
			return gcvSTATUS_OK;

		/* r2000+ is a video card(prototype) */
		if (pdev->subsystem_device == 4)
			return gcvSTATUS_OK;

		/* Signal to PMC to turn power ON */
		pci_read_config_dword(pdev, vcfg_offset, &pdata);
		pdata = pdata & ~0x00000008;
		pci_write_config_dword(pdev, vcfg_offset, pdata);
		Platform->flagBits |= gcvPLATFORM_FLAG_PMC_POWER_ON;
#ifdef DEBUG
		gcmkPRINT("%s: signal to PMC to turn power ON.\n",
			__func__);
#endif
	}
	return gcvSTATUS_OK;
}

static gceSTATUS _PutPower(IN gcsPLATFORM * Platform)
{
	if (mcst_dev) {
		struct pci_dev *pdev = to_pci_dev(mcst_dev->dev.parent);

		if (pdev->device != PCI_DEVICE_ID_MCST_3D_VIVANTE_R2000P)
			return gcvSTATUS_OK;

		if (s1_proto)
			return gcvSTATUS_OK;

		/* r2000+ is a video card(prototype) */
		if (pdev->subsystem_device == 4)
			return gcvSTATUS_OK;

		if (Platform->flagBits & gcvPLATFORM_FLAG_PMC_POWER_ON) {
			u32 pdata;

			Platform->flagBits &= ~gcvPLATFORM_FLAG_PMC_POWER_ON;
			/* Signal to PMC to turn power OFF */
			pci_read_config_dword(pdev, vcfg_offset, &pdata);
			pdata = pdata | 0x00000008;
			pci_write_config_dword(pdev, vcfg_offset, pdata);
#ifdef DEBUG
			gcmkPRINT("%s: signal to PMC to turn power OFF.\n",
				__func__);
#endif
		}
	}
	return gcvSTATUS_OK;
}

static struct _gcsPLATFORM_OPERATIONS mcst_ops =
{
    .adjustParam = _AdjustParam,
	.getPower = _GetPower,
	.putPower = _PutPower,
};

static struct _gcsPLATFORM mcst_platform =
{
    .name = __FILE__,
    .ops  = &mcst_ops,
#if defined(CONFIG_E90S)
    .flagBits = 0,
#else
    .flagBits = gcvPLATFORM_FLAG_LIMIT_4G_ADDRESS,
#endif
};

static const struct pci_device_id pciidlist[] = {
	{ PCI_VDEVICE(MCST_TMP, PCI_DEVICE_ID_MCST_MGA2) }, /* e1c+ */
	{ PCI_VDEVICE(MCST_TMP, PCI_DEVICE_ID_MCST_3D_VIVANTE_R2000P) }
};

#define GPU_APERTURE_BASE 	(0x50)
#define GPU_APERTURE_LIMIT	(0x58)
#define GPU_APERTURE_REMAP	(0x60)

#ifdef CONFIG_E90S
static void external_memory_config(struct pci_dev *pdev)
{
	u32 pdatal, pdatah;
	u64 base, len;
	u_long region_base, region_length;
	struct pci_dev *pdev_mga2;

	pdev_mga2 = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
				PCI_DEVICE_ID_MCST_MGA26, NULL);

	if (!pdev_mga2) {
		pr_err("galcore: No mga2 pci device found.\n");
		return;
	}

	region_base = pci_resource_start(pdev_mga2, 4);
	region_length = pci_resource_len(pdev_mga2, 4);
#ifdef DEBUG
	gcmkPRINT("%s: mga2 pci bar 4 base: 0x%lx\n",
			__FUNCTION__, region_base);
	gcmkPRINT("%s: mga2 pci bar 4 length: 0x%lx\n",
			__FUNCTION__, region_length);
#endif
	pci_dev_put(pdev_mga2);

	if (!region_base || !region_length) {
		pr_err("galcore: No mga2 pci resources: base=0x%lx, len=0x%lx\n",
			region_base, region_length);
		return;
	}

	/* The second quarter of the region (bug 149246) is available for the gpu usage. */
	len = region_length / 4;
	vram_start = region_base + len;
	vram_len = len;
	
	/* 1. 
	 * GPU.APERTURE_BASE.ApertureBase=(the address of the beginning of
	 * the VRAM BAR area) [63:13]
	 * GPU.APERTURE_BASE.ApertureEnable=1 [0]
	 */
	base = region_base;
	pdatal = (u32)(base & 0xFFFFE000) | 0x00000001;
	pdatah = (u32)(base >> 32);
	pci_write_config_dword(pdev, GPU_APERTURE_BASE, pdatal);
	pci_write_config_dword(pdev, GPU_APERTURE_BASE + 4, pdatah);
#ifdef DEBUG
	pci_read_config_dword(pdev, GPU_APERTURE_BASE, &pdatal);
	pci_read_config_dword(pdev, GPU_APERTURE_BASE + 4, &pdatah);
	gcmkPRINT("%s: GPU APERTURE BASE: 0x%08lx_%08lx\n",
				__FUNCTION__, pdatah, pdatal);
#endif
	/* 2. 
	 * GPU.APERTURE_LIMIT.ApertureLimit=(the address of the end of
	 * the VRAM BAR area) [63:13]
	 */
	base = region_base - 1 + region_length;
	pdatal = (u32)(base & 0xFFFFE000);
	pdatah = (u32)(base >> 32);
	pci_write_config_dword(pdev, GPU_APERTURE_LIMIT, pdatal);
	pci_write_config_dword(pdev, GPU_APERTURE_LIMIT + 4, pdatah);
#ifdef DEBUG
	pci_read_config_dword(pdev, GPU_APERTURE_LIMIT, &pdatal);
	pci_read_config_dword(pdev, GPU_APERTURE_LIMIT + 4, &pdatah);
	gcmkPRINT("%s: GPU APERTURE LIMIT: 0x%08lx_%08lx\n",
				__FUNCTION__, pdatah, pdatal);
#endif
	/* 3. 
	 * GPU.APERTURE_REMAP.ApertureRemapBase=0x0 [63:13]
	 * GPU.APERTURE_REMAP.ApertureRemapEnable=1 [0]
	 */
	pdatal = 0x00000001;
	pdatah = 0x0;
	pci_write_config_dword(pdev, GPU_APERTURE_REMAP, pdatal);
	pci_write_config_dword(pdev, GPU_APERTURE_REMAP + 4, pdatah);
#ifdef DEBUG
	pci_read_config_dword(pdev, GPU_APERTURE_REMAP, &pdatal);
	pci_read_config_dword(pdev, GPU_APERTURE_REMAP + 4, &pdatah);
	gcmkPRINT("%s: GPU APERTURE REMAP: 0x%08lx_%08lx\n",
				__FUNCTION__, pdatah, pdatal);
#endif

	return;
}
#endif

static void r2000p_load_3d(void *data, async_cookie_t cookie)
{
	request_module_nowait("vivante");
}

int gckPLATFORM_Init(struct platform_driver *pdrv,
            struct _gcsPLATFORM **platform)
{
    int ret, i;
    struct pci_dev *pdev = NULL;
    
    for (i = 0; i < ARRAY_SIZE(pciidlist); i++) {
        pdev = pci_get_device(pciidlist[i].vendor, pciidlist[i].device, NULL);
        if (pdev != NULL)
            break;
    }

    if (!pdev)
        return -ENODEV;

#ifdef DEBUG
#ifdef __HASH__
    gcmkPRINT("galcore: hash: " __HASH__ "\n");
#endif
#endif
    gcmkPRINT("galcore: ven 0x%x dev 0x%x\n",
              pciidlist[i].vendor, pciidlist[i].device);

    if (pdev->dev.bus->dma_configure) {
        struct pci_driver driver = { };
        if (!pdev->dev.driver) /*HACK: dma_configure() uses the pointer*/
            pdev->dev.driver = &driver.driver;

        /* Bind iommu. Normally it is done just before pci-probe call,
           but galcore is not pci driver */
        ret = pdev->dev.bus->dma_configure(&pdev->dev);
        if (pdev->dev.driver == &driver.driver)
            pdev->dev.driver = NULL;
        if (ret)
            return ret;
    }
    /* Bind irq. Normally it is done just before pci-probe call,
       but galcore is not pci driver */
    ret = pcibios_alloc_irq(pdev);
    if (ret < 0) {
        pr_err("galcore: pcibios_alloc_irq failed.\n");
	return ret;
    }

    ret = pci_enable_device(pdev);
    if (ret < 0) {
        pr_err("galcore: pci_enable_device failed.\n");
    }

#if defined(CONFIG_E90S)
	/* if r2000+ is a video card */
	if ((pdev->subsystem_device == 3) ||
		(pdev->subsystem_device == 4)) {
		/* 
	 	 * It has to be done before turning the Bus Master on.
		 */
		external_memory_config(pdev);
	}
#endif

    pci_set_master(pdev);

    mcst_dev = platform_device_alloc(pdrv->driver.name, -1);
    if (!mcst_dev) {
        pr_err("galcore: platform_device_alloc failed.\n");
        return -ENOMEM;
    }

    mcst_dev->dev.parent = &pdev->dev;

    /* Add device */
    ret = platform_device_add(mcst_dev);
    if (ret) {
        pr_err("galcore: platform_device_add failed.\n");
        goto put_dev;
    }

    set_dma_ops(&mcst_dev->dev, get_dma_ops(&pdev->dev));
    mcst_platform.device = mcst_dev;
    *platform = &mcst_platform;

	if (pdev->vendor == PCI_VENDOR_ID_MCST_TMP &&
			pdev->device == PCI_DEVICE_ID_MCST_3D_VIVANTE_R2000P) {
		/* vivante driver has no pci-device, so load drivers here. */
		/* Do it on another thread to avoid deadlock. */
		async_schedule(r2000p_load_3d, NULL);
	}
    return 0;

put_dev:
    pci_disable_device(pdev);
    platform_device_put(mcst_dev);

    return ret;
}

int gckPLATFORM_Terminate(struct _gcsPLATFORM *platform)
{
    if (mcst_dev) {
        struct pci_dev *pdev = to_pci_dev(mcst_dev->dev.parent);
        pci_clear_master(pdev);
	if (platform->flagBits & gcvPLATFORM_FLAG_MSIX_ENABLED) {
		/* r2000+ */
		pci_free_irq_vectors(pdev);
	}
    	pci_disable_device(pdev);
        pci_dev_put(pdev);
        platform_device_unregister(mcst_dev);
        mcst_dev = NULL;
    }

    return 0;
}

