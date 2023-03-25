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

#include "gc_hal_kernel_linux.h"
#include "gc_hal_kernel_platform.h"


#define VRAM_BAR       0
#define GC2500_BAR     3
#define GC8000_BAR     2


static struct platform_device *mcst_dev;

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

		if (nr_vecs > gcvCORE_COUNT)
			nr_vecs = gcvCORE_COUNT;	

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
    gcmkPRINT("galcore: build: " __DATE__ " " __TIME__ "\n");
#ifdef __HASH__
    gcmkPRINT("galcore: hash: " __HASH__ "\n");
#endif
#endif
    gcmkPRINT("galcore: ven 0x%x dev 0x%x\n",
              pciidlist[i].vendor, pciidlist[i].device);

    ret = pci_enable_device(pdev);
    if (ret < 0) {
        pr_err("galcore: pci_enable_device failed.\n");
    }

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

