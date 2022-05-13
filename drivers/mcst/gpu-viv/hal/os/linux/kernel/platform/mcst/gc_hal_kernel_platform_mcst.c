/****************************************************************************
*
*    The MIT License (MIT)
*
*    Copyright (c) 2014 - 2020 Vivante Corporation
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
*    Copyright (C) 2014 - 2020 Vivante Corporation
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
       if (!mcst_dev || !mcst_dev->dev.parent)
          return gcvSTATUS_NOT_FOUND;

       pdev = to_pci_dev(mcst_dev->dev.parent);
       Args->irqs[gcvCORE_MAJOR] = pdev->irq;

       Args->registerBases[gcvCORE_MAJOR] = pci_resource_start(pdev, GC2500_BAR);
       Args->registerSizes[gcvCORE_MAJOR] = pci_resource_len(pdev, GC2500_BAR);
       Args->contiguousSize = (128 << 20); /* Do not forget set CONFIG_FORCE_MAX_ZONEORDER=16 ! */
       Args->bankSize = 65536;

       return gcvSTATUS_OK;
}

static struct _gcsPLATFORM_OPERATIONS mcst_ops =
{
    .adjustParam = _AdjustParam,
};

static struct _gcsPLATFORM mcst_platform =
{
    .name = __FILE__,
    .ops  = &mcst_ops,
    .flagBits = gcvPLATFORM_FLAG_LIMIT_4G_ADDRESS,
};

int gckPLATFORM_Init(struct platform_driver *pdrv,
            struct _gcsPLATFORM **platform)
{
    int ret;
    struct pci_dev *pdev = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
                             PCI_DEVICE_ID_MCST_MGA2, NULL);
    if (!pdev)
        return -ENODEV;

    mcst_dev = platform_device_alloc(pdrv->driver.name, -1);

    if (!mcst_dev) {
        printk(KERN_ERR "galcore: platform_device_alloc failed.\n");
        return -ENOMEM;
    }
    mcst_dev->dev.parent = &pdev->dev;
    /* Add device */
    ret = platform_device_add(mcst_dev);
    if (ret) {
        printk(KERN_ERR "galcore: platform_device_add failed.\n");
        goto put_dev;
    }

    set_dma_ops(&mcst_dev->dev, get_dma_ops(&pdev->dev));
    *platform = &mcst_platform;
    return 0;

put_dev:
    platform_device_put(mcst_dev);

    return ret;
}

int gckPLATFORM_Terminate(struct _gcsPLATFORM *platform)
{
    if (mcst_dev) {
        pci_dev_put(to_pci_dev(mcst_dev->dev.parent));
        platform_device_unregister(mcst_dev);
        mcst_dev = NULL;
    }

    return 0;
}

