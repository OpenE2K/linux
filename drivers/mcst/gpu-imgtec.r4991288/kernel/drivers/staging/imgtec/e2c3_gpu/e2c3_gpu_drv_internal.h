/* vi: set ts=8 sw=8 sts=8: */
/*************************************************************************/ /*!
@Codingstyle    LinuxKernel
@Copyright      Copyright (c) Imagination Technologies Ltd. All Rights Reserved
@Copyright      Copyright (c) MCST
@License        Dual MIT/GPLv2

The contents of this file are subject to the MIT license as set out below.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

Alternatively, the contents of this file may be used under the terms of
the GNU General Public License Version 2 ("GPL") in which case the provisions
of GPL are applicable instead of those above.

If you wish to allow use of your version of this file only under the terms of
GPL, and not to allow others to use your version of this file under the terms
of the MIT license, indicate your decision by deleting the provisions above
and replace them with the notice and other provisions required by GPL as set
out in the file called "GPL-COPYING" included in this distribution. If you do
not delete the provisions above, a recipient may use your version of this file
under the terms of either the MIT license or GPL.

This License is also included in this distribution in the file called
"MIT-COPYING".

EXCEPT AS OTHERWISE STATED IN A NEGOTIATED AGREEMENT: (A) THE SOFTWARE IS
PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT; AND (B) IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/ /**************************************************************************/

#ifndef _E2C3_DRV_INTERNAL_H
#define _E2C3_DRV_INTERNAL_H

#include "e2c3_gpu_drv.h"

#include <linux/version.h>

#if defined(E2C3_GPU_FAKE_INTERRUPTS)
#define E2C3_GPU_FAKE_INTERRUPT_TIME_MS 1600
#include <linux/timer.h>
#include <linux/time.h>
#endif

#define DRV_NAME "e2c3-gpu"

/* Convert a byte offset to a 32 bit dword offset */
#define DWORD_OFFSET(byte_offset) ((byte_offset) >> 2)

#define HEX2DEC(v) ((((v) >> 4) * 10) + ((v)&0x0F))

struct e2c3_gpu_interrupt_handler {
	bool enabled;
	void (*handler_function)(void *);
	void *handler_data;
};

struct e2c3_gpu_region {
	resource_size_t base;
	resource_size_t size;
};

struct e2c3_gpu_io_region {
	struct e2c3_gpu_region region;
	void __iomem *registers;
};

struct e2c3_gpu_device {
	struct pci_dev *pdev;

	spinlock_t interrupt_handler_lock;
	spinlock_t interrupt_enable_lock;

	struct e2c3_gpu_interrupt_handler interrupt_handler;

	struct platform_device *ext_dev;

#if defined(E2C3_GPU_FAKE_INTERRUPTS)
	struct timer_list timer;
#endif
};

int request_pci_io_addr(struct pci_dev *pdev, u32 index, resource_size_t offset,
			resource_size_t length);
void release_pci_io_addr(struct pci_dev *pdev, u32 index, resource_size_t start,
			 resource_size_t length);

int setup_io_region(struct pci_dev *pdev, struct e2c3_gpu_io_region *region,
		    u32 index, resource_size_t offset, resource_size_t size);

#if defined(E2C3_GPU_FAKE_INTERRUPTS)
void e2c3_gpu_irq_fake_wrapper(unsigned long data);
#endif /* defined(E2C3_GPU_FAKE_INTERRUPTS) */

#endif /* _E2C3_DRV_INTERNAL_H */
