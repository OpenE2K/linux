/*
 * Copyright (c) 2015, Verisilicon Inc. - All Rights Reserved
 *
 * This software is dual licensed, either GPL-2.0 or BSD-3-Clause, at your
 * option.
 *
 ********************************************************************************
 *
 * GPL-2.0
 *
 ********************************************************************************
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 ********************************************************************************
 *
 * Alternatively, This software may be distributed under the terms of
 * BSD-3-Clause, in which case the following provisions apply instead of the ones
 * mentioned above :
 *
 ********************************************************************************
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */
#include <linux/version.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include <linux/module.h>
#include <linux/init.h>
#include <linux/kernel.h>
#include <linux/debugfs.h>
#include <linux/types.h>
#include <linux/device.h>
#include <linux/pagemap.h>
#include <linux/sched.h>
#if (KERNEL_VERSION(5, 10, 0) > LINUX_VERSION_CODE)
#include <linux/dma-contiguous.h>
#else
#include <linux/dma-map-ops.h>
#endif
#include <linux/platform_device.h>
#include <linux/dma-buf.h>
#include <linux/stddef.h>
#include <linux/delay.h>

#include "hantroaxife.h"

void AXIFEEnable(volatile unsigned char *hwregs)
{
#ifndef HANTROVCMD_ENABLE_IP_SUPPORT
	if (!hwregs)
		return;

	//AXI FE non-secure mode
	iowrite32(0x0, (void __iomem *)(hwregs + HANTRO_AXIFE_OFFSET + 0x2C));
	pr_info("AXI FE: 0x2C = 0x%x\n",
		ioread32((void __iomem *)(hwregs + 0x2C)));
	iowrite32(0x2, (void __iomem *)(hwregs + HANTRO_AXIFE_OFFSET + 0x28));
	pr_info("AXI FE: 0x28 = 0x%x\n",
		ioread32((void __iomem *)(hwregs + 0x28)));
#endif
}

int AXIFEFlush(volatile unsigned char *hwregs)
{
#ifndef HANTROVCMD_ENABLE_IP_SUPPORT
	int loop_cnt = 0;

	if (!hwregs)
		return 0;

	/* trigger AXI FE flush, AXI FE will automatically read or empty data in its
	 * Master side until the Master status is IDLE.
	 */
	iowrite32(0x01, (void __iomem *)(hwregs + HANTRO_AXIFE_OFFSET + 0x8C));
	pr_info("AXI FE Flush Enable: 0x8C = 0x%x\n",
		ioread32((void __iomem *)(hwregs + 0x8C)));

	//polling read flush status(swreg[0]). If it is set to 1, means flush is completed.
	while (!(ioread32(((void __iomem *)(hwregs + AXI_REG0_SW_HWCFG)))) >> 31) {
		loop_cnt++;
		mdelay(10); // wait 10ms
		if (loop_cnt > 20) { // too long
			pr_err("AXI FE: too long before axife flushed successfully\n");
			return -1;
		}
	}
#endif
	return 0;
}
