/*
 * SPDX_license-Identifier: GPL-2.0  OR BSD-3-Clause
 * Copyright (c) 2015, Verisilicon Inc. - All Rights Reserved
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

#include <linux/ioctl.h>
#include <linux/types.h>
#include <asm/io.h>
#include "hantroabnormalirq.h"
#ifdef AXI2TO1_SUPPORT
#include "hantroaxi2to1.h"

extern void _vcmd_kthread_wakeup(vcmd_mgr_t *vcmd_mgr);
#endif

/**
 * process vcd pp line-counter irq
 */
static void process_vcd_line_cnt_irq(volatile void *hwregs, u32 irq)
{
	irq &= IRQ_BIT_MASK(VCD_STATUS_LINE_CNT_INT);
	iowrite32(irq, (void __iomem *)(hwregs + 4 * 1));

	vcmd_klog(LOGLVL_BRIEF, "VCD has a line-counter interrupt.\n");
}

/**
 * process vcd bus-err abnormal irq
 */
static void process_vcd_bus_err_irq(volatile void *hwregs, u32 irq)
{
	irq &= IRQ_BIT_MASK(VCD_STATUS_BUS_ERR_INT);
	iowrite32(irq, (void __iomem *)(hwregs + 4*1));

	vcmd_klog(LOGLVL_WARNING, "VCD has a bus err interrupt.\n");
}

extern void proc_add_done_job(vcmd_mgr_t *vcmd_mgr, struct cmdbuf_obj *obj);
#ifdef SUPPORT_WATCHDOG
extern void _vcmd_watchdog_stop(struct hantrovcmd_dev *dev);
#endif

/**
 * process vcd multi-slice abnormal irq
 */
static void process_vcd_slice_irq(vcmd_mgr_t *vcmd_mgr,
									struct hantrovcmd_dev *dev,
									struct cmdbuf_obj *obj, u32 irq)
{
	struct vcmd_subsys_info *subsys = dev->subsys_info;
	u32 *status_va;

	if (obj->slice_run_done == 0) {
		status_va = obj->status_va +
					subsys->reg_off[SUB_MOD_MAIN] / 2 / 4 + 1;

		*status_va = irq & (~0x100);	// clean sw_dec_irq (bit 8 of reg1)

		//Gate abnormal interrupt from VCD, to avoid repeatly BUF_EMPTY to CPU.
		vcmd_write_reg((const void *)dev->hwregs,
						VCMD_REGISTER_EXT_INT_GATE_OFFSET,
						dev->intr_gate_mask | dev->abn_irq_mask);

		obj->slice_run_done = 1;
		proc_add_done_job(vcmd_mgr, obj);
#ifdef SUPPORT_WATCHDOG
		_vcmd_watchdog_stop(dev);
#endif
	}
}

/**
 * process vcd abnormal irq
 */
void process_vcd_abn_irq(vcmd_mgr_t *vcmd_mgr,
						struct hantrovcmd_dev *dev, struct cmdbuf_obj *obj)
{
	struct vcmd_subsys_info *subsys = dev->subsys_info;

	volatile void *hwregs;
	unsigned long flags;
	u32 irq;

	hwregs = subsys->hwregs[SUB_MOD_MAIN];

	// read VCD int_status
	spin_lock_irqsave(&dev->abn_irq_lock, flags);
	irq = (u32)ioread32((void __iomem *)(hwregs + 0x04));

	if (irq & VCD_STATUS_LINE_CNT_INT) {
		/* pp line counter irq */
		process_vcd_line_cnt_irq(hwregs, irq);
	}

	if (irq & VCD_STATUS_BUS_ERR_INT) {
		/* bus-error irq */
		process_vcd_bus_err_irq(hwregs, irq);
	}

	if (irq & VCD_STATUS_SLICE_READY_INT) {
		/* slice rdy irq */
		process_vcd_slice_irq(vcmd_mgr, dev, obj, irq);
	}
	spin_unlock_irqrestore(&dev->abn_irq_lock, flags);

}

#ifdef AXI2TO1_SUPPORT
/**
 * @brief process axi2to1 abnormal irq
 */
void process_axi2to1_abn_irq(vcmd_mgr_t *vcmd_mgr, struct hantrovcmd_dev *dev)
{
	struct vcmd_subsys_info *subsys = dev->subsys_info;

	volatile void *hwregs;
	unsigned long flags;
	u32 irq;

	hwregs = subsys->hwregs[SUB_MOD_AXI2TO1];

	irq = (u32)ioread32((void __iomem *)(hwregs + AXI2TO1_REG5_SW_IRQ)); //axi2to irq status
	/* bit0: flush done and bit1: flush timeout will be triggerd by flush operation */
	if (irq & 0xFFFFFFFC) {
		spin_lock_irqsave(&dev->abn_irq_lock, flags);
		/* clear axi2to1 irq */
		iowrite32(irq, (void __iomem *)(hwregs + AXI2TO1_REG5_SW_IRQ));
		dev->kthread_actions |= KT_ACT_AXI2TO1_EXCEPTION;
		spin_unlock_irqrestore(&dev->abn_irq_lock, flags);
		_vcmd_kthread_wakeup(vcmd_mgr);
	}
}
#endif
