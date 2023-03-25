/*!
 *****************************************************************************
 *
 * @File       vxd_pvdec_priv.h
 * ---------------------------------------------------------------------------
 *
 * Copyright (c) Imagination Technologies Ltd.
 *
 * The contents of this file are subject to the MIT license as set out below.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 ("GPL")in which case the provisions of
 * GPL are applicable instead of those above.
 *
 * If you wish to allow use of your version of this file only under the terms
 * of GPL, and not to allow others to use your version of this file under the
 * terms of the MIT license, indicate your decision by deleting the provisions
 * above and replace them with the notice and other provisions required by GPL
 * as set out in the file called "GPLHEADER" included in this distribution. If
 * you do not delete the provisions above, a recipient may use your version of
 * this file under the terms of either the MIT license or GPL.
 *
 * This License is also included in this distribution in the file called
 * "MIT_COPYING".
 *
 *****************************************************************************/


#ifndef VXD_PVDEC_PRIV_H
#define VXD_PVDEC_PRIV_H

#include <linux/interrupt.h>
#include <uapi/vxd.h>

#include "vxd_pvdec_regs.h"

struct vxd_boot_poll_params {
	unsigned int msleep_cycles;
};

struct vxd_ena_params {
	struct vxd_boot_poll_params boot_poll;

	size_t fw_buf_size;
	u32 fw_buf_virt_addr; /* VXD's MMU virtual address of a firmware
			       * buffer. */
	u32 ptd; /* Shifted physical address of PTD */

	/* Required for firmware upload via registers. */
	struct {
		const u8 *buf; /* Firmware blob buffer */

	} regs_data;

	struct {
		unsigned use_dma:1; /* Use DMA or upload via registers. */
		unsigned secure:1;  /* Secure flow indicator. */
		unsigned wait_dbg_fifo:1; /* Indicates that fw shall use
			blocking mode when putting logs into debug fifo */
	};

	/* Structure containing memory staller configuration */
	struct {
		u32 *data;          /* Configuration data array */
		u8 size;            /* Configuration size in dwords */

	} mem_staller;

	uint32_t fwwdt_ms;      /* Firmware software watchdog timeout value */

	uint32_t crc; /* HW signatures to be enabled by firmware */
	uint32_t rendec_addr; /* VXD's virtual address of a rendec buffer */
	uint16_t rendec_size; /* Size of a rendec buffer in 4K pages */
};

/* HW state */
struct vxd_hw_state {
	u32 fw_counter;

	u32 fe_status[VXD_MAX_PIPES];
	u32 be_status[VXD_MAX_PIPES];
	u32 dmac_status[VXD_MAX_PIPES][2]; /* Cover DMA chan 2/3*/

	u32 irq_status;

};

struct vxd_hw_boot {
	unsigned int freq_khz;  /* Core clock frequency measured during
			the boot of the firmware */
	unsigned int timer_div;  /* The mtx timer divider value set
			during the boot procedure */
	uint64_t upload_us; /* Time spent to boot the firmware */

};

int vxd_pvdec_init(const struct device *dev, void __iomem *reg_base);

int vxd_pvdec_ena(const struct device *dev, void __iomem *reg_base,
		struct vxd_ena_params *ena_params, struct vxd_fw_hdr *hdr,
		struct vxd_hw_boot *boot);

int vxd_pvdec_stop(const struct device *dev, void __iomem *reg_base);

int vxd_pvdec_dis(const struct device *dev, void __iomem *reg_base);

int vxd_pvdec_mmu_flush(const struct device *dev, void __iomem *reg_base);

int vxd_pvdec_send_msg(const struct device *dev, void __iomem *reg_base,
		u32 *msg, size_t msg_size, uint16_t msg_id);

int vxd_pvdec_pend_msg_info(const struct device *dev, void __iomem *reg_base,
		size_t *size, uint16_t *msg_id, bool *not_last_msg);

int vxd_pvdec_recv_msg(const struct device *dev, void __iomem *reg_base,
		u32 *buf, size_t buf_size);

int vxd_pvdec_check_fw_status(const struct device *dev,
		void __iomem *reg_base);

size_t vxd_pvdec_peek_mtx_fifo(const struct device *dev,
		void __iomem *reg_base);

size_t vxd_pvdec_read_mtx_fifo(const struct device *dev, void __iomem *reg_base,
		u32 *buf, size_t size);

irqreturn_t vxd_pvdec_clear_int(void __iomem *reg_base, u32 *irq_status);

int vxd_pvdec_check_irq(const struct device *dev, void __iomem *reg_base,
		u32 irq_status);

int vxd_pvdec_msg_fit(const struct device *dev, void __iomem *reg_base,
		size_t msg_size);

void vxd_pvdec_get_state(const struct device *dev, void __iomem *reg_base,
		u32 num_pipes, struct vxd_hw_state *state);

int vxd_pvdec_get_props(const struct device *dev, void __iomem *reg_base,
		struct vxd_core_props *props);

size_t vxd_pvdec_get_dbg_fifo_size(void __iomem *reg_base);

int vxd_pvdec_dump_mtx_ram(const struct device *dev, void __iomem *reg_base,
		u32 addr, u32 count, u32 *buf);

int vxd_pvdec_dump_mtx_status(const struct device *dev, void __iomem *reg_base,
		u32 *array, u32 array_size);

#endif /* VXD_PVDEC_PRIV_H */
