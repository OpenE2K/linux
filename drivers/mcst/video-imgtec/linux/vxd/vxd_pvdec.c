/*!
 *****************************************************************************
 *
 * @File       vxd_pvdec.c
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


#include <linux/io.h>
#include <linux/delay.h>
#include <linux/device.h>
#include <linux/time.h>
#ifdef CONFIG_MCST
#include <linux/pci.h>
#endif

#include <uapi/vxd.h>
#include <uapi/vxd_pvdec.h>

#include "vxd_common.h"
#include "vxd_pvdec_priv.h"
#include "vxd_pvdec_regs.h"
#include "vxd_plat.h"

#ifdef PVDEC_SINGLETHREADED_IO
static DEFINE_SPINLOCK(pvdec_irq_lock);
static unsigned long pvdec_irq_flags;
#endif

/*
 * Reads PROC_DEBUG register and provides number of MTX RAM banks
 * and their size
 */
static int pvdec_get_mtx_ram_info(void __iomem *reg_base, int *bank_cnt,
		size_t *bank_size, size_t *last_bank_size)
{
	u32 ram_bank_count, reg;

	reg = VXD_RD_REG(reg_base, PVDEC_CORE, PROC_DEBUG);
	ram_bank_count = VXD_RD_REG_FIELD(reg, PVDEC_CORE, PROC_DEBUG,
			MTX_RAM_BANKS);
	if (!ram_bank_count)
		return -EIO;

	if (bank_cnt)
		*bank_cnt = ram_bank_count;

	if (bank_size) {
		u32 ram_bank_size = VXD_RD_REG_FIELD(reg, PVDEC_CORE,
				PROC_DEBUG, MTX_RAM_BANK_SIZE);
		*bank_size = 1 << (ram_bank_size + 2);
	}

	if (last_bank_size) {
		u32 last_bank = VXD_RD_REG_FIELD(reg, PVDEC_CORE, PROC_DEBUG,
				MTX_LAST_RAM_BANK_SIZE);
		bool new_representation = VXD_RD_REG_FIELD(reg,
			PVDEC_CORE, PROC_DEBUG, MTX_RAM_NEW_REPRESENTATION);
		if (new_representation)
			*last_bank_size = 1024 * last_bank;
		else {
			*last_bank_size = 1 << (last_bank + 2);
			if (bank_cnt && last_bank == 13 && *bank_cnt == 4) {
				u32 ver = VXD_RD_REG(reg_base, PVDEC_CORE, PVDEC_CORE_REV);
				if ((ver & 0x00ffff00) < 0x00070e00) {
					/* VXD hardware ambiguity:
					 * old cores confuse 120KB and 128KB,
					 * but only the ones < 7.14 have 120KB,
					 * so let's adjust it here. */
					*last_bank_size -= 0x2000;
				}
			}
		}
	}
	return 0;
}

/* Provides size of MTX RAM in bytes */
static int pvdec_get_mtx_ram_size(void __iomem *reg_base,
		unsigned int *ram_size)
{
	int bank_cnt, ret;
	size_t bank_size, last_bank_size;

	ret = pvdec_get_mtx_ram_info(reg_base, &bank_cnt, &bank_size,
			&last_bank_size);
	if (ret)
		return ret;

	*ram_size = (bank_cnt - 1)*bank_size + last_bank_size;

	return 0;
}

/* Poll for single ram-based transfer to/from MTX to complete */
static u32 pvdec_wait_mtx_ram_access(void __iomem *reg_base, u32 *mtx_fault)
{
	u32 pvdec_timeout = PVDEC_TIMEOUT_COUNTER, reg;

	do {
		/* Check MTX is OK...*/
		reg = VXD_RD_REG(reg_base, MTX_CORE, MTX_FAULT0);
		if (reg != 0) {
			*mtx_fault = reg;
			return -EIO;
		}
#if 0
		mdelay(1);
#endif
		pvdec_timeout--;
		reg = VXD_RD_REG(reg_base, MTX_CORE,
				MTX_RAM_ACCESS_STATUS);
	} while ((VXD_RD_REG_FIELD(reg, MTX_CORE,
					MTX_RAM_ACCESS_STATUS,
					MTX_MTX_MCM_STAT) == 0) &&
			(pvdec_timeout != 0));

	if (pvdec_timeout == 0)
		return -EIO;

	return 0;
}

/* Poll for single register-based transfer to/from MTX to complete */
static u32 pvdec_wait_mtx_reg_access(void __iomem *reg_base, u32 *mtx_fault)
{
	u32 pvdec_timeout = PVDEC_TIMEOUT_COUNTER, reg;

	do {
		/* Check MTX is OK...*/
		reg = VXD_RD_REG(reg_base, MTX_CORE, MTX_FAULT0);
		if (reg != 0) {
			*mtx_fault = reg;
			return -EIO;
		}
#if 0
		mdelay(1);
#endif
		pvdec_timeout--;
		reg = VXD_RD_REG(reg_base, MTX_CORE,
				MTX_REG_READ_WRITE_REQUEST);
	} while ((VXD_RD_REG_FIELD(reg, MTX_CORE,
					MTX_REG_READ_WRITE_REQUEST,
					MTX_DREADY) == 0) &&
			(pvdec_timeout != 0));

	if (pvdec_timeout == 0)
		return -EIO;

	return 0;
}

static int pvdec_mtx_ram_dump(const struct device *dev,
		void __iomem *reg_base, u32 dwrds_to_dump,
		u32 dump_offs, u32 *out_buf)
{
	size_t bank_size;
	u32 reg, ram_id, i, ret;

	ret = pvdec_get_mtx_ram_info(reg_base, NULL, &bank_size, NULL);
	if (ret) {
		dev_err(dev, "%s: failed to get MTX RAM info!\n", __func__);
		return -EIO;
	}

	dev_dbg(dev, "%s: dumping 0x%x dwords of MTX RAM at 0x%x, bank: %zu\n",
			__func__, dwrds_to_dump, dump_offs, bank_size);

	ram_id = 0;
	i = dump_offs;

	while (i < dump_offs + dwrds_to_dump) {
		u32 val[4], j, addr;

		for (j = 0; j < 4; j++) {
			reg = 0, addr = (i + j) * sizeof(u32);

			if ((PVDEC_MTX_CORE_MEM + (addr/bank_size)) !=
					ram_id) {
				ram_id = (PVDEC_MTX_CORE_MEM +
						(addr/bank_size));
			}

			VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_RAM_ACCESS_CONTROL,
					MTX_MCMID, ram_id);
			VXD_WR_REG_FIELD(reg, MTX_CORE,
					MTX_RAM_ACCESS_CONTROL, MTX_MCM_ADDR,
					i + j);
			VXD_WR_REG_FIELD(reg, MTX_CORE,
					MTX_RAM_ACCESS_CONTROL, MTX_MCMAI, 0);
			VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_RAM_ACCESS_CONTROL,
					MTX_MCMR, 1);

			VXD_WR_REG(reg_base, MTX_CORE, MTX_RAM_ACCESS_CONTROL,
					reg);

			if (pvdec_wait_mtx_ram_access(reg_base, &reg)) {
				dev_err(dev,
					"%s: MTX RAM RD fault: 0x%08x@%u, addr: 0x%08x\n",
					__func__, reg, i, addr);
				return -EIO;
			}

			val[j] = VXD_RD_REG(reg_base, MTX_CORE,
					MTX_RAM_ACCESS_DATA_EXCHANGE);
		}

#if 0
		dev_dbg(dev, "%s: RAM 0x%08x: 0x%08x 0x%08x 0x%08x 0x%08x\n",
			__func__, i*4, val[0], val[1], val[2], val[3]);
#endif
		if (out_buf) {
			memcpy(out_buf, val, sizeof(val));
			out_buf += 4;
		}

		i += sizeof(u32);
	}

	return 0;
}

static int __maybe_unused pvdec_mtx_ram_reset(const struct device *dev,
		void __iomem *reg_base, u32 reset_val)
{
	size_t mtx_bank_size = 0;
	u32 i, reg = 0, ret, ram_id = (unsigned int)-1, addr = 0;
	uint32_t ram_size;

	if (reg_base == NULL)
		return -EINVAL;

	ret = pvdec_get_mtx_ram_size(reg_base, &ram_size);
	if (ret || ram_size == 0) {
		dev_err(dev, "%s: failed to get MTX RAM size!\n", __func__);
		return ret;
	}

	ret = pvdec_get_mtx_ram_info(reg_base, NULL, &mtx_bank_size, NULL);
	if (ret || mtx_bank_size == 0) {
		dev_err(dev, "%s: failed to get MTX RAM info!\n", __func__);
		return ret;
	}

	dev_err(dev,
			"%s: filling the MTX ram(%u) with 0x%x\n",
			__func__, ram_size, reset_val);

	ram_size = ram_size/sizeof(u32);

	for (i = 0; i < ram_size; i++) {
		if ((PVDEC_MTX_CORE_MEM + (addr/mtx_bank_size)) != ram_id) {
			/* Initiate write access to RAM block...*/
			ram_id = (PVDEC_MTX_CORE_MEM + (addr / mtx_bank_size));
			reg = 0;
			VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_RAM_ACCESS_CONTROL,
					MTX_MCMID, ram_id);
			VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_RAM_ACCESS_CONTROL,
					MTX_MCM_ADDR, (addr>>2));
			VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_RAM_ACCESS_CONTROL,
					MTX_MCMR, 0);
			if (ram_size > 1) {
				VXD_WR_REG_FIELD(reg, MTX_CORE,
						MTX_RAM_ACCESS_CONTROL,
						MTX_MCMAI, 1);
			}
			VXD_WR_REG(reg_base, MTX_CORE,
					MTX_RAM_ACCESS_CONTROL, reg);

			dev_dbg(dev, "%s: configured RAM access: 0x%08x\n",
					__func__, reg);
		}

		VXD_WR_REG(reg_base, MTX_CORE, MTX_RAM_ACCESS_DATA_TRANSFER,
				reset_val);

		if (pvdec_wait_mtx_ram_access(reg_base, &reg)) {
			dev_err(dev,
				"%s: MTX RAM WR fault: 0x%08x@%u, addr: 0x%08x\n",
				__func__, reg, i, addr);
			return -EIO;
		}

		addr += sizeof(addr);
	}

	return 0;
}

static void __maybe_unused pvdec_core_regs_dump(void __iomem *reg_base)
{
	unsigned int i;

	struct dev_regspace {
		const unsigned char *name;
		unsigned int base_addr;
		unsigned short size;
	} reg_spaces[] = {
		{ "CORE", PVDEC_CORE_OFFSET, PVDEC_CORE_SIZE },
		{ "BUS4_MMU", VIDEO_BUS4_MMU_OFFSET, VIDEO_BUS4_MMU_SIZE },
		{ "MTX CORE", MTX_CORE_OFFSET, MTX_CORE_SIZE },
		{ "VLR", VLR_OFFSET, 0x100 }
#if 0
		{ "PIXEL PIPE", PVDEC_PIXEL_OFFSET, PVDEC_PIXEL_SIZE },
		{ "PIXEL DMA", DMAC_OFFSET, DMAC_SIZE },
#endif
	};

	pr_debug("%s: *** dumping registers ***\n", __func__);

	for (i = 0; i < sizeof(reg_spaces)/sizeof(struct dev_regspace); i++) {
		unsigned int val[4];
		unsigned int word, size = reg_spaces[i].size/sizeof(u32);

		pr_debug("%s: reg space %s -> addr: 0x%08x, size 0x%08x\n",
			__func__, reg_spaces[i].name,
			reg_spaces[i].base_addr, size);

		for (word = 0; word < size; word += 4) {
			unsigned int offs = reg_spaces[i].base_addr + word * 4;

			val[0] = VXD_RD_REG_ABS(reg_base, offs);
			val[1] = (word + 1  < size) ?
				(VXD_RD_REG_ABS(reg_base, offs+4)) : 0xdeadbeef;
			val[2] = (word + 2  < size) ?
				(VXD_RD_REG_ABS(reg_base, offs+8)) : 0xdeadbeef;
			val[3] = (word + 3  < size) ?
				(VXD_RD_REG_ABS(reg_base, offs+12)) :
					0xdeadbeef;
			pr_debug(
				"%s: 0x%08x: 0x%08x 0x%08x 0x%08x 0x%08x\n",
				__func__, offs, val[0], val[1], val[2], val[3]);
		}
	}

	pr_debug("%s: *** registers dump done ***\n", __func__);
}

static void pvdec_mtx_status_dump(void __iomem *reg_base, u32 *status)
{
	u32 reg;

	pr_debug("%s: *** dumping status ***\n", __func__);

#define READ_MTX_REG(_NAME_) \
	do { \
		unsigned int val; \
		VXD_WR_REG(reg_base, MTX_CORE, \
				MTX_REG_READ_WRITE_REQUEST, reg); \
		if (pvdec_wait_mtx_reg_access(reg_base, &reg)) { \
			pr_debug("%s: " \
			"MTX REG RD fault: 0x%08x\n", __func__, reg); \
			break; \
		} \
		val = VXD_RD_REG(reg_base, MTX_CORE, MTX_REG_READ_WRITE_DATA); \
		if (status) \
			*status++ = val; \
		pr_debug("%s: " _NAME_ ": 0x%08x\n", __func__, val); \
	} while (0)

	reg = 0;
	VXD_WR_REG_FIELD(reg, MTX_CORE, /* Read */
			MTX_REG_READ_WRITE_REQUEST, MTX_RNW, 1);
	VXD_WR_REG_FIELD(reg, MTX_CORE, /* PC or PCX */
			MTX_REG_READ_WRITE_REQUEST, MTX_USPECIFIER, 5);
	VXD_WR_REG_FIELD(reg, MTX_CORE, /* PC */
			MTX_REG_READ_WRITE_REQUEST, MTX_RSPECIFIER, 0);
	READ_MTX_REG("MTX PC");

	reg = 0;
	VXD_WR_REG_FIELD(reg, MTX_CORE, /* Read */
			MTX_REG_READ_WRITE_REQUEST, MTX_RNW, 1);
	VXD_WR_REG_FIELD(reg, MTX_CORE, /* PC or PCX */
			MTX_REG_READ_WRITE_REQUEST, MTX_USPECIFIER, 5);
	VXD_WR_REG_FIELD(reg, MTX_CORE, /* PCX */
			MTX_REG_READ_WRITE_REQUEST, MTX_RSPECIFIER, 1);
	READ_MTX_REG("MTX PCX");

	reg = 0;
	VXD_WR_REG_FIELD(reg, MTX_CORE, /* Read */
			MTX_REG_READ_WRITE_REQUEST, MTX_RNW, 1);
	VXD_WR_REG_FIELD(reg, MTX_CORE, /* A0StP */
			MTX_REG_READ_WRITE_REQUEST, MTX_USPECIFIER, 3);
	VXD_WR_REG_FIELD(reg, MTX_CORE,
			MTX_REG_READ_WRITE_REQUEST, MTX_RSPECIFIER, 0);
	READ_MTX_REG("MTX A0STP");

	reg = 0;
	VXD_WR_REG_FIELD(reg, MTX_CORE, /* Read */
			MTX_REG_READ_WRITE_REQUEST, MTX_RNW, 1);
	VXD_WR_REG_FIELD(reg, MTX_CORE, /* A0FrP */
			MTX_REG_READ_WRITE_REQUEST, MTX_USPECIFIER, 3);
	VXD_WR_REG_FIELD(reg, MTX_CORE,
			MTX_REG_READ_WRITE_REQUEST, MTX_RSPECIFIER, 1);
	READ_MTX_REG("MTX A0FRP");
#undef PRINT_MTX_REG

	pr_debug("%s: *** status dump done ***\n", __func__);
}

static void pvdec_prep_fw_upload(const struct device *dev,
		void __iomem *reg_base, struct vxd_ena_params *ena_params,
		uint8_t dma_channel)
{
	uint32_t fw_vxd_virt_addr = ena_params->fw_buf_virt_addr;
	uint32_t vxd_ptd_addr = ena_params->ptd;
	uint32_t reg = 0;
	int i;
	u32 flags = PVDEC_FWFLAG_FORCE_FS_FLOW |
		PVDEC_FWFLAG_DISABLE_GENC_FLUSHING |
		PVDEC_FWFLAG_DISABLE_AUTONOMOUS_RESET |
		PVDEC_FWFLAG_DISABLE_IDLE_GPIO |
		PVDEC_FWFLAG_ENABLE_ERROR_CONCEALMENT;

	if (ena_params->secure)
		flags |= PVDEC_FWFLAG_BIG_TO_HOST_BUFFER;

	dev_dbg(dev, "%s: fw_virt: 0x%x, ptd: 0x%x, dma ch: %u, flags: 0x%x\n",
			__func__, fw_vxd_virt_addr, vxd_ptd_addr, dma_channel,
			flags);

#if 0
	pvdec_mtx_ram_reset(dev, reg_base, 0xFFFFFFFF);
#endif

	/* Reset MTX */
	VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_SOFT_RESET, MTX_RESET, 1);
	VXD_WR_REG(reg_base, MTX_CORE, MTX_SOFT_RESET, reg);
	/* NOTE: The MTX reset bit is WRITE ONLY, so we cannot
	 * check the reset procedure has finished, thus BEWARE to put
	 * any MTX_CORE* access just after this line
	 */

	/* Clear COMMS RAM header */
	for (i = 0; i < PVDEC_FW_COMMS_HDR_SIZE; i++)
		VXD_WR_REG_ABS(reg_base, VLR_OFFSET + i*sizeof(u32), 0);

	VXD_WR_REG_ABS(reg_base, VLR_OFFSET + PVDEC_FW_FLAGS_OFFSET, flags);
	/* Do not wait for debug FIFO flag - set it only when requested */
	VXD_WR_REG_ABS(reg_base, VLR_OFFSET + PVDEC_FW_SIGNATURE_OFFSET,
			!ena_params->wait_dbg_fifo);

	/* Clear the bypass bits and enable extended addressing in MMU.
	 * Firmware depends on this configuration, so we have to set it,
	 * even if firmware is being uploaded via registers.
	 */
	reg = 0;
	VXD_WR_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU, MMU_ADDRESS_CONTROL,
			UPPER_ADDR_FIXED, 0);
	VXD_WR_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU, MMU_ADDRESS_CONTROL,
			MMU_ENA_EXT_ADDR,
			/*(eMmuType == MMU_TYPE_40BIT) ? 1 : 0 */ 1);
	VXD_WR_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU, MMU_ADDRESS_CONTROL,
			MMU_BYPASS, 0);
	VXD_WR_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_ADDRESS_CONTROL, reg);

	/* Buffer device virtual address.
	 * This is an address of a firmware blob, firmware reads this base
	 * address from DMAC_SETUP register and uses to load the modules, so it
	 * has to be set even when uploading the FW via registers.
	 */
	VXD_WR_RPT_REG(reg_base, DMAC, DMAC_SETUP, fw_vxd_virt_addr,
			dma_channel);

	/* Set base address of PTD. Same as before, has to be configured even
	 * when uploading the firmware via regs, FW uses it to execute DMA
	 * before switching to stream MMU context.
	 */
	VXD_WR_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_DIR_BASE_ADDR,
			vxd_ptd_addr);

	/* Configure MMU bank index */
	/* Use bank 0 */
	VXD_WR_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_BANK_INDEX, 0);

	/* Set the MTX timer divider register */
	reg = 0;
	VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_SYSC_TIMERDIV, TIMER_EN, 1);
	/* Setting max freq - divide by 1 for better measurement accuracy
	 * during fw upload stage
	 */
	VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_SYSC_TIMERDIV, TIMER_DIV, 0);
	VXD_WR_REG(reg_base, MTX_CORE, MTX_SYSC_TIMERDIV, reg);
}

static int pvdec_check_fw_sig(void __iomem *reg_base)
{
	u32 fw_sig = VXD_RD_REG_ABS(reg_base, VLR_OFFSET +
			PVDEC_FW_SIGNATURE_OFFSET);

	if (fw_sig != PVDEC_FW_READY_SIG)
		return -EIO;

	return 0;
}

static void pvdec_kick_mtx(void __iomem *reg_base)
{
	u32 reg = 0;

	VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_KICKI, MTX_KICKI, 1);
	VXD_WR_REG(reg_base, MTX_CORE, MTX_KICKI, reg);
}

static int pvdec_write_vlr(void __iomem *reg_base, const u32 *buf,
		size_t size_dwrds, int off_dwrds)
{
	unsigned int i;

	if (((off_dwrds + size_dwrds)*sizeof(u32)) > VLR_SIZE)
		return -EINVAL;

	for (i = 0; i < size_dwrds; i++) {
		int off = (off_dwrds + i)*sizeof(u32);

		VXD_WR_REG_ABS(reg_base, (VLR_OFFSET + off), *buf);
		buf++;
	}

	return 0;
}

static int pvdec_read_vlr(void __iomem *reg_base, u32 *buf, size_t size_dwrds,
		int off_dwrds)
{
	unsigned int i;

	if (((off_dwrds + size_dwrds)*sizeof(u32)) > VLR_SIZE)
		return -EINVAL;

	for (i = 0; i < size_dwrds; i++) {
		int off = (off_dwrds + i)*sizeof(u32);
		*buf++ = VXD_RD_REG_ABS(reg_base, (VLR_OFFSET + off));
	}

	return 0;
}

/* Get configuration of a ring buffer used to send messages to the MTX */
static int pvdec_get_to_mtx_cfg(void __iomem *reg_base, size_t *size, int *off,
		unsigned int *wr_idx, unsigned int *rd_idx)
{
	u32 to_mtx_cfg;
	int to_mtx_off, ret;

	ret = pvdec_check_fw_sig(reg_base);
	if (ret)
		return ret;

	to_mtx_cfg = VXD_RD_REG_ABS(reg_base, VLR_OFFSET +
			PVDEC_FW_TO_MTX_BUF_CONF_OFFSET);

	*size = PVDEC_FW_COM_BUF_SIZE(to_mtx_cfg);
	to_mtx_off = PVDEC_FW_COM_BUF_OFF(to_mtx_cfg);

	if (to_mtx_off % 4)
		return -EIO;

	to_mtx_off /= sizeof(u32);
	*off = to_mtx_off;


	*wr_idx = VXD_RD_REG_ABS(reg_base, VLR_OFFSET +
			PVDEC_FW_TO_MTX_WR_IDX_OFFSET);
	*rd_idx = VXD_RD_REG_ABS(reg_base, VLR_OFFSET +
			PVDEC_FW_TO_MTX_RD_IDX_OFFSET);

	if ((*rd_idx >= *size) || (*wr_idx >= *size))
		return -EIO;

	return 0;
}

/* Submit a padding message to the host->MTX ring buffer */
static int pvdec_send_pad_msg(void __iomem *reg_base)
{
	int ret, pad_size, to_mtx_off; /* offset in dwords */
	unsigned int wr_idx, rd_idx; /* indicies in dwords */
	size_t pad_msg_size = 1, to_mtx_size; /* size in dwords */
	const size_t max_msg_size = VXD_MAX_PAYLOAD_SIZE/sizeof(u32);
	u32 pad_msg;

	ret = pvdec_get_to_mtx_cfg(reg_base, &to_mtx_size, &to_mtx_off,
			&wr_idx, &rd_idx);
	if (ret)
		return ret;

	pad_size = to_mtx_size - wr_idx; /* size in dwords */

	if (pad_size <= 0) {
		VXD_WR_REG_ABS(reg_base, VLR_OFFSET +
				PVDEC_FW_TO_MTX_WR_IDX_OFFSET, 0);
		return 0;
	}

	while (pad_size > 0) {
		int cur_pad_size = pad_size > max_msg_size ?
			max_msg_size : pad_size;
		pad_msg = 0;
		VXD_WR_REG_FIELD(pad_msg, PVDEC_FW, DEVA_GENMSG, MSG_SIZE,
				cur_pad_size);
		VXD_WR_REG_FIELD(pad_msg, PVDEC_FW, DEVA_GENMSG, MSG_TYPE,
				PVDEC_FW_MSG_TYPE_PADDING);

		ret = pvdec_write_vlr(reg_base, &pad_msg, pad_msg_size,
				to_mtx_off + wr_idx);
		if (ret)
			return ret;

		wr_idx += cur_pad_size;

		VXD_WR_REG_ABS(reg_base, VLR_OFFSET +
				PVDEC_FW_TO_MTX_WR_IDX_OFFSET, wr_idx);

		pad_size -= cur_pad_size;

		pvdec_kick_mtx(reg_base);
	}

	wr_idx = 0;
	VXD_WR_REG_ABS(reg_base, VLR_OFFSET +
			PVDEC_FW_TO_MTX_WR_IDX_OFFSET, wr_idx);

	return 0;
}

/* Check if there is enough space in comms RAM to submit a <msg_size>
 * dwords long message. Submit a padding message if necessary and requested.
 *
 * Returns 0 if there is space for a message.
 * Returns -EINVAL when msg is too big or empty.
 * Returns -EIO when there was a problem accessing the HW.
 * Returns -EBUSY when there is not ennough space.
 */
static int pvdec_check_comms_space(void __iomem *reg_base, size_t msg_size,
		bool send_padding)
{
	int ret, to_mtx_off; /* offset in dwords */
	unsigned int wr_idx, rd_idx; /* indicies in dwords */
	size_t to_mtx_size; /* size in dwords */

	ret = pvdec_get_to_mtx_cfg(reg_base, &to_mtx_size, &to_mtx_off,
			&wr_idx, &rd_idx);
	if (ret)
		return ret;

	/* Enormous or empty message, won't fit */
	if (msg_size >= to_mtx_size || !msg_size)
		return -EINVAL;

	/* Buffer does not wrap */
	if (wr_idx >= rd_idx) {
		/* Is there enough space to put the message? */
		if (wr_idx + msg_size < to_mtx_size)
			return 0;

		if (!send_padding)
			return -EBUSY;

		/* Check if it's ok to send a padding message */
		if (rd_idx == 0)
			return -EBUSY;

		/* Send a padding message */
		ret = pvdec_send_pad_msg(reg_base);
		if (ret)
			return ret;

		/* And check if there's enough space at the beginning
		 * of a buffer
		 */
		if (msg_size >= rd_idx)
			return -EBUSY; /* Not enough space at the beginning */

	} else { /* Buffer wraps */
		if (wr_idx + msg_size >= rd_idx)
			return -EBUSY; /* Not enough space! */
	}

	return 0;
}

/* Get configuration of a ring buffer used to receive messages from the MTX */
static int pvdec_get_to_host_cfg(void __iomem *reg_base, size_t *size, int *off,
		unsigned int *wr_idx, unsigned int *rd_idx)
{
	u32 to_host_cfg;
	int to_host_off, ret;

	ret = pvdec_check_fw_sig(reg_base);
	if (ret)
		return ret;

	to_host_cfg = VXD_RD_REG_ABS(reg_base, VLR_OFFSET +
			PVDEC_FW_TO_HOST_BUF_CONF_OFFSET);

	*size = PVDEC_FW_COM_BUF_SIZE(to_host_cfg);
	to_host_off = PVDEC_FW_COM_BUF_OFF(to_host_cfg);

	if (to_host_off % 4)
		return -EIO;

	to_host_off /= sizeof(u32);
	*off = to_host_off;


	*wr_idx = VXD_RD_REG_ABS(reg_base, VLR_OFFSET +
			PVDEC_FW_TO_HOST_WR_IDX_OFFSET);
	*rd_idx = VXD_RD_REG_ABS(reg_base, VLR_OFFSET +
			PVDEC_FW_TO_HOST_RD_IDX_OFFSET);

	if ((*rd_idx >= *size) || (*wr_idx >= *size))
		return -EIO;

	return 0;
}

static int pvdec_poll_fw_boot(void __iomem *reg_base,
		struct vxd_boot_poll_params *poll_params)
{
	unsigned int i;

	for (i = 0; i < 25; i++) {
		if (!pvdec_check_fw_sig(reg_base))
			return 0;
		udelay(100);
	}
	for (i = 0; i < poll_params->msleep_cycles; i++) {
		if (!pvdec_check_fw_sig(reg_base))
			return 0;
		msleep(100);
	}
	return -EIO;
}

static void pvdec_select_pipe(void __iomem *reg_base, uint8_t pipe)
{
	uint32_t reg = 0;

	VXD_WR_REG_FIELD(reg, PVDEC_CORE, PVDEC_HOST_PIPE_SELECT,
			PIPE_SEL, pipe);
	VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_HOST_PIPE_SELECT, reg);
}

static void pvdec_pre_boot_setup(const struct device *dev,
		void __iomem *reg_base, struct vxd_ena_params *ena_params)
{
	/* Memory staller pre boot settings*/
	if (ena_params->mem_staller.data) {
		u8 size = ena_params->mem_staller.size;

		if (size == PVDEC_CORE_MEMSTALLER_ELEMENTS) {
			u32 *data = ena_params->mem_staller.data;
			dev_dbg(dev, "%s: Setting up memory staller",
					__func__);
			/*
			 * Data structure represents PVDEC_TEST memory staller
			 * registers according to TRM 5.25 section
			 */
			VXD_WR_REG(reg_base, PVDEC_TEST,
					MEM_READ_LATENCY, data[0]);
			VXD_WR_REG(reg_base, PVDEC_TEST,
					MEM_WRITE_RESPONSE_LATENCY, data[1]);
			VXD_WR_REG(reg_base, PVDEC_TEST,
					MEM_CTRL, data[2]);
			VXD_WR_REG(reg_base, PVDEC_TEST,
					RAND_STL_MEM_CMD_CONFIG, data[3]);
			VXD_WR_REG(reg_base, PVDEC_TEST,
					RAND_STL_MEM_WDATA_CONFIG, data[4]);
			VXD_WR_REG(reg_base, PVDEC_TEST,
					RAND_STL_MEM_WRESP_CONFIG, data[5]);
			VXD_WR_REG(reg_base, PVDEC_TEST,
					RAND_STL_MEM_RDATA_CONFIG, data[6]);
		} else {
			dev_warn(dev,
					"%s: Wrong layout of memory staller configuration (%u)!",
					__func__, size);
		}
	}
}

static void pvdec_post_boot_setup(const struct device *dev,
		void __iomem *reg_base, u32 freq_khz, u32 *timer_div)
{
	int reg;
	unsigned long heap_addrs[][2] = {
#if PVDEC_USE_HEAP_TILE512
		{PVDEC_HEAP_TILE512_START, PVDEC_HEAP_TILE512_START + PVDEC_HEAP_TILE512_SIZE - 1},
#endif
		{PVDEC_HEAP_TILE1024_START, PVDEC_HEAP_TILE1024_START + PVDEC_HEAP_TILE1024_SIZE - 1},
		{PVDEC_HEAP_TILE2048_START, PVDEC_HEAP_TILE2048_START + PVDEC_HEAP_TILE2048_SIZE - 1},
		{PVDEC_HEAP_TILE4096_START, PVDEC_HEAP_TILE4096_START + PVDEC_HEAP_TILE4096_SIZE - 1}
	};
	unsigned int heap_count = sizeof(heap_addrs)/(sizeof(unsigned long) * 2);
	unsigned int i = 0;

	/* Configure VXD MMU to use video tiles (256x16) and unique
	 * strides per context as default. There is currently no
	 * override mechanism.
	 */
	reg = VXD_RD_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_CONTROL0);
	VXD_WR_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU, MMU_CONTROL0,
		MMU_TILING_SCHEME, 0);
	VXD_WR_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU, MMU_CONTROL0,
		USE_TILE_STRIDE_PER_CTX, 1);
	VXD_WR_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_CONTROL0, reg);

	/* Setup VXD MMU with the tile heap device virtual address
	 * ranges. */
	for(i = 0; i < heap_count; i++)
	{
		VXD_WR_RPT_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_TILE_MIN_ADDR,
			heap_addrs[i][0], i);
		VXD_WR_RPT_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_TILE_MAX_ADDR,
			heap_addrs[i][1], i);
	}
	for(; i < 4; i++)
	{
		VXD_WR_RPT_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_TILE_MIN_ADDR,
			0, i);
		VXD_WR_RPT_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_TILE_MAX_ADDR,
			0, i);
	}

	/* Disable timer */
	VXD_WR_REG(reg_base, MTX_CORE, MTX_SYSC_TIMERDIV, 0);

	reg = 0;
	if (freq_khz) {
		VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_SYSC_TIMERDIV, TIMER_DIV,
			PVDEC_CALC_TIMER_DIV(freq_khz/1000));
	} else {
		VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_SYSC_TIMERDIV, TIMER_DIV,
				PVDEC_CLK_MHZ_DEFAULT-1);
	}
	dev_dbg(dev, "%s: set timer_div: %u\n", __func__, reg);
	*timer_div = reg;

	/* Enable the MTX timer with final settings */
	VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_SYSC_TIMERDIV, TIMER_EN, 1);
	VXD_WR_REG(reg_base, MTX_CORE, MTX_SYSC_TIMERDIV, reg);
}

static void pvdec_clock_measure(void __iomem *reg_base,
	struct timespec64 *start_time, uint32_t *start_ticks)
{
	local_irq_disable();
	ktime_get_real_ts64(start_time);
	*start_ticks = VXD_RD_REG(reg_base, MTX_CORE, MTX_SYSC_TXTIMER);
	local_irq_enable();
}

static int pvdec_clock_calculate(const struct device *dev,
		void __iomem *reg_base, struct timespec64 start_time,
		uint32_t start_ticks, u32 *freq_khz, u64 *upload_us)
{
	struct timespec64 end_time;
	int64_t span_nsec = 0;
	uint32_t stop_ticks, tot_ticks;

	local_irq_disable();
	ktime_get_real_ts64(&end_time);
	stop_ticks = VXD_RD_REG(reg_base, MTX_CORE, MTX_SYSC_TXTIMER);
	local_irq_enable();
	span_nsec = timespec64_to_ns(&end_time) - timespec64_to_ns(&start_time);

	/* Sanity check for mtx timer */
	if (!stop_ticks || stop_ticks < start_ticks) {
		dev_err(dev, "%s: invalid ticks (0x%x -> 0x%x)\n",
				__func__, start_ticks, stop_ticks);
		return -EIO;
	}
	tot_ticks = stop_ticks - start_ticks;

	if (span_nsec) {
		uint64_t res = (uint64_t)tot_ticks * 1000000UL;

		do_div(res, span_nsec);
		*freq_khz = (unsigned int)res;
		if (*freq_khz < 1000)
			*freq_khz = 1000;   /* 1MHz */
		res = span_nsec;
		do_div(res, 1000);
		*upload_us = res;
	} else {
		dev_err(dev, "%s: generic failure!\n", __func__);
		*freq_khz = 0;
		return -ERANGE;
	}

	return 0;
}

static int pvdec_wait_dma_done(const struct device *dev,
		void __iomem *reg_base, size_t size, uint8_t dma_channel)
{
	uint32_t reg, timeout = PVDEC_TIMEOUT_COUNTER, prev_count, count = size;

	do {
		udelay(300);
		prev_count = count;
		reg = VXD_RD_RPT_REG(reg_base, DMAC, DMAC_COUNT, dma_channel);
		count = VXD_RD_REG_FIELD(reg, DMAC, DMAC_COUNT, CNT);
		/* Check for dma progress */
		if (count == prev_count) {
			/* There could be a bus lag, protect against that */
			timeout--;
			if (timeout == 0) {
				dev_err(dev, "%s FW DMA failed! (0x%x)\n",
						__func__, count);
				return -EIO;
			}
		} else {
			/* Reset timeout counter */
			timeout = PVDEC_TIMEOUT_COUNTER;
		}
	} while (count > 0);

	return 0;
}

static int pvdec_start_fw_dma(const struct device *dev,
		void __iomem *reg_base, uint8_t dma_channel,
		size_t fw_buf_size, u32 *freq_khz, u64 *upload_us)
{
	uint32_t reg = 0;
	int ret = 0;

	fw_buf_size = fw_buf_size/sizeof(u32);
	dev_dbg(dev, "%s: dma FW upload, fw_buf_size: %zu (dwords)\n",
			__func__, fw_buf_size);

	pvdec_select_pipe(reg_base, 1);

	reg = VXD_RD_REG(reg_base, PVDEC_PIXEL, PIXEL_MAN_CLK_ENA);
	VXD_WR_REG_FIELD(reg, PVDEC_PIXEL, PIXEL_MAN_CLK_ENA,
			PIXEL_DMAC_MAN_CLK_ENA, 1);
	VXD_WR_REG_FIELD(reg, PVDEC_PIXEL, PIXEL_MAN_CLK_ENA,
			PIXEL_REG_MAN_CLK_ENA, 1);
	VXD_WR_REG(reg_base, PVDEC_PIXEL, PIXEL_MAN_CLK_ENA, reg);

	/* Setup MTX to receive DMA */
	/* DMA transfers to/from the MTX have to be 32-bit aligned and
	 * in multiples of 32 bits */
	VXD_WR_REG(reg_base, MTX_CORE, MTX_SYSC_CDMAA, 0); /* MTX: 0x80900000*/

	reg = 0;
	/* Burst size in multiples of 64 bits (allowed values are 2 or 4) */
	VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_SYSC_CDMAC, BURSTSIZE, 0);
	/* 0 - write to MTX memory */
	VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_SYSC_CDMAC, RNW, 0);
	/* Begin transfer */
	VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_SYSC_CDMAC, ENABLE, 1);
	/* Transfer size */
	VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_SYSC_CDMAC, LENGTH,
			((fw_buf_size + 7)&(~7)) + 8);
	VXD_WR_REG(reg_base, MTX_CORE, MTX_SYSC_CDMAC, reg);

	/* Boot MTX once transfer is done */
	reg = 0;
	VXD_WR_REG_FIELD(reg, PVDEC_CORE, PROC_DMAC_CONTROL,
			BOOT_ON_DMA_CH0, 1);
	VXD_WR_REG(reg_base, PVDEC_CORE, PROC_DMAC_CONTROL, reg);

	/* Toggle channel 0 usage between MTX and other PVDEC peripherals */
	reg = 0;
	VXD_WR_REG_FIELD(reg, PVDEC_PIXEL, PIXEL_CONTROL_0,
			DMAC_CH_SEL_FOR_MTX, 0);
	VXD_WR_REG(reg_base, PVDEC_PIXEL, PIXEL_CONTROL_0, reg);

	/* Reset DMA channel first */
	reg = 0;
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, SRST, 1);
	VXD_WR_RPT_REG(reg_base, DMAC, DMAC_COUNT, reg, dma_channel);

	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, LIST_EN, 0);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, CNT, 0);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, EN, 0);
	VXD_WR_RPT_REG(reg_base, DMAC, DMAC_COUNT, reg, dma_channel);

	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, SRST, 0);
	VXD_WR_RPT_REG(reg_base, DMAC, DMAC_COUNT, reg, dma_channel);

	/* Setup a Simple DMA for Ch0 */
	/* Specify the holdover period to use for the channel */
	reg = 0;
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_PER_HOLD, PER_HOLD, 7);
	VXD_WR_RPT_REG(reg_base, DMAC, DMAC_PER_HOLD, reg, dma_channel);

	/* Clear the DMAC Stats */
	VXD_WR_RPT_REG(reg_base, DMAC, DMAC_IRQ_STAT, 0, dma_channel);

	reg = 0;
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_PERIPH_ADDR, ADDR,
			MTX_CORE_MTX_SYSC_CDMAT_OFFSET);
	VXD_WR_RPT_REG(reg_base, DMAC, DMAC_PERIPH_ADDR, reg, dma_channel);

	/* Clear peripheral register address */
	reg = 0;
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_PERIPH, ACC_DEL, 0);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_PERIPH, INCR, DMAC_INCR_OFF);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_PERIPH, BURST, DMAC_BURST_1);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_PERIPH, EXT_BURST,
			DMAC_EXT_BURST_0);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_PERIPH, EXT_SA, 0);
	VXD_WR_RPT_REG(reg_base, DMAC, DMAC_PERIPH, reg, dma_channel);

	/* Now start the transfer by setting the list enable bit in
	 * the count register */
	reg = 0;
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, TRANSFER_IEN, 1);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, PW, DMAC_PWIDTH_32_BIT);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, DIR, DMAC_MEM_TO_VXD);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, PI, DMAC_INCR_ON);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, LIST_FIN_CTL, 0);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, LIST_EN, 0);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, ENABLE_2D_MODE, 0);
	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, CNT, fw_buf_size);
	VXD_WR_RPT_REG(reg_base, DMAC, DMAC_COUNT, reg, dma_channel);

	VXD_WR_REG_FIELD(reg, DMAC, DMAC_COUNT, EN, 1);
	VXD_WR_RPT_REG(reg_base, DMAC, DMAC_COUNT, reg, dma_channel);

	/* NOTE: The MTX timer starts once DMA boot is triggered */
	{
		struct timespec64 host_time;
		uint32_t mtx_time;

		pvdec_clock_measure(reg_base, &host_time, &mtx_time);

		ret = pvdec_wait_dma_done(dev, reg_base,
				fw_buf_size, dma_channel);
		if (!ret) {
			if (pvdec_clock_calculate(dev, reg_base,
					host_time, mtx_time,
					freq_khz, upload_us) < 0)
				dev_dbg(dev, "%s: measure info not available!\n",
						__func__);
		}
	}

	return ret;
}

static int pvdec_start_fw_regs(const struct device *dev, void __iomem *reg_base,
		const u8 *fw, size_t size, u32 *freq_khz, u64 *upload_us)
{
	size_t mtx_bank_size = 0;
	u32 i, reg = 0, ret, ram_id = (unsigned int)-1, addr = 0;
	const u32 *buf = (const unsigned int *)fw;

	size = size/sizeof(u32);

	if (size == 0 || fw == NULL || reg_base == NULL)
		return -EINVAL;

	ret = pvdec_get_mtx_ram_info(reg_base, NULL, &mtx_bank_size, NULL);
	if (ret || mtx_bank_size == 0) {
		dev_err(dev, "%s: failed to get MTX RAM info!\n", __func__);
		return ret;
	}

	dev_dbg(dev,
			"%s: regs FW upload, bank: %zu, addr: %p, size: %zu (dwords)\n",
			__func__, mtx_bank_size, fw, size);

	for (i = 0; i < size; i++) {
		if ((PVDEC_MTX_CORE_MEM + (addr/mtx_bank_size)) != ram_id) {
			/* Initiate write access to RAM block...*/
			ram_id = (PVDEC_MTX_CORE_MEM + (addr / mtx_bank_size));
			reg = 0;
			VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_RAM_ACCESS_CONTROL,
					MTX_MCMID, ram_id);
			VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_RAM_ACCESS_CONTROL,
					MTX_MCM_ADDR, (addr>>2));
			VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_RAM_ACCESS_CONTROL,
					MTX_MCMR, 0);
			if (size > 1) {
				VXD_WR_REG_FIELD(reg, MTX_CORE,
						MTX_RAM_ACCESS_CONTROL,
						MTX_MCMAI, 1);
			}
			VXD_WR_REG(reg_base, MTX_CORE,
					MTX_RAM_ACCESS_CONTROL, reg);

			dev_dbg(dev, "%s: configured RAM access: 0x%08x\n",
					__func__, reg);
		}

		VXD_WR_REG(reg_base, MTX_CORE, MTX_RAM_ACCESS_DATA_TRANSFER,
				buf[i]);

#if 0
		if ((i % 4 == 0) && (i < 0x100) && (i + 3 < size)) {
			/* Dump first 0x100 dwords of FW binary */
			dev_dbg(dev, "0x%08x: 0x%08x 0x%08x 0x%08x 0x%08x\n",
				i*4, buf[i], buf[i+1], buf[i+2], buf[i+3]);
		}
#endif
		if (pvdec_wait_mtx_ram_access(reg_base, &reg)) {
			dev_err(dev,
				"%s: MTX RAM WR fault: 0x%08x@%u, addr: 0x%08x\n",
				__func__, reg, i, addr);
			return -EIO;
		}

		addr += sizeof(addr);
	}

	/* Set PC */
	VXD_WR_REG(reg_base, MTX_CORE, MTX_REG_READ_WRITE_DATA, 0x80900000);

	reg = 0;
	VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_REG_READ_WRITE_REQUEST,
			MTX_RNW, 0); /* Write */
	VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_REG_READ_WRITE_REQUEST,
			MTX_USPECIFIER, 5);  /* PC or PCX */
	VXD_WR_REG_FIELD(reg, MTX_CORE, MTX_REG_READ_WRITE_REQUEST,
			MTX_RSPECIFIER, 0);  /* PC */
	VXD_WR_REG(reg_base, MTX_CORE, MTX_REG_READ_WRITE_REQUEST, reg);

	/* Wait for PC being set */
	if (pvdec_wait_mtx_reg_access(reg_base, &reg)) {
		dev_err(dev,
		"%s: MTX REG WR fault: 0x%08x\n", __func__, reg);
		return -EIO;
	}

	/* Set the MTX running. */
	VXD_WR_REG(reg_base, MTX_CORE, MTX_ENABLE, 1);

	/* NOTE: The MTX timer starts once the MTX is enabled */
	{
		struct timespec64 host_time;
		uint32_t mtx_time;

		pvdec_clock_measure(reg_base, &host_time, &mtx_time);

		/* Uploading firmware using register/ram access is only
		 * a debug option, so we put artificial delay
		 * just to collect the mtx timer data */
		mdelay(20);

		if (pvdec_clock_calculate(dev, reg_base,
				host_time, mtx_time,
				freq_khz, upload_us) < 0)
			dev_dbg(dev, "%s: measure info not available!\n",
					__func__);
	}

	dev_dbg(dev, "%s: FW binary upload done!\n", __func__);

	return 0;
}

static int pvdec_set_clocks(void __iomem *reg_base, uint32_t req_clocks)
{
	u32 clocks = 0, reg;
	u32 pvdec_timeout;

	/* Turn on core clocks only */
	VXD_WR_REG_FIELD(clocks, PVDEC_CORE, PVDEC_MAN_CLK_ENA,
			PVDEC_REG_MAN_CLK_ENA, 1);
	VXD_WR_REG_FIELD(clocks, PVDEC_CORE, PVDEC_MAN_CLK_ENA,
			CORE_MAN_CLK_ENA, 1);

	/* Wait until core clocks set */
	pvdec_timeout = PVDEC_TIMEOUT_COUNTER;
	do {
		VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_MAN_CLK_ENA, clocks);
		udelay(vxd_plat_poll_udelay);
		reg = VXD_RD_REG(reg_base, PVDEC_CORE, PVDEC_MAN_CLK_ENA);
		pvdec_timeout--;
	} while (reg != clocks && pvdec_timeout != 0);

	if (pvdec_timeout == 0) {
		pr_err("Waiting for clocks reset timed out (%x!=%x)!\n",
				reg, req_clocks);
		return -EIO;
	}
	/* Write requested clocks */
	VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_MAN_CLK_ENA, req_clocks);

	return 0;
}

static int pvdec_enable_clocks(void __iomem *reg_base)
{
	u32 clocks = 0;

	VXD_WR_REG_FIELD(clocks, PVDEC_CORE, PVDEC_MAN_CLK_ENA,
			PVDEC_REG_MAN_CLK_ENA, 1);
	VXD_WR_REG_FIELD(clocks, PVDEC_CORE, PVDEC_MAN_CLK_ENA,
			CORE_MAN_CLK_ENA, 1);
	VXD_WR_REG_FIELD(clocks, PVDEC_CORE, PVDEC_MAN_CLK_ENA,
			MEM_MAN_CLK_ENA, 1);
	VXD_WR_REG_FIELD(clocks, PVDEC_CORE, PVDEC_MAN_CLK_ENA,
			PROC_MAN_CLK_ENA, 1);
	VXD_WR_REG_FIELD(clocks, PVDEC_CORE, PVDEC_MAN_CLK_ENA,
			PIXEL_PROC_MAN_CLK_ENA, 1);

	return pvdec_set_clocks(reg_base, clocks);
}

static int pvdec_disable_clocks(void __iomem *reg_base)
{
	return pvdec_set_clocks(reg_base, 0);
}

static void pvdec_ena_mtx_int(void __iomem *reg_base)
{
	u32 reg = VXD_RD_REG(reg_base, PVDEC_CORE, PVDEC_HOST_INT_ENA);

	VXD_WR_REG_FIELD(reg, PVDEC_CORE, PVDEC_INT_STAT,
			HOST_PROC_IRQ, 1);
	VXD_WR_REG_FIELD(reg, PVDEC_CORE, PVDEC_INT_STAT,
			HOST_MMU_FAULT_IRQ, 1);
	VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_HOST_INT_ENA, reg);
}

static void pvdec_check_mmu_requests(void __iomem *reg_base,
			u32 mmu_checks, u32 max_attempts)
{
	u32 reg, i, checks = 0;

	for (i = 0; i < max_attempts; i++) {
		reg = VXD_RD_REG(reg_base,
				IMG_VIDEO_BUS4_MMU, MMU_MEM_REQ);
		reg = VXD_RD_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU,
				MMU_MEM_REQ, TAG_OUTSTANDING);
		if (reg) {
			udelay(vxd_plat_poll_udelay);
			continue;
		}

		/* Read READ_WORDS_OUTSTANDING */
		reg = VXD_RD_REG(reg_base, IMG_VIDEO_BUS4_MMU,
						MMU_MEM_EXT_OUTSTANDING);
		reg = VXD_RD_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU,
				MMU_MEM_EXT_OUTSTANDING, READ_WORDS);
		if (!reg) {
			checks++;
			if (checks == mmu_checks)
				break;
		} else { /* Reset the counter and continue */
			checks = 0;
		}
	}

	if (checks != mmu_checks)
		pr_warn("Checking for MMU outstanding requests failed!\n");
}

static int pvdec_reset(void __iomem *reg_base, bool skip_pipe_clocks)
{
	u32 reg = 0;
	u8 pipe, num_ent_pipes, num_pix_pipes;
	u32 core_id, pvdec_timeout;

	core_id = VXD_RD_REG(reg_base, PVDEC_CORE, PVDEC_CORE_ID);

	num_ent_pipes = VXD_RD_REG_FIELD(core_id, PVDEC_CORE, PVDEC_CORE_ID,
			ENT_PIPES);
	num_pix_pipes = VXD_RD_REG_FIELD(core_id, PVDEC_CORE, PVDEC_CORE_ID,
			PIX_PIPES);

	if (num_pix_pipes == 0 || num_pix_pipes > VXD_MAX_PIPES)
		return -EINVAL;

#ifdef CONFIG_MCST
	if (vxd_pci_drv_ptr &&
		vxd_pci_drv_ptr->pci_dev) {
		if (pci_reset_function(vxd_pci_drv_ptr->pci_dev) < 0)
			printk(KERN_WARNING "%s: No pci_reset_function supported!\n", __func__);
	}
#endif

	/* Clear interrupt enabled flag */
	VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_HOST_INT_ENA, 0);

	/* Clear any pending interrupt flags */
	reg = 0;
	VXD_WR_REG_FIELD(reg, PVDEC_CORE, PVDEC_INT_CLEAR, IRQ_CLEAR, 0xFFFF);
	VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_INT_CLEAR, reg);

	/* Turn all clocks on - don't touch reserved bits! */
	pvdec_set_clocks(reg_base, 0xFFFF0113);

	if (!skip_pipe_clocks) {
		for (pipe = 1; pipe <= num_pix_pipes; pipe++) {
			pvdec_select_pipe(reg_base, pipe);
			/* Turn all available clocks on - skip reserved bits! */
			VXD_WR_REG(reg_base, PVDEC_PIXEL, PIXEL_MAN_CLK_ENA,
					0xFFBF0FFF);
		}

		for (pipe = 1; pipe <= num_ent_pipes; pipe++) {
			pvdec_select_pipe(reg_base, pipe);
			/* Turn all available clocks on - skip reserved bits! */
			VXD_WR_REG(reg_base, PVDEC_ENTROPY, ENTROPY_MAN_CLK_ENA,
						0x5);
		}
	}

	/* 1st MMU outstanding requests check */
	pvdec_check_mmu_requests(reg_base, 1000, 2000);

	/* Make sure MMU is not under reset MMU_SOFT_RESET -> 0 */
	pvdec_timeout = PVDEC_TIMEOUT_COUNTER;
	do {
		reg = VXD_RD_REG(reg_base, IMG_VIDEO_BUS4_MMU,
				MMU_CONTROL1);
		reg = VXD_RD_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU,
				MMU_CONTROL1, MMU_SOFT_RESET);
		udelay(vxd_plat_poll_udelay);
		pvdec_timeout--;
	} while (reg != 0 && pvdec_timeout != 0);

	if (pvdec_timeout == 0) {
		pr_err("Waiting for MMU soft reset(1) timed out!\n");
#ifdef DUMP_REGS
		pvdec_core_regs_dump(reg_base);
		pvdec_mtx_status_dump(reg_base, NULL);
#endif
	}

	/* Write 1 to MMU_PAUSE_SET */
	reg = 0;
	VXD_WR_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU, MMU_CONTROL1,
			MMU_PAUSE_SET, 1);
	VXD_WR_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_CONTROL1, reg);

	/* 2nd MMU outstanding requests check */
	pvdec_check_mmu_requests(reg_base, 100, 1000);

	/* Issue software reset for all but MMU/core */
	reg = 0;
	VXD_WR_REG_FIELD(reg, PVDEC_CORE, PVDEC_SOFT_RST,
			PVDEC_PIXEL_PROC_SOFT_RST, 0xFF);
	VXD_WR_REG_FIELD(reg, PVDEC_CORE, PVDEC_SOFT_RST,
			PVDEC_ENTROPY_SOFT_RST, 0xFF);
	VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_SOFT_RST, reg);

	VXD_RD_REG(reg_base, PVDEC_CORE, PVDEC_SOFT_RST);
	VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_SOFT_RST, 0);

	/* Write 1 to MMU_PAUSE_CLEAR in MMU_CONTROL1 reg */
	reg = 0;
	VXD_WR_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU, MMU_CONTROL1,
			MMU_PAUSE_CLEAR, 1);
	VXD_WR_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_CONTROL1, reg);

	/* Confirm MMU_PAUSE_SET is cleared */
	pvdec_timeout = PVDEC_TIMEOUT_COUNTER;
	do {
		reg = VXD_RD_REG(reg_base, IMG_VIDEO_BUS4_MMU,
				MMU_CONTROL1);
		reg = VXD_RD_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU,
				MMU_CONTROL1, MMU_PAUSE_SET);
		udelay(vxd_plat_poll_udelay);
		pvdec_timeout--;
	} while (reg != 0 && pvdec_timeout != 0);

	if (pvdec_timeout == 0) {
		pr_err("Waiting for MMU pause clear timed out!\n");
#ifdef DUMP_REGS
		pvdec_core_regs_dump(reg_base);
		pvdec_mtx_status_dump(reg_base, NULL);
#endif
		return -EIO;
	}

	/* Issue software reset for MMU */
	reg = 0;
	VXD_WR_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU, MMU_CONTROL1,
			MMU_SOFT_RESET, 1);
	VXD_WR_REG(reg_base, IMG_VIDEO_BUS4_MMU,
			MMU_CONTROL1, reg);

	/* Wait until MMU_SOFT_RESET -> 0 */
	pvdec_timeout = PVDEC_TIMEOUT_COUNTER;
	do {
		reg = VXD_RD_REG(reg_base, IMG_VIDEO_BUS4_MMU,
				MMU_CONTROL1);
		reg = VXD_RD_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU,
				MMU_CONTROL1, MMU_SOFT_RESET);
		udelay(vxd_plat_poll_udelay);
		pvdec_timeout--;
	} while (reg != 0 && pvdec_timeout != 0);

	if (pvdec_timeout == 0) {
		pr_err("Waiting for MMU soft reset(2) timed out!\n");
#ifdef DUMP_REGS
		pvdec_core_regs_dump(reg_base);
		pvdec_mtx_status_dump(reg_base, NULL);
#endif
	}

	/* Issue software reset for entire PVDEC */
	reg = 0;
	VXD_WR_REG_FIELD(reg, PVDEC_CORE, PVDEC_SOFT_RST,
			PVDEC_SOFT_RST, 0x1);
	VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_SOFT_RST, reg);

	/* Waiting for reset bit to be cleared */
	pvdec_timeout = PVDEC_TIMEOUT_COUNTER;
	do {
		reg = VXD_RD_REG(reg_base, PVDEC_CORE, PVDEC_SOFT_RST);
		reg = VXD_RD_REG_FIELD(reg, PVDEC_CORE, PVDEC_SOFT_RST,
					PVDEC_SOFT_RST);
		udelay(vxd_plat_poll_udelay);
		pvdec_timeout--;
	} while (reg != 0 && pvdec_timeout != 0);

	if (pvdec_timeout == 0) {
		pr_err("Waiting for PVDEC soft reset timed out!\n");
#ifdef DUMP_REGS
		pvdec_core_regs_dump(reg_base);
		pvdec_mtx_status_dump(reg_base, NULL);
#endif
		return -EIO;
	}

#ifdef VXD_SECURE_FAULTS
	/* Check mmu faults support for secure transactions */
	reg = VXD_RD_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_CONFIG1);
	if (VXD_RD_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU,
				MMU_CONFIG1, SUPPORT_SECURE)) {
		/* Reset security policy */
		VXD_WR_REG(reg_base, IMG_VIDEO_BUS4_MMU,
				SECURE_FAULT_ENABLE, 0);
	}
#endif

	/* Clear interrupt enabled flag */
	VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_HOST_INT_ENA, 0);

	/* Clear any pending interrupt flags */
	reg = 0;
	VXD_WR_REG_FIELD(reg, PVDEC_CORE, PVDEC_INT_CLEAR, IRQ_CLEAR, 0xFFFF);
	VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_INT_CLEAR, reg);
	return 0;
}

static int pvdec_get_properties(void __iomem *reg_base,
		struct vxd_core_props *props)
{
	unsigned int major, minor, maint, group_id, core_id;
	unsigned char num_pix_pipes, pipe;

	if (props == NULL)
		return -EINVAL;

	/* PVDEC Core Revision Information */
	props->core_rev = VXD_RD_REG(reg_base, PVDEC_CORE, PVDEC_CORE_REV);
	major = VXD_RD_REG_FIELD(props->core_rev, PVDEC_CORE,
			PVDEC_CORE_REV, PVDEC_MAJOR_REV);
	minor = VXD_RD_REG_FIELD(props->core_rev, PVDEC_CORE,
			PVDEC_CORE_REV, PVDEC_MINOR_REV);
	maint = VXD_RD_REG_FIELD(props->core_rev, PVDEC_CORE,
			PVDEC_CORE_REV, PVDEC_MAINT_REV);

	/* Core ID */
	props->pvdec_core_id = VXD_RD_REG(reg_base, PVDEC_CORE, PVDEC_CORE_ID);
	group_id = VXD_RD_REG_FIELD(props->pvdec_core_id, PVDEC_CORE,
			PVDEC_CORE_ID, GROUP_ID);
	core_id = VXD_RD_REG_FIELD(props->pvdec_core_id, PVDEC_CORE,
			PVDEC_CORE_ID, CORE_ID);

	/* Ensure that the core is IMG Video Decoder (PVDEC). */
	if (group_id != 3 || core_id != 3) {
		pr_err("Wrong core revision %d.%d.%d !!!\n",
				major, minor, maint);
		return -EIO;
	}

	props->mmu_config0 = VXD_RD_REG(reg_base, IMG_VIDEO_BUS4_MMU,
			MMU_CONFIG0);
	props->mmu_config1 = VXD_RD_REG(reg_base, IMG_VIDEO_BUS4_MMU,
			MMU_CONFIG1);

	num_pix_pipes = VXD_NUM_PIX_PIPES(*props);

	if (unlikely(num_pix_pipes > VXD_MAX_PIPES)) {
		WARN(1, "too many pipes detected!\n");
		num_pix_pipes = VXD_MAX_PIPES;
	}

	for (pipe = 1; pipe <= num_pix_pipes; ++pipe) {
		pvdec_select_pipe(reg_base, pipe);
		props->pixel_pipe_cfg[pipe - 1] =
			VXD_RD_REG(reg_base, PVDEC_PIXEL, PIXEL_PIPE_CONFIG);
		props->pixel_misc_cfg[pipe - 1] =
			VXD_RD_REG(reg_base, PVDEC_PIXEL, PIXEL_MISC_CONFIG);
		/* Detect pipe access problems.
		 * Pipe config shall always indicate
		 * a non zero value (at least one standard supported) !*/
		WARN(!props->pixel_pipe_cfg[pipe - 1],
			"pipe config info is wrong!\n");
	}

	pvdec_select_pipe(reg_base, 1);
	props->pixel_max_frame_cfg = VXD_RD_REG(reg_base, PVDEC_PIXEL,
			MAX_FRAME_CONFIG);

	{
		u32 fifo_ctrl = VXD_RD_REG(reg_base, PVDEC_CORE, PROC_DBG_FIFO_CTRL0);
		props->dbg_fifo_size = VXD_RD_REG_FIELD(fifo_ctrl,
			PVDEC_CORE, PROC_DBG_FIFO_CTRL0, PROC_DBG_FIFO_SIZE);
	}

	return 0;
}

int vxd_pvdec_init(const struct device *dev, void __iomem *reg_base)
{
	int ret;

	dev_dbg(dev, "%s: trying to reset VXD, reg base: %p\n",
			__func__, reg_base);

	ret = pvdec_enable_clocks(reg_base);
	if (ret) {
		dev_err(dev, "%s: failed to enable clocks!\n", __func__);
		return ret;
	}

	ret = pvdec_reset(reg_base, false);
	if (ret) {
		dev_err(dev, "%s: VXD reset failed!\n", __func__);
		return ret;
	}

	pvdec_ena_mtx_int(reg_base);

	return 0;
}

/* Send <msg_size> dwords long message */
int vxd_pvdec_send_msg(const struct device *dev, void __iomem *reg_base,
		u32 *msg, size_t msg_size, uint16_t msg_id)
{
	int ret, to_mtx_off; /* offset in dwords */
	unsigned int wr_idx, rd_idx; /* indicies in dwords */
	size_t to_mtx_size; /* size in dwords */
	uint32_t msg_wrd;

	ret = pvdec_get_to_mtx_cfg(reg_base, &to_mtx_size, &to_mtx_off,
			&wr_idx, &rd_idx);
	if (ret) {
		dev_err(dev, "%s: failed to obtain mtx ring buffer config!\n",
				__func__);
		return ret;
	}

	/* populate the size and id fields in the message header */
	msg_wrd = VXD_RD_MSG_WRD(msg, PVDEC_FW, DEVA_GENMSG);
	VXD_WR_REG_FIELD(msg_wrd, PVDEC_FW, DEVA_GENMSG, MSG_SIZE, msg_size);
	VXD_WR_REG_FIELD(msg_wrd, PVDEC_FW, DEVA_GENMSG, MSG_ID, msg_id);
	VXD_WR_MSG_WRD(msg, PVDEC_FW, DEVA_GENMSG, msg_wrd);

	dev_dbg(dev, "%s: [msg out] size: %zu, id: 0x%x, type: 0x%x\n",
			__func__, msg_size, msg_id,
			VXD_RD_REG_FIELD(msg_wrd,
				PVDEC_FW, DEVA_GENMSG, MSG_TYPE));
	dev_dbg(dev, "%s: to_mtx: (%zu @ %d), wr_idx: %d, rd_idx: %d\n",
			__func__, to_mtx_size, to_mtx_off, wr_idx, rd_idx);

	ret = pvdec_check_comms_space(reg_base, msg_size, false);
	if (ret) {
		dev_err(dev, "%s: invalid message or not enough space (%d)!\n",
				__func__, ret);
		return ret;
	}

	ret = pvdec_write_vlr(reg_base, msg, msg_size, to_mtx_off + wr_idx);
	if (ret) {
		dev_err(dev, "%s: failed to write msg to vlr!\n", __func__);
		return ret;
	}

	wr_idx += msg_size;
	if (wr_idx == to_mtx_size)
		wr_idx = 0;
	VXD_WR_REG_ABS(reg_base, VLR_OFFSET +
			PVDEC_FW_TO_MTX_WR_IDX_OFFSET, wr_idx);

	pvdec_kick_mtx(reg_base);

	return 0;
}

/* Fetch size (in dwords) of message pending from MTX */
int vxd_pvdec_pend_msg_info(const struct device *dev, void __iomem *reg_base,
		size_t *size, uint16_t *msg_id, bool *not_last_msg)
{
	int ret, to_host_off; /* offset in dwords */
	unsigned int wr_idx, rd_idx; /* indicies in dwords */
	size_t to_host_size; /* size in dwords */
	u32 val = 0;

	ret = pvdec_get_to_host_cfg(reg_base, &to_host_size, &to_host_off,
			&wr_idx, &rd_idx);
	if (ret) {
		dev_err(dev, "%s: failed to obtain host ring buffer config!\n",
				__func__);
		return ret;
	}

	dev_dbg(dev, "%s: to host: (%zu @ %d), wr: %u, rd: %u\n", __func__,
			to_host_size, to_host_off, wr_idx, rd_idx);

	if (wr_idx == rd_idx) {
		*size = 0;
		*msg_id = 0;
		return 0;
	}

	ret = pvdec_read_vlr(reg_base, &val, 1, to_host_off + rd_idx);
	if (ret) {
		dev_err(dev, "%s: failed to read first word!\n", __func__);
		return ret;
	}

	*size = VXD_RD_REG_FIELD(val, PVDEC_FW, DEVA_GENMSG, MSG_SIZE);
	*msg_id = VXD_RD_REG_FIELD(val, PVDEC_FW, DEVA_GENMSG, MSG_ID);
	*not_last_msg = VXD_RD_REG_FIELD(val, PVDEC_FW, DEVA_GENMSG,
			NOT_LAST_MSG);

	dev_dbg(dev,
		"%s: [msg in] rd_idx: %d, size: %zu, id: 0x%04x, type: 0x%x\n",
		__func__, rd_idx, *size, *msg_id,
		VXD_RD_REG_FIELD(val, PVDEC_FW, DEVA_GENMSG, MSG_TYPE));

	return 0;
}

/*
 * Receive message from the MTX and place it in a <buf_size> dwords long
 * buffer. If the provided buffer is too small to hold the message, only part
 * of it will be placed in a buffer, but the ring buffer read index will be
 * moved so that message is no longer available.
 */
int vxd_pvdec_recv_msg(const struct device *dev, void __iomem *reg_base,
		u32 *buf, size_t buf_size)
{
	int ret, to_host_off; /* offset in dwords */
	unsigned int wr_idx, rd_idx; /* indicies in dwords */
	size_t to_host_size, msg_size, to_read; /* sizes in dwords */
	u32 val = 0;

	ret = pvdec_get_to_host_cfg(reg_base, &to_host_size,
			&to_host_off, &wr_idx, &rd_idx);
	if (ret) {
		dev_err(dev, "%s: failed to obtain host ring buffer config!\n",
				__func__);
		return ret;
	}

	dev_dbg(dev, "%s: to host: (%zu @ %d), wr: %u, rd: %u\n", __func__,
			to_host_size, to_host_off, wr_idx, rd_idx);

	/* Obtain the message size */
	ret = pvdec_read_vlr(reg_base, &val, 1, to_host_off + rd_idx);
	if (ret) {
		dev_err(dev, "%s: failed to read first word!\n", __func__);
		return ret;
	}
	msg_size = VXD_RD_REG_FIELD(val, PVDEC_FW, DEVA_GENMSG, MSG_SIZE);

	to_read = (msg_size > buf_size) ? buf_size : msg_size;

	/* Does the message wrap? */
	if (to_read + rd_idx > to_host_size) {
		size_t chunk_size = to_host_size - rd_idx;

		ret = pvdec_read_vlr(reg_base, buf, chunk_size,
				to_host_off + rd_idx);
		if (ret) {
			dev_err(dev, "%s: failed to read chunk before wrap!\n",
					__func__);
			return ret;
		}
		to_read -= chunk_size;
		buf += chunk_size;
		rd_idx = 0;
		msg_size -= chunk_size;

	}

	/*
	 * If the message wrapped, read the second chunk.
	 * If it didn't, read first and only chunk
	 */
	ret = pvdec_read_vlr(reg_base, buf, to_read, to_host_off + rd_idx);
	if (ret) {
		dev_err(dev, "%s: failed to read message from vlr!\n",
				__func__);
		return ret;
	}

	/* Update read index in the ring buffer */
	rd_idx = (rd_idx + msg_size) % to_host_size;
	VXD_WR_REG_ABS(reg_base, VLR_OFFSET +
			PVDEC_FW_TO_HOST_RD_IDX_OFFSET, rd_idx);

	return 0;
}

int vxd_pvdec_check_fw_status(const struct device *dev,
		void __iomem *reg_base)
{
	int ret;
	u32 val = 0;

	/* Obtain current fw status */
	ret = pvdec_read_vlr(reg_base, &val, 1, PVDEC_FW_STATUS_OFFSET);
	if (ret) {
		dev_err(dev, "%s: failed to read fw status!\n", __func__);
		return ret;
	}

	/* Check for fatal condition */
	switch (val) {
		case PVDEC_FW_STATUS_PANIC:
			return VXD_FW_MSG_FLAG_FATAL;
		case PVDEC_FW_STATUS_ASSERT:
			return VXD_FW_MSG_FLAG_FATALA;
		case PVDEC_FW_STATUS_SO:
			return VXD_FW_MSG_FLAG_FATALO;
		default:
			break;
	}

	return 0;
}

static int pvdec_send_init_msg(const struct device *dev,
		void __iomem *reg_base, struct vxd_ena_params *ena_params)
{
	uint16_t msg_id = 0;
	uint32_t msg[PVDEC_FW_DEVA_INIT_MSG_WRDS] = { 0 }, msg_wrd = 0;

	dev_dbg(dev, "%s: rendec: %d@0x%x, crc: 0x%x\n", __func__,
			ena_params->rendec_size, ena_params->rendec_addr,
			ena_params->crc);

	/* message type */
	VXD_WR_REG_FIELD(msg_wrd, PVDEC_FW, DEVA_GENMSG, MSG_TYPE,
			PVDEC_FW_MSG_TYPE_INIT);
	VXD_WR_MSG_WRD(msg, PVDEC_FW, DEVA_GENMSG, msg_wrd);

	/* rendec address */
	VXD_WR_MSG_WRD(msg, PVDEC_FW_DEVA_INIT, RENDEC_ADDR0,
			ena_params->rendec_addr);

	/* rendec size */
	msg_wrd = 0;
	VXD_WR_REG_FIELD(msg_wrd, PVDEC_FW, DEVA_INIT, RENDEC_SIZE0,
			ena_params->rendec_size);
	VXD_WR_MSG_WRD(msg, PVDEC_FW_DEVA_INIT, RENDEC_SIZE0, msg_wrd);

	/* HEVC configuration */
	msg_wrd = 0;
	VXD_WR_REG_FIELD(msg_wrd, PVDEC_FW, DEVA_INIT,
			HEVC_CFG_MAX_H_FOR_PIPE_WAIT, 0xFFFF);
	VXD_WR_MSG_WRD(msg, PVDEC_FW_DEVA_INIT, HEVC_CFG, msg_wrd);

	/* signature select */
	VXD_WR_MSG_WRD(msg, PVDEC_FW_DEVA_INIT, SIG_SELECT, ena_params->crc);

	/* partial frame notification timer divider */
	msg_wrd = 0;
	VXD_WR_REG_FIELD(msg_wrd, PVDEC_FW, DEVA_INIT, PFNT_DIV, PVDEC_PFNT_DIV);
	VXD_WR_MSG_WRD(msg, PVDEC_FW_DEVA_INIT, PFNT_DIV, msg_wrd);

	/* firmware watchdog timeout value */
	VXD_WR_REG_FIELD(msg_wrd, PVDEC_FW, DEVA_INIT, FWWDT_MS,
		ena_params->fwwdt_ms);
	VXD_WR_MSG_WRD(msg, PVDEC_FW_DEVA_INIT, FWWDT_MS, msg_wrd);

	return vxd_pvdec_send_msg(dev, reg_base, msg,
			ARRAY_SIZE(msg), msg_id);
}

int vxd_pvdec_ena(const struct device *dev, void __iomem *reg_base,
		struct vxd_ena_params *ena_params, struct vxd_fw_hdr *fw_hdr,
		struct vxd_hw_boot *boot)
{
	int ret;
	unsigned int mtx_ram_size = 0;
	uint8_t dma_channel = 0;

	ret = vxd_pvdec_init(dev, reg_base);
	if (ret) {
		dev_err(dev, "%s: PVDEC init failed!\n", __func__);
		return ret;
	}

	ret = pvdec_get_mtx_ram_size(reg_base, &mtx_ram_size);
	if (ret) {
		dev_err(dev, "%s: failed to get MTX RAM size!\n", __func__);
		return ret;
	}

	if (mtx_ram_size < fw_hdr->core_size) {
		dev_err(dev, "%s: FW larger than MTX RAM size (%u < %d)!\n",
				__func__, mtx_ram_size, fw_hdr->core_size);
		return -EINVAL;
	}

	dev_dbg(dev, "%s: trying to load PVDEC FW, dma: %d\n", __func__,
			ena_params->use_dma);

	/* Apply pre boot settings - if any */
	pvdec_pre_boot_setup(dev, reg_base, ena_params);

	pvdec_prep_fw_upload(dev, reg_base, ena_params, dma_channel);

	if (ena_params->use_dma) {
		ret = pvdec_start_fw_dma(dev, reg_base, dma_channel,
				fw_hdr->core_size, &boot->freq_khz,
				&boot->upload_us);
	} else {
		ret = pvdec_start_fw_regs(dev, reg_base,
				ena_params->regs_data.buf, fw_hdr->core_size,
				&boot->freq_khz, &boot->upload_us);
	}

	if (ret) {
		dev_err(dev, "%s: failed to load FW! (%d)", __func__, ret);
#ifdef DUMP_REGS
		pvdec_mtx_status_dump(reg_base, NULL);
		pvdec_core_regs_dump(reg_base);
#endif
		return ret;
	}

	dev_dbg(dev, "%s: upload took %llu [us], freq: %u [kHz]\n",
				__func__, boot->upload_us, boot->freq_khz);

	/* Apply final settings - if any */
	pvdec_post_boot_setup(dev, reg_base, boot->freq_khz,
			&boot->timer_div);

	ret = pvdec_poll_fw_boot(reg_base, &ena_params->boot_poll);
	if (ret) {
		dev_err(dev, "%s: FW failed to boot! (%d)!\n", __func__, ret);
		return ret;
	}

	ret = pvdec_send_init_msg(dev, reg_base, ena_params);
	if (ret) {
		dev_err(dev, "%s: failed to send init message! (%d)!\n",
				__func__, ret);
		return ret;
	}

	return 0;
}

int vxd_pvdec_stop(const struct device *dev, void __iomem *reg_base)
{
	/* Stopping MTX to prevent any fw acitvity */
	VXD_WR_REG(reg_base, MTX_CORE, MTX_ENABLE, 0);

	return 0;
}

int vxd_pvdec_dis(const struct device *dev, void __iomem *reg_base)
{
	int ret = pvdec_enable_clocks(reg_base);
	if (ret) {
		dev_err(dev, "%s: failed to enable clocks! (%d)\n",
				__func__, ret);
		return ret;
	}

	ret = pvdec_reset(reg_base, true);
	if (ret) {
		dev_err(dev, "%s: VXD reset failed! (%d)\n", __func__, ret);
		return ret;
	}

	ret = pvdec_disable_clocks(reg_base);
	if (ret) {
		dev_err(dev, "%s: VXD disable clocks failed! (%d)\n",
				__func__, ret);
		return ret;
	}

	return 0;
}

/*
 * Invalidate VXD's MMU cache.
 * WARNING: it kills FPGA when called when HW (clocks) is disabled!
 */
int vxd_pvdec_mmu_flush(const struct device *dev, void __iomem *reg_base)
{
	u32 reg = VXD_RD_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_CONTROL1);

	if (reg == PVDEC_INVALID_HW_STATE) {
		dev_err(dev, "%s: invalid HW state!\n", __func__);
		return -EIO;
	}

	VXD_WR_REG_FIELD(reg, IMG_VIDEO_BUS4_MMU, MMU_CONTROL1,
			MMU_INVALDC, 0xF);
	VXD_WR_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_CONTROL1, reg);

	dev_dbg(dev, "%s: device MMU cache invalidated!\n", __func__);

	return 0;
}

/*
 * Peeks PVDEC debug FIFO to see if any data is available to be read
 */
size_t vxd_pvdec_peek_mtx_fifo(const struct device *dev, void __iomem *reg_base)
{
	u32 fifo_ctrl = VXD_RD_REG(reg_base, PVDEC_CORE, PROC_DBG_FIFO_CTRL0);
	u32 fifo_size = VXD_RD_REG_FIELD(fifo_ctrl,
		PVDEC_CORE, PROC_DBG_FIFO_CTRL0, PROC_DBG_FIFO_SIZE);
	u32 fifo_count = VXD_RD_REG_FIELD(fifo_ctrl, PVDEC_CORE,
			PROC_DBG_FIFO_CTRL0, PROC_DBG_FIFO_COUNT);

	if (!fifo_count)
		dev_warn(dev, "%s: mtx fifo overflow!\n", __func__);

	return fifo_size - fifo_count;
}

/*
 * Reads PVDEC debug FIFO and puts the data into provided buffer <buf>
 * of size <size> (in bytes)
 */
size_t vxd_pvdec_read_mtx_fifo(const struct device *dev, void __iomem *reg_base,
		u32 *buf, size_t size)
{
	s32 dwrds, count = 0;

	dwrds = vxd_pvdec_peek_mtx_fifo(dev, reg_base);
	if (!dwrds)
		return 0;

	do {
		*(buf++) = VXD_RD_REG(reg_base, PVDEC_CORE, PROC_DBG_FIFO);
		count++;
	} while ((size -= sizeof(u32)) > 0 && --dwrds > 0);

	return count;
}

irqreturn_t vxd_pvdec_clear_int(void __iomem *reg_base, u32 *irq_status)
{
	irqreturn_t ret = IRQ_NONE;
	u32 enabled;
	u32 status = VXD_RD_REG(reg_base, PVDEC_CORE, PVDEC_INT_STAT);

	enabled = VXD_RD_REG(reg_base, PVDEC_CORE, PVDEC_HOST_INT_ENA);

	status &= enabled;
	/* Store the last irq status */
	*irq_status |= status;

	if (status & (PVDEC_CORE_PVDEC_INT_STAT_HOST_MMU_FAULT_IRQ_MASK |
				PVDEC_CORE_PVDEC_INT_STAT_HOST_PROC_IRQ_MASK))
		ret = IRQ_WAKE_THREAD;

	/* Disable MMU interrupts - clearing is not enough */
	if (status & PVDEC_CORE_PVDEC_INT_STAT_HOST_MMU_FAULT_IRQ_MASK) {
		enabled &= ~PVDEC_CORE_PVDEC_INT_STAT_HOST_MMU_FAULT_IRQ_MASK;
		VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_HOST_INT_ENA, enabled);
	}

	VXD_WR_REG(reg_base, PVDEC_CORE, PVDEC_INT_CLEAR, status);

	return ret;
}

/*
 * Check for the source of the last interrupt.
 *
 * return 0 if nothing serious happened,
 * return -EFAULT if there was a critical interrupt detected.
 */
int vxd_pvdec_check_irq(const struct device *dev, void __iomem *reg_base,
		u32 irq_status)
{
	if (irq_status & PVDEC_CORE_PVDEC_INT_STAT_HOST_MMU_FAULT_IRQ_MASK) {
		u32 status0 =
			VXD_RD_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_STATUS0);
		u32 status1 =
			VXD_RD_REG(reg_base, IMG_VIDEO_BUS4_MMU, MMU_STATUS1);

		u32 addr = VXD_RD_REG_FIELD(status0, IMG_VIDEO_BUS4_MMU,
				MMU_STATUS0, MMU_FAULT_ADDR) << 12;
		u8 reason = VXD_RD_REG_FIELD(status0, IMG_VIDEO_BUS4_MMU,
				MMU_STATUS0, MMU_PF_N_RW);
		u8 requestor = VXD_RD_REG_FIELD(status1, IMG_VIDEO_BUS4_MMU,
				MMU_STATUS1, MMU_FAULT_REQ_ID);
		u8 type = VXD_RD_REG_FIELD(status1, IMG_VIDEO_BUS4_MMU,
				MMU_STATUS1, MMU_FAULT_RNW);
		bool secure = VXD_RD_REG_FIELD(status0, IMG_VIDEO_BUS4_MMU,
				MMU_STATUS0, MMU_SECURE_FAULT);

		dev_dbg(dev, "%s: MMU Page Fault s0:%08x s1:%08x", __func__,
				status0, status1);

		dev_err(dev, "%s: MMU %s fault from %s while %s @ 0x%08X",
				__func__,
				(reason) ? "Page" : "Protection",
				(requestor&(0x1)) ? "dmac" :
				(requestor&(0x2)) ? "vec"  :
				(requestor&(0x4)) ? "vdmc" :
				(requestor&(0x8)) ? "vdeb" : "unknown source",
				(type) ? "reading" : "writing", addr);

		if (secure)
			dev_err(dev, "%s: MMU security policy violation detected!",
					__func__);

		return -EFAULT;
	}

	return 0;
}

/*
 * Check if there's enough space in comms RAM to submit <msg_size> dwords long
 * message. This function also submits a padding message if it will be
 * necessary for this particular message.
 *
 * return 0 if there is enough space,
 * return -EBUSY if there is not enough space,
 * return another fault code in case of an error.
 */
int vxd_pvdec_msg_fit(const struct device *dev, void __iomem *reg_base,
		size_t msg_size)
{
	int ret = pvdec_check_comms_space(reg_base, msg_size, true);

	/* In specific environment, when to_mtx buffer is small, and messages
	 * the userspace is submitting are large (e.g. FWBSP flow), it's
	 * possible that firmware will consume the padding message sent by
	 * vxd_pvdec_msg_fit() immediately. Retry the check. */
	if (ret == -EBUSY) {
		u32 flags = VXD_RD_REG_ABS(reg_base, VLR_OFFSET + PVDEC_FW_FLAGS_OFFSET) |
			PVDEC_FWFLAG_FAKE_COMPLETION;

		dev_dbg(dev, "comms space full, asking fw to send empty msg when more"
			"space is available");

		VXD_WR_REG_ABS(reg_base, VLR_OFFSET + PVDEC_FW_FLAGS_OFFSET, flags);
		ret = pvdec_check_comms_space(reg_base, msg_size, false);
	}

	return ret;
}

void vxd_pvdec_get_state(const struct device *dev, void __iomem *reg_base,
		u32 num_pipes, struct vxd_hw_state *state)
{
	u32 state_cfg = VXD_RD_REG_ABS(reg_base, (VLR_OFFSET +
				PVDEC_FW_STATE_BUF_CFG_OFFSET));

	u16 state_size = PVDEC_FW_COM_BUF_SIZE(state_cfg);
	u16 state_off = PVDEC_FW_COM_BUF_OFF(state_cfg);
	u8 pipe;

	/* The generic fw progress counter
	 * is the first element in the fw state */
	dev_dbg(dev, "%s: state off: 0x%x, size: 0x%x\n", __func__,
			state_off, state_size);
	state->fw_counter = VXD_RD_REG_ABS(reg_base,
			(VLR_OFFSET + state_off));
	dev_dbg(dev, "%s: fw_counter: 0x%x\n", __func__, state->fw_counter);

	/* We just combine the macroblocks being processed by the HW */
	for (pipe = 0; pipe < num_pipes; pipe++) {
		u32 p_off = VXD_GET_PIPE_OFF(num_pipes, pipe + 1);
		u32 reg_val;

		/* Front-end */
		u32 reg_off = VXD_GET_REG_OFF(PVDEC_ENTROPY, ENTROPY_LAST_MB);

		state->fe_status[pipe] = VXD_RD_REG_ABS(reg_base, reg_off);

		reg_off = VXD_GET_REG_OFF(MSVDX_VEC, VEC_ENTDEC_INFORMATION);
		state->fe_status[pipe] |= VXD_RD_REG_ABS(reg_base, reg_off +
				+ p_off);

		/* Back-end */
		reg_off = VXD_GET_REG_OFF(PVDEC_VEC_BE, VEC_BE_STATUS);
		state->be_status[pipe] = VXD_RD_REG_ABS(reg_base, reg_off +
				+ p_off);
		reg_off = VXD_GET_REG_OFF(MSVDX_VDMC, VDMC_MACROBLOCK_NUMBER);
		state->be_status[pipe] |= VXD_RD_REG_ABS(reg_base, reg_off +
				+ p_off);

		/* Take DMAC channels 2/3 into consideration to cover
		 * parser progress on SR1/2 */
		reg_off = VXD_GET_RPT_REG_OFF(DMAC, DMAC_COUNT, 2);
		reg_val = VXD_RD_REG_ABS(reg_base, reg_off + p_off);
		state->dmac_status[pipe][0] = VXD_RD_REG_FIELD(reg_val, DMAC,
				DMAC_COUNT, CNT);
		reg_off = VXD_GET_RPT_REG_OFF(DMAC, DMAC_COUNT, 3);
		reg_val = VXD_RD_REG_ABS(reg_base, reg_off + p_off);
		state->dmac_status[pipe][1] = VXD_RD_REG_FIELD(reg_val, DMAC,
				DMAC_COUNT, CNT);
	}
}

/* This functions enables the clocks, fetches the core properties, stores them
 * in the <props> structure and DISABLES the clocks. Do not call when hardware
 * is busy! */
int vxd_pvdec_get_props(const struct device *dev, void __iomem *reg_base,
		struct vxd_core_props *props)
{
	unsigned char num_pix_pipes, pipe;
	int ret = pvdec_enable_clocks(reg_base);

	if (ret) {
		dev_err(dev, "%s: failed to enable clocks!\n", __func__);
		return ret;
	}

	ret = pvdec_get_mtx_ram_size(reg_base, &props->mtx_ram_size);
	if (ret) {
		dev_err(dev, "%s: failed to get MTX ram size!\n", __func__);
		return ret;
	}

	ret = pvdec_get_properties(reg_base, props);
	if (ret) {
		dev_err(dev, "%s: failed to get VXD props!\n", __func__);
		return ret;
	}

	if (pvdec_disable_clocks(reg_base))
		dev_err(dev, "%s: failed to disable clocks!\n", __func__);

	num_pix_pipes = VXD_NUM_PIX_PIPES(*props);

	/* Warning already raised in pvdec_get_properties() */
	if (unlikely(num_pix_pipes > VXD_MAX_PIPES))
			num_pix_pipes = VXD_MAX_PIPES;

	dev_dbg(dev, "%s: id: 0x%08x\n", __func__, props->id);
	dev_dbg(dev, "%s: core_rev: 0x%08x\n", __func__, props->core_rev);
	dev_dbg(dev, "%s: pvdec_core_id: 0x%08x\n",
			__func__, props->pvdec_core_id);
	dev_dbg(dev, "%s: mmu_config0: 0x%08x\n",
			__func__, props->mmu_config0);
	dev_dbg(dev, "%s: mmu_config1: 0x%08x\n",
			__func__, props->mmu_config1);
	dev_dbg(dev, "%s: mtx_ram_size: %u\n",
			__func__, props->mtx_ram_size);
	dev_dbg(dev, "%s: pix max frame: 0x%08x\n",
			__func__, props->pixel_max_frame_cfg);

	for (pipe = 1; pipe <= num_pix_pipes; ++pipe)
		dev_dbg(dev, "%s:  pipe %u, 0x%08x, misc 0x%08x\n",
				__func__, pipe, props->pixel_pipe_cfg[pipe - 1],
				props->pixel_misc_cfg[pipe - 1]);
	dev_dbg(dev, "%s: dbg fifo size: %u\n",
			__func__, props->dbg_fifo_size);
	return 0;
}

size_t vxd_pvdec_get_dbg_fifo_size(void __iomem *reg_base)
{
	u32 fifo_ctrl = VXD_RD_REG(reg_base, PVDEC_CORE, PROC_DBG_FIFO_CTRL0);

	return VXD_RD_REG_FIELD(fifo_ctrl, PVDEC_CORE, PROC_DBG_FIFO_CTRL0,
			PROC_DBG_FIFO_SIZE)*sizeof(u32);
}

int vxd_pvdec_dump_mtx_ram(const struct device *dev, void __iomem *reg_base,
		u32 addr, u32 count, u32 *buf)
{
	int ret = 0;
	u32 ram_size;

	/* Check address 4-byte aligned */
	if (addr & 0x3) {
		dev_err(dev, "%s: bad address (0x%x)!\n",
				__func__, addr);
		return -EINVAL;
	}

	if (!count) {
		dev_err(dev, "%s: wrong number of entries to dump!\n",
				__func__);
		return -EINVAL;
	}

	ret = pvdec_get_mtx_ram_size(reg_base, &ram_size);
	if (ret) {
		dev_err(dev, "%s: failed to get MTX ram size!\n",
				__func__);
		return ret;
	}

	if (ram_size < (addr + count)*sizeof(u32)) {
		dev_err(dev, "%s: dump request beyond ram size!\n",
				__func__);
		return -EINVAL;
	}

	/* Set the MTX idle */
	VXD_WR_REG(reg_base, MTX_CORE, MTX_ENABLE, 0);
	ret = pvdec_mtx_ram_dump(dev, reg_base, count, addr, buf);
	/* Set the MTX running */
	VXD_WR_REG(reg_base, MTX_CORE, MTX_ENABLE, 1);

	return ret;
}

int vxd_pvdec_dump_mtx_status(const struct device *dev, void __iomem *reg_base,
		u32 *array, u32 array_size)
{
	int ret = 0;

	if (array_size < MTX_CORE_STATUS_ELEMENTS) {
		dev_err(dev, "%s: status array to small!\n",
				__func__);
		return -EINVAL;
	}

	pvdec_mtx_status_dump(reg_base, array);

	return ret;
}
