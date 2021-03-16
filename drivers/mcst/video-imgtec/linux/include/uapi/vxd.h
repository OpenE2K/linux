/*!
 *****************************************************************************
 *
 * @File       vxd.h
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

#ifndef _VXD_H
#define _VXD_H

#if defined(__KERNEL__)
#include <linux/ioctl.h>
#include <linux/types.h>
#elif defined(__linux__)
#include <sys/ioctl.h>
#include <inttypes.h>
#else
#error unsupported build
#endif

/* Max size of the message payload, in bytes. There are 7 bits used to encode
 * the message size in the firmware interface. */
#define VXD_MAX_PAYLOAD_SIZE (127*sizeof(u32))
/* Max size of the input message in bytes. */
#define VXD_MAX_INPUT_SIZE (VXD_MAX_PAYLOAD_SIZE + sizeof(struct vxd_fw_msg))
/* Min size of the input message. Two words needed for message header and
 * stream PTD */
#define VXD_MIN_INPUT_SIZE 2
/* Offset of the stream PTD within message. This word has to be left null in
 * submitted message, driver will fill it in with an appropriate value. */
#define VXD_PTD_MSG_OFFSET 1

/* Read flags */
#define VXD_FW_MSG_RD_FLAGS_MASK 0xffff
/* Driver watchdog interrupted processing of the message. */
#define VXD_FW_MSG_FLAG_DWR 0x1
/* VXD MMU fault occurred when the message was processed. */
#define VXD_FW_MSG_FLAG_MMU_FAULT 0x2
/* Invalid input message, e.g. the message was too large. */
#define VXD_FW_MSG_FLAG_INV 0x4
/* I/O error occurred when the message was processed. */
#define VXD_FW_MSG_FLAG_DEV_ERR 0x8
/* Driver error occurred when the message was processed, e.g. failed to
 * allocate memory. */
#define VXD_FW_MSG_FLAG_DRV_ERR 0x10
/* Item was cancelled, without being fully processed
 * i.e. corresponding stream was destroyed. */
#define VXD_FW_MSG_FLAG_CANCELED 0x20
/* Firmware internal error occurred when the message was processed */
#define VXD_FW_MSG_FLAG_FATAL  0x40
#define VXD_FW_MSG_FLAG_FATALA 0x80
#define VXD_FW_MSG_FLAG_FATALO 0x100
#define VXD_FW_MSG_FLAG_FATALS \
	(VXD_FW_MSG_FLAG_FATAL | VXD_FW_MSG_FLAG_FATALA | VXD_FW_MSG_FLAG_FATALO)


/* Write flags */
#define VXD_FW_MSG_WR_FLAGS_MASK 0xffff0000
/* Indicates that message shall be dropped after sending it to the firmware. */
#define VXD_FW_MSG_FLAG_DROP 0x10000
/* Indicates that message shall be exclusively handled by
 * the firmware/hardware. Any other pending messages are
 * blocked until such message is handled. */
#define VXD_FW_MSG_FLAG_EXCL 0x20000

/* Format of data exchanged in read/write. */
struct vxd_fw_msg {
	uint32_t stream_id;
	uint32_t out_flags;
	uint32_t payload_size; /* size of payload in bytes */
	uint32_t payload[0]; /* data which is send to firmware */

};

#define VXD_MSG_SIZE(msg) (sizeof(struct vxd_fw_msg) + ((msg).payload_size))

/* Header included at the beginning of firmware binary */
struct vxd_fw_hdr {
	uint32_t core_size;
	uint32_t blob_size;
	uint32_t firmware_id;
	uint32_t timestamp;
};


#define VXD_MAX_PIPES 3

struct vxd_core_props {
	uint32_t id;
	uint32_t core_rev;
	uint32_t pvdec_core_id;
	uint32_t mmu_config0;
	uint32_t mmu_config1;
	uint32_t mtx_ram_size;
	uint32_t pixel_max_frame_cfg;
	int32_t internal_heap_id;
	uint32_t pixel_pipe_cfg[VXD_MAX_PIPES];
	uint32_t pixel_misc_cfg[VXD_MAX_PIPES];
	uint32_t dbg_fifo_size;

};

struct vxd_alloc_data {
	uint32_t heap_id;	/* [IN] Heap ID of allocator                */
	uint32_t size;		/* [IN] Size of device memory (in bytes)    */
	uint32_t attributes;	/* [IN] Attributes of buffer
				 * TODO: what sort of values ?              */
	uint32_t buf_id;	/* [OUT] Generated buffer ID                */
};

struct vxd_import_data {
	uint32_t heap_id;	/* [IN] Heap ID of allocator                */
	uint32_t size;		/* [IN] Size of device memory (in bytes)    */
	uint32_t attributes;	/* [IN] Attributes of buffer
				 * TODO: what sort of values ?              */
	uint32_t buf_fd;	/* [IN] File descriptor of buffer to import */
	uint32_t buf_id;	/* [OUT] Generated buffer ID                */
};

struct vxd_free_data {
	uint32_t buf_id;	/* [IN] ID of device buffer to free */
};

enum vxd_stream_type {
	VXD_STR_TYPE_LOOPBACK = 0,
	VXD_STR_TYPE_NON_SECURE = 1,
	VXD_STR_TYPE_SECURE = 2,
	VXD_STR_TYPE_MAX = 3
};

struct vxd_create_stream_data {
	uint32_t stream_type;   /* [IN] Stream type to select appropriate fw */
	uint32_t stream_id;	/* [OUT] Stream ID created by driver */
};

struct vxd_destroy_stream_data {
	uint32_t stream_id;	/* [IN] Stream ID to destroy context */
};

enum vxd_map_flags {
	VXD_MAP_FLAG_NONE = 0x0,
	VXD_MAP_FLAG_READ_ONLY = 0x1,
	VXD_MAP_FLAG_WRITE_ONLY = 0x2,
};

struct vxd_map_data {
	uint32_t stream_id;	/* [IN] Stream to map this buffer in      */
	uint32_t buf_id;	/* [IN] ID of device buffer to map to VXD */
	uint32_t virt_addr;	/* [IN] Device virtual address to map     */
	uint32_t flags;		/* [IN] Mapping flags, see vxd_map_flags  */
};

struct vxd_unmap_data {
	uint32_t stream_id;	/* [IN] Stream to unmap this buffer from      */
	uint32_t buf_id;	/* [IN] ID of device buffer to unmap from VXD */
};

#define VXD_IOCTL_MAGIC  'p'

#define VXD_IOCTL_PROPS \
	_IOR(VXD_IOCTL_MAGIC, 0, struct vxd_core_props)
#define VXD_IOCTL_ALLOC \
	_IOWR(VXD_IOCTL_MAGIC, 1, struct vxd_alloc_data)
#define VXD_IOCTL_IMPORT \
	_IOWR(VXD_IOCTL_MAGIC, 2, struct vxd_import_data)
#define VXD_IOCTL_FREE \
	_IOW(VXD_IOCTL_MAGIC, 3, struct vxd_free_data)
#define VXD_IOCTL_STREAM_CREATE \
	_IOR(VXD_IOCTL_MAGIC, 4, struct vxd_create_stream_data)
#define VXD_IOCTL_STREAM_DESTROY \
	_IOW(VXD_IOCTL_MAGIC, 5, struct vxd_destroy_stream_data)
#define VXD_IOCTL_VXD_MAP \
	_IOW(VXD_IOCTL_MAGIC, 6, struct vxd_map_data)
#define VXD_IOCTL_VXD_UNMAP \
	_IOW(VXD_IOCTL_MAGIC, 7, struct vxd_unmap_data)




/* Helpers for parsing core properties. Based on HW registers layout. */
#define VXD_GET_BITS(v, lb, rb) ((v >> (rb)) & ((1 << (lb - rb + 1)) - 1))
#define VXD_GET_BIT(v, b) ((v >> b) & 1)

/* Get major core revision. */
#define VXD_MAJ_REV(props) (VXD_GET_BITS((props).core_rev, 23, 16))
/* Get minor core revision. */
#define VXD_MIN_REV(props) (VXD_GET_BITS((props).core_rev, 15, 8))
/* Get maint core revision. */
#define VXD_MAINT_REV(props) (VXD_GET_BITS((props).core_rev, 7, 0))
/* Get number of entropy pipes available (HEVC). */
#define VXD_NUM_ENT_PIPES(props) ((props).pvdec_core_id & 0xF)
/* Get number of pixel pipes available (other standards). */
#define VXD_NUM_PIX_PIPES(props) (((props).pvdec_core_id & 0xF0) >> 4)
/* Get number of bits used by external memory interface. */
#define VXD_EXTRN_ADDR_WIDTH(props) ((((props).mmu_config0 & 0xF0) >> 4) + 32)

/* Check whether specific standard is supported by the pixel pipe. */
#define VXD_HAS_MPEG2(props, pipe) VXD_GET_BIT(props.pixel_pipe_cfg[pipe], 0)
#define VXD_HAS_MPEG4(props, pipe) VXD_GET_BIT(props.pixel_pipe_cfg[pipe], 1)
#define VXD_HAS_H264(props, pipe) VXD_GET_BIT(props.pixel_pipe_cfg[pipe], 2)
#define VXD_HAS_VC1(props, pipe) VXD_GET_BIT(props.pixel_pipe_cfg[pipe], 3)
#define VXD_HAS_WMV9(props, pipe) VXD_GET_BIT(props.pixel_pipe_cfg[pipe], 4)
#define VXD_HAS_JPEG(props, pipe) VXD_GET_BIT(props.pixel_pipe_cfg[pipe], 5)
#define VXD_HAS_MPEG4_DATA_PART(props, pipe) \
	VXD_GET_BIT(props.pixel_pipe_cfg[pipe], 6)
#define VXD_HAS_AVS(props, pipe) VXD_GET_BIT(props.pixel_pipe_cfg[pipe], 7)
#define VXD_HAS_REAL(props, pipe) VXD_GET_BIT(props.pixel_pipe_cfg[pipe], 8)
#define VXD_HAS_VP6(props, pipe) VXD_GET_BIT(props.pixel_pipe_cfg[pipe], 9)
#define VXD_HAS_VP8(props, pipe) VXD_GET_BIT(props.pixel_pipe_cfg[pipe], 10)
#define VXD_HAS_SORENSON(props, pipe) \
	VXD_GET_BIT(props.pixel_pipe_cfg[pipe], 11)

/* Check wheter specific feature is supported by the pixel pipe */

/* Max picture size for HEVC still picture profile is 64k wide and/or 64k
 * high. */
#define VXD_HAS_HEVC_64K_STILL(props, pipe) \
	(VXD_GET_BIT((props).pixel_misc_cfg[pipe], 24))

/* Pixel processing pipe index. */
#define VXD_PIX_PIPE_ID(props, pipe) \
	(VXD_GET_BITS((props).pixel_misc_cfg[pipe], 18, 16))

/* Number of stream supported by the pixel pipe DMAC and shift register. */
#define VXD_PIX_NUM_STRS(props, pipe) \
	(VXD_GET_BITS((props).pixel_misc_cfg[pipe], 13, 12) + 1)

/* Is scaling supported. */
#define VXD_HAS_SCALING(props, pipe) \
	(VXD_GET_BIT((props).pixel_misc_cfg[pipe], 9))

/* Is rotation supported. */
#define VXD_HAS_ROTATION(props, pipe) \
	(VXD_GET_BIT((props).pixel_misc_cfg[pipe], 8))

/* Are HEVC range extensions supported. */
#define VXD_HAS_HEVC_REXT(props, pipe) \
	(VXD_GET_BIT((props).pixel_misc_cfg[pipe], 7))

/* Maximum bit depth supported by the pipe. */
#define VXD_MAX_BIT_DEPTH(props, pipe) \
	(VXD_GET_BITS((props).pixel_misc_cfg[pipe], 6, 4) + 8)

/* Maximum chroma fomar supported by the pipe in HEVC mode.
 * 0x1 - 4:2:0
 * 0x2 - 4:2:2
 * 0x3 - 4:4:4 */
#define VXD_MAX_HEVC_CHROMA_FMT(props, pipe) \
	(VXD_GET_BITS((props).pixel_misc_cfg[pipe], 3, 2))

/* Maximum chroma fomar supported by the pipe in H264 mode.
 * 0x1 - 4:2:0
 * 0x2 - 4:2:2
 * 0x3 - 4:4:4 */
#define VXD_MAX_H264_CHROMA_FMT(props, pipe) \
	(VXD_GET_BITS((props).pixel_misc_cfg[pipe], 1, 0))

/* Maximum frame width and height supported in MSVDX pipeline. */
#define VXD_MAX_WIDTH_MSVDX(props) \
	(2 << (VXD_GET_BITS((props).pixel_max_frame_cfg, 4, 0)))
#define VXD_MAX_HEIGHT_MSVDX(props) \
	(2 << (VXD_GET_BITS((props).pixel_max_frame_cfg, 12, 8)))

/* Maximum frame width and height supported in PVDEC pipeline. */
#define VXD_MAX_WIDTH_PVDEC(props) \
	(2 << (VXD_GET_BITS((props).pixel_max_frame_cfg, 20, 16)))
#define VXD_MAX_HEIGHT_PVDEC(props) \
	(2 << (VXD_GET_BITS((props).pixel_max_frame_cfg, 28, 24)))


/*
 * coding style for emacs
 *
 * Local variables:
 * indent-tabs-mode: t
 * tab-width: 8
 * c-basic-offset: 8
 * End:
 */
/*
 * coding style for vim
 *
 * vim: set tabstop=8 softtabstop=8 shiftwidth=8 noexpandtab :
*/
#endif /* _VXD_H */
