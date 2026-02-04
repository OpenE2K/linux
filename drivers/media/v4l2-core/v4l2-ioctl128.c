/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/module.h>
#include <linux/time.h>
#include <linux/videodev2.h>
#include <linux/v4l2-subdev.h>
#include <media/v4l2-dev.h>
#include <media/v4l2-fh.h>
#include <media/v4l2-ctrls.h>
#include <media/v4l2-ioctl.h>

/*
 * Per-ioctl data copy handlers.
 *
 * Those come in pairs, with a get_v4l2_foo() and a put_v4l2_foo() routine,
 * where "v4l2_foo" is the name of the V4L2 struct.
 *
 * They basically get two __user pointers, one with a 32-bits struct that
 * came from the userspace call and a 64-bits struct, also allocated as
 * userspace, but filled internally by do_video_ioctl().
 *
 * For ioctls that have pointers inside it, the functions will also
 * receive an ancillary buffer with extra space, used to pass extra
 * data to the routine.
 */

struct v4l2_clip128 {
	struct v4l2_rect        c;
	e2k_ap_t		next; /* struct v4l2_clip128  __user * */
};

struct v4l2_window128 {
	struct v4l2_rect        w;
	__u32			field;	/* enum v4l2_field */
	__u32			chromakey;
	e2k_ap_t		clips; /* actually (struct v4l2_clip128 *) */
	__u32			clipcount;
	e2k_ap_t		bitmap; /* (void __user *) */
	__u8                    global_alpha;
};

static int get_v4l2_window128(struct v4l2_window *p64,
			     struct v4l2_window128 __user *p128)
{
	struct v4l2_window128 w128;
	e2k_ap_t	ap;
	int		tag;
	if (copy_from_user(&w128, p128, sizeof(w128)))
		return -EFAULT;

	*p64 = (struct v4l2_window) {
		.w		= w128.w,
		.field		= w128.field,
		.chromakey	= w128.chromakey,
		.clipcount	= w128.clipcount,
		.global_alpha	= w128.global_alpha,
	};
	if (p64->clipcount > 2048)
		return -EINVAL;
	if (get_user_tagged_16(ap.qword, tag, &p128->bitmap))
		return -EFAULT;
	if (IS_AP(ap, tag)) {
		p64->bitmap = (void __user *)AP_PTR(ap);
	} else {
		p64->bitmap = NULL;
	}
	/* Did not find out where bitmap data accessed, not set u_border */
	if (!p64->clipcount) {
		p64->clips = NULL;
	} else {
		if (get_user_tagged_16(ap.qword, tag, &p128->clips))
			return -EFAULT;
		if (IS_AP(ap, tag) &&
		    AP_OBJ_SIZE(ap) < w128.clipcount * sizeof(struct v4l2_clip128))
			return -EFAULT;
		p64->clips = (void __force *)AP_PTR(ap);
	}
	set_ap_u_border(ap);
	return 0;
}

static int put_v4l2_window128(struct v4l2_window *p64,
			     struct v4l2_window128 __user *p128)
{
	struct v4l2_window128 w128;

	memset(&w128, 0, sizeof(w128));
	w128 = (struct v4l2_window128) {
		.w		= p64->w,
		.field		= p64->field,
		.chromakey	= p64->chromakey,
		.clipcount	= p64->clipcount,
		.global_alpha	= p64->global_alpha,
	};
	/* copy everything except the clips and bitmap pointers */
	set_max_u_border();
	if (copy_to_user(p128, &w128, offsetof(struct v4l2_window128, clips)) ||
	    put_user(w128.clipcount, &p128->clipcount) ||
	    put_user(w128.global_alpha, &p128->global_alpha))
		return -EFAULT;
	return 0;
}

struct v4l2_format128 {
	__u32	type;	/* enum v4l2_buf_type */
	union {
		struct v4l2_pix_format	pix;
		struct v4l2_pix_format_mplane	pix_mp;
		struct v4l2_window128	win;
		struct v4l2_vbi_format	vbi;
		struct v4l2_sliced_vbi_format	sliced;
		struct v4l2_sdr_format	sdr;
		struct v4l2_meta_format	meta;
		__u8	raw_data[200];        /* user-defined */
	} fmt;
};

/**
 * struct v4l2_create_buffers128 - VIDIOC_CREATE_BUFS32 argument
 * @index:	on return, index of the first created buffer
 * @count:	entry: number of requested buffers,
 *		return: number of created buffers
 * @memory:	buffer memory type
 * @format:	frame format, for which buffers are requested
 * @capabilities: capabilities of this buffer type.
 * @flags:	additional buffer management attributes (ignored unless the
 *		queue has V4L2_BUF_CAP_SUPPORTS_MMAP_CACHE_HINTS capability and
 *		configured for MMAP streaming I/O).
 * @reserved:	future extensions
 */
struct v4l2_create_buffers128 {
	__u32			index;
	__u32			count;
	__u32			memory;	/* enum v4l2_memory */
	struct v4l2_format128	format;
	__u32			capabilities;
	__u32			flags;
	__u32			reserved[6];
};

static int get_v4l2_format128(struct v4l2_format *p64,
			     struct v4l2_format128 __user *p128)
{
	if (get_user(p64->type, &p128->type))
		return -EFAULT;

	switch (p64->type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		return copy_from_user(&p64->fmt.pix, &p128->fmt.pix,
				      sizeof(p64->fmt.pix)) ? -EFAULT : 0;
	case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE:
		return copy_from_user(&p64->fmt.pix_mp, &p128->fmt.pix_mp,
				      sizeof(p64->fmt.pix_mp)) ? -EFAULT : 0;
	case V4L2_BUF_TYPE_VIDEO_OVERLAY:
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY:
		return get_v4l2_window128(&p64->fmt.win, &p128->fmt.win);
	case V4L2_BUF_TYPE_VBI_CAPTURE:
	case V4L2_BUF_TYPE_VBI_OUTPUT:
		return copy_from_user(&p64->fmt.vbi, &p128->fmt.vbi,
				      sizeof(p64->fmt.vbi)) ? -EFAULT : 0;
	case V4L2_BUF_TYPE_SLICED_VBI_CAPTURE:
	case V4L2_BUF_TYPE_SLICED_VBI_OUTPUT:
		return copy_from_user(&p64->fmt.sliced, &p128->fmt.sliced,
				      sizeof(p64->fmt.sliced)) ? -EFAULT : 0;
	case V4L2_BUF_TYPE_SDR_CAPTURE:
	case V4L2_BUF_TYPE_SDR_OUTPUT:
		return copy_from_user(&p64->fmt.sdr, &p128->fmt.sdr,
				      sizeof(p64->fmt.sdr)) ? -EFAULT : 0;
	case V4L2_BUF_TYPE_META_CAPTURE:
	case V4L2_BUF_TYPE_META_OUTPUT:
		return copy_from_user(&p64->fmt.meta, &p128->fmt.meta,
				      sizeof(p64->fmt.meta)) ? -EFAULT : 0;
	default:
		return -EINVAL;
	}
}

static int get_v4l2_create128(struct v4l2_create_buffers *p64,
			     struct v4l2_create_buffers128 __user *p128)
{
	if (copy_from_user(p64, p128,
			   offsetof(struct v4l2_create_buffers128, format)))
		return -EFAULT;
	if (copy_from_user(&p64->flags, &p128->flags, sizeof(p128->flags)))
		return -EFAULT;
	return get_v4l2_format128(&p64->format, &p128->format);
}

static int put_v4l2_format128(struct v4l2_format *p64,
			     struct v4l2_format128 __user *p128)
{
	set_max_u_border();
	switch (p64->type) {
	case V4L2_BUF_TYPE_VIDEO_CAPTURE:
	case V4L2_BUF_TYPE_VIDEO_OUTPUT:
		return copy_to_user(&p128->fmt.pix, &p64->fmt.pix,
				    sizeof(p64->fmt.pix)) ? -EFAULT : 0;
	case V4L2_BUF_TYPE_VIDEO_CAPTURE_MPLANE:
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_MPLANE:
		return copy_to_user(&p128->fmt.pix_mp, &p64->fmt.pix_mp,
				    sizeof(p64->fmt.pix_mp)) ? -EFAULT : 0;
	case V4L2_BUF_TYPE_VIDEO_OVERLAY:
	case V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY:
		return put_v4l2_window128(&p64->fmt.win, &p128->fmt.win);
	case V4L2_BUF_TYPE_VBI_CAPTURE:
	case V4L2_BUF_TYPE_VBI_OUTPUT:
		return copy_to_user(&p128->fmt.vbi, &p64->fmt.vbi,
				    sizeof(p64->fmt.vbi)) ? -EFAULT : 0;
	case V4L2_BUF_TYPE_SLICED_VBI_CAPTURE:
	case V4L2_BUF_TYPE_SLICED_VBI_OUTPUT:
		return copy_to_user(&p128->fmt.sliced, &p64->fmt.sliced,
				    sizeof(p64->fmt.sliced)) ? -EFAULT : 0;
	case V4L2_BUF_TYPE_SDR_CAPTURE:
	case V4L2_BUF_TYPE_SDR_OUTPUT:
		return copy_to_user(&p128->fmt.sdr, &p64->fmt.sdr,
				    sizeof(p64->fmt.sdr)) ? -EFAULT : 0;
	case V4L2_BUF_TYPE_META_CAPTURE:
	case V4L2_BUF_TYPE_META_OUTPUT:
		return copy_to_user(&p128->fmt.meta, &p64->fmt.meta,
				    sizeof(p64->fmt.meta)) ? -EFAULT : 0;
	default:
		return -EINVAL;
	}
}

static int put_v4l2_create128(struct v4l2_create_buffers *p64,
			     struct v4l2_create_buffers128 __user *p128)
{
	set_max_u_border();
	if (copy_to_user(p128, p64,
			 offsetof(struct v4l2_create_buffers128, format)) ||
	    put_user(p64->capabilities, &p128->capabilities) ||
	    put_user(p64->flags, &p128->flags) ||
	    copy_to_user(p128->reserved, p64->reserved, sizeof(p64->reserved)))
		return -EFAULT;
	return put_v4l2_format128(&p64->format, &p128->format);
}


struct v4l2_buffer128 {
	__u32			index;
	__u32			type;	/* enum v4l2_buf_type */
	__u32			bytesused;
	__u32			flags;
	__u32			field;	/* enum v4l2_field */
	struct __kernel_v4l2_timeval timestamp;
	struct v4l2_timecode	timecode;
	__u32			sequence;

	/* memory location */
	__u32			memory;	/* enum v4l2_memory */
	union {
		__u32           offset;
		unsigned long   userptr;
		e2k_ap_t  planes; /* (struct v4l2_plane *planes) */
		__s32		fd;
	} m;
	__u32			length;
	__u32			reserved2;
	__s32			request_fd;
};


static int get_v4l2_buffer128(struct v4l2_buffer *vb,
			     struct v4l2_buffer128 __user *arg)
{
	struct v4l2_buffer128 vb128;

	if (copy_from_user(&vb128, arg, sizeof(vb128)))
		return -EFAULT;

	memset(vb, 0, sizeof(*vb));
	*vb = (struct v4l2_buffer) {
		.index		= vb128.index,
		.type		= vb128.type,
		.bytesused	= vb128.bytesused,
		.flags		= vb128.flags,
		.field		= vb128.field,
		.timestamp	= vb128.timestamp,
		.timecode	= vb128.timecode,
		.sequence	= vb128.sequence,
		.memory		= vb128.memory,
		.m.offset	= vb128.m.offset,
		.length		= vb128.length,
		.request_fd	= vb128.request_fd,
	};

	switch (vb->memory) {
	case V4L2_MEMORY_MMAP:
	case V4L2_MEMORY_OVERLAY:
		vb->m.offset = vb128.m.offset;
		break;
	case V4L2_MEMORY_USERPTR:
		vb->m.userptr = vb128.m.userptr;
		break;
	case V4L2_MEMORY_DMABUF:
		vb->m.fd = vb128.m.fd;
		break;
	}

	if (V4L2_TYPE_IS_MULTIPLANAR(vb->type)) {
		e2k_ap_t ap;
		int tag;
		if (get_user_tagged_16(ap.qword, tag, &arg->m.planes) ||
		    !IS_AP(ap, tag) || AP_OBJ_SIZE(ap) < vb128.length * sizeof(struct v4l2_plane))
			return -EFAULT;
		vb->m.planes = (void __force *)AP_PTR(ap);
		set_ap_u_border(ap);
	}
	return 0;
}

static int put_v4l2_buffer128(struct v4l2_buffer *vb,
			     struct v4l2_buffer128 __user *arg)
{
	struct v4l2_buffer128 vb128;
	e2k_ap_t ap;
	int tag;

	set_max_u_border();
	memset(&vb128, 0, sizeof(vb128));
	vb128 = (struct v4l2_buffer128) {
		.index		= vb->index,
		.type		= vb->type,
		.bytesused	= vb->bytesused,
		.flags		= vb->flags,
		.field		= vb->field,
		.timestamp	= vb->timestamp,
		.timecode	= vb->timecode,
		.sequence	= vb->sequence,
		.memory		= vb->memory,
		.m.offset	= vb->m.offset,
		.length		= vb->length,
		.request_fd	= vb->request_fd,
	};

	switch (vb->memory) {
	case V4L2_MEMORY_MMAP:
	case V4L2_MEMORY_OVERLAY:
		vb128.m.offset = vb->m.offset;
		break;
	case V4L2_MEMORY_USERPTR:
		vb128.m.userptr = vb->m.userptr;
		break;
	case V4L2_MEMORY_DMABUF:
		vb128.m.fd = vb->m.fd;
		break;
	}

	if (V4L2_TYPE_IS_MULTIPLANAR(vb->type)) {
		if (get_user_tagged_16(ap.qword, tag, &arg->m.planes))
			return -EFAULT;
	}

	if (copy_to_user(arg, &vb128, sizeof(vb128)))
		return -EFAULT;

	if (V4L2_TYPE_IS_MULTIPLANAR(vb->type)) {
		if (put_user_tagged_16(ap.qword, tag, &arg->m.planes))
			return -EFAULT;
	}
	return 0;
}

struct v4l2_framebuffer128 {
	__u32			capability;
	__u32			flags;
	e2k_ap_t		base;
	struct {
		__u32		width;
		__u32		height;
		__u32		pixelformat;
		__u32		field;
		__u32		bytesperline;
		__u32		sizeimage;
		__u32		colorspace;
		__u32		priv;
	} fmt;
};

static int get_v4l2_framebuffer128(struct v4l2_framebuffer *p64,
				  struct v4l2_framebuffer128 __user *p128)
{
	e2k_ap_t	ap;
	int		tag;

	if (get_user_tagged_16(ap.qword, tag, &p128->base) ||
	    get_user(p64->capability, &p128->capability) ||
	    get_user(p64->flags, &p128->flags) ||
	    copy_from_user(&p64->fmt, &p128->fmt, sizeof(p64->fmt)))
		return -EFAULT;
	p64->base = (void __force *)AP_PTR(ap);

	return 0;
}

static int put_v4l2_framebuffer128(struct v4l2_framebuffer *p64,
				  struct v4l2_framebuffer128 __user *p128)
{
	e2k_ap_t ap = MAKE_AP(p64->base, 0);
	if (put_user_tagged_16(ap.qword, 0, &p128->base) ||
	    put_user(p64->capability, &p128->capability) ||
	    put_user(p64->flags, &p128->flags) ||
	    copy_to_user(&p128->fmt, &p64->fmt, sizeof(p64->fmt)))
		return -EFAULT;

	return 0;
}


struct v4l2_ext_controls128 {
	__u32 which;
	__u32 count;
	__u32 error_idx;
	__s32 request_fd;
	__u32 reserved[1];
	e2k_ap_t controls; /* actually struct v4l2_ext_control128 * */
};

struct v4l2_ext_control128 {
	__u32 id;
	__u32 size;
	__u32 reserved2[1];
	union {
		__s32 value;
		__s64 value64;
		e2k_ap_t string; /* actually char * */
	};
} __attribute__ ((packed));

/* Return true if this control is a pointer type. */
static inline bool ctrl_is_pointer(struct file *file, u32 id)
{
	struct video_device *vdev = video_devdata(file);
	struct v4l2_fh *fh = NULL;
	struct v4l2_ctrl_handler *hdl = NULL;
	struct v4l2_query_ext_ctrl qec = { id };
	const struct v4l2_ioctl_ops *ops = vdev->ioctl_ops;

	if (test_bit(V4L2_FL_USES_V4L2_FH, &vdev->flags))
		fh = file->private_data;

	if (fh && fh->ctrl_handler)
		hdl = fh->ctrl_handler;
	else if (vdev->ctrl_handler)
		hdl = vdev->ctrl_handler;

	if (hdl) {
		struct v4l2_ctrl *ctrl = v4l2_ctrl_find(hdl, id);

		return ctrl && ctrl->is_ptr;
	}

	if (!ops || !ops->vidioc_query_ext_ctrl)
		return false;

	return !ops->vidioc_query_ext_ctrl(file, fh, &qec) &&
		(qec.flags & V4L2_CTRL_FLAG_HAS_PAYLOAD);
}

static int get_v4l2_ext_controls128(struct v4l2_ext_controls *p64,
				   struct v4l2_ext_controls128 __user *p128)
{
	struct v4l2_ext_controls128 ec128;
	e2k_ap_t ap;
	int tag;

	if (copy_from_user(&ec128, p128, sizeof(ec128)))
		return -EFAULT;
	if (get_user_tagged_16(ap.qword, tag, &p128->controls) ||
	    !IS_AP(ap, tag) || AP_OBJ_SIZE(ap) < ec128.count * sizeof(struct v4l2_ext_control128))
		return -EFAULT;

	*p64 = (struct v4l2_ext_controls) {
		.which		= ec128.which,
		.count		= ec128.count,
		.error_idx	= ec128.error_idx,
		.request_fd	= ec128.request_fd,
		.reserved[0]	= ec128.reserved[0],
		.controls	= (void __force *)AP_PTR(ap),
	};
	set_ap_u_border(ap);
	return 0;
}

static int put_v4l2_ext_controls128(struct v4l2_ext_controls *p64,
				   struct v4l2_ext_controls128 __user *p128)
{
	set_max_u_border();
	if (copy_to_user(p128, p64, offsetof(struct v4l2_ext_controls128, reserved)) ||
	    put_user(p64->reserved[0], &p128->reserved[0]))
		return -EFAULT;

	return 0;
}



struct v4l2_edid128 {
	__u32 pad;
	__u32 start_block;
	__u32 blocks;
	__u32 reserved[5];
	e2k_ap_t  edid;
};

static int get_v4l2_edid128(struct v4l2_edid *p64,
			   struct v4l2_edid128 __user *p128)
{
	e2k_ap_t ap;
	int tag;

	if (copy_from_user(p64, p128, offsetof(struct v4l2_edid, edid)) ||
	    get_user_tagged_16(ap.qword, tag, &p128->edid) || !IS_AP(ap, tag))
		return -EFAULT;

	p64->edid = (void __force *)AP_PTR(ap);
	set_ap_u_border(ap);
	return 0;
}

static int put_v4l2_edid128(struct v4l2_edid *p64,
			   struct v4l2_edid128 __user *p128)
{
	set_max_u_border();
	if (copy_to_user(p128, p64, offsetof(struct v4l2_edid, edid)))
		return -EFAULT;
	return 0;
}

/*
 * List of ioctls that require 32-bits/64-bits conversion
 *
 * The V4L2 ioctls that aren't listed there don't have pointer arguments
 * and the struct size is identical for both 32 and 64 bits versions, so
 * they don't need translations.
 */

#define VIDIOC_G_FMT128		_IOWR('V',  4, struct v4l2_format128)
#define VIDIOC_S_FMT128		_IOWR('V',  5, struct v4l2_format128)
#define VIDIOC_QUERYBUF128	_IOWR('V',  9, struct v4l2_buffer128)
#define VIDIOC_G_FBUF128	_IOR('V', 10, struct v4l2_framebuffer128)
#define VIDIOC_S_FBUF128	_IOW('V', 11, struct v4l2_framebuffer128)
#define VIDIOC_QBUF128		_IOWR('V', 15, struct v4l2_buffer128)
#define VIDIOC_DQBUF128		_IOWR('V', 17, struct v4l2_buffer128)
#define VIDIOC_G_EDID128	_IOWR('V', 40, struct v4l2_edid128)
#define VIDIOC_S_EDID128	_IOWR('V', 41, struct v4l2_edid128)
#define VIDIOC_TRY_FMT128	_IOWR('V', 64, struct v4l2_format128)
#define VIDIOC_G_EXT_CTRLS128	_IOWR('V', 71, struct v4l2_ext_controls128)
#define VIDIOC_S_EXT_CTRLS128   _IOWR('V', 72, struct v4l2_ext_controls128)
#define VIDIOC_TRY_EXT_CTRLS128 _IOWR('V', 73, struct v4l2_ext_controls128)
#define VIDIOC_CREATE_BUFS128	_IOWR('V', 92, struct v4l2_create_buffers128)
#define VIDIOC_PREPARE_BUF128	_IOWR('V', 93, struct v4l2_buffer128)


unsigned int v4l2_ptr128_translate_cmd(unsigned int cmd)
{
	switch (cmd) {
	case VIDIOC_G_FMT128:
		return VIDIOC_G_FMT;
	case VIDIOC_S_FMT128:
		return VIDIOC_S_FMT;
	case VIDIOC_TRY_FMT128:
		return VIDIOC_TRY_FMT;
	case VIDIOC_G_FBUF128:
		return VIDIOC_G_FBUF;
	case VIDIOC_S_FBUF128:
		return VIDIOC_S_FBUF;
	case VIDIOC_QUERYBUF128:
		return VIDIOC_QUERYBUF;
	case VIDIOC_QBUF128:
		return VIDIOC_QBUF;
	case VIDIOC_DQBUF128:
		return VIDIOC_DQBUF;
	case VIDIOC_CREATE_BUFS128:
		return VIDIOC_CREATE_BUFS;
	case VIDIOC_G_EXT_CTRLS128:
		return VIDIOC_G_EXT_CTRLS;
	case VIDIOC_S_EXT_CTRLS128:
		return VIDIOC_S_EXT_CTRLS;
	case VIDIOC_TRY_EXT_CTRLS128:
		return VIDIOC_TRY_EXT_CTRLS;
	case VIDIOC_PREPARE_BUF128:
		return VIDIOC_PREPARE_BUF;
	case VIDIOC_G_EDID128:
		return VIDIOC_G_EDID;
	case VIDIOC_S_EDID128:
		return VIDIOC_S_EDID;
	}
	return cmd;
}

int v4l2_ptr128_get_user(void __user *arg, void *parg, unsigned int cmd)
{
	switch (cmd) {
	case VIDIOC_G_FMT128:
	case VIDIOC_S_FMT128:
	case VIDIOC_TRY_FMT128:
		return get_v4l2_format128(parg, arg);

	case VIDIOC_S_FBUF128:
		return get_v4l2_framebuffer128(parg, arg);
	case VIDIOC_QUERYBUF128:
	case VIDIOC_QBUF128:
	case VIDIOC_DQBUF128:
	case VIDIOC_PREPARE_BUF128:
		return get_v4l2_buffer128(parg, arg);

	case VIDIOC_G_EXT_CTRLS128:
	case VIDIOC_S_EXT_CTRLS128:
	case VIDIOC_TRY_EXT_CTRLS128:
		return get_v4l2_ext_controls128(parg, arg);

	case VIDIOC_CREATE_BUFS128:
		return get_v4l2_create128(parg, arg);

	case VIDIOC_G_EDID128:
	case VIDIOC_S_EDID128:
		return get_v4l2_edid128(parg, arg);
	}
	return 0;
}

int v4l2_ptr128_put_user(void __user *arg, void *parg, unsigned int cmd)
{
	switch (cmd) {
	case VIDIOC_G_FMT128:
	case VIDIOC_S_FMT128:
	case VIDIOC_TRY_FMT128:
		return put_v4l2_format128(parg, arg);

	case VIDIOC_G_FBUF128:
		return put_v4l2_framebuffer128(parg, arg);
	case VIDIOC_QUERYBUF128:
	case VIDIOC_QBUF128:
	case VIDIOC_DQBUF128:
	case VIDIOC_PREPARE_BUF128:
		return put_v4l2_buffer128(parg, arg);

	case VIDIOC_G_EXT_CTRLS128:
	case VIDIOC_S_EXT_CTRLS128:
	case VIDIOC_TRY_EXT_CTRLS128:
		return put_v4l2_ext_controls128(parg, arg);

	case VIDIOC_CREATE_BUFS128:
		return put_v4l2_create128(parg, arg);

	case VIDIOC_G_EDID128:
	case VIDIOC_S_EDID128:
		return put_v4l2_edid128(parg, arg);
	}
	return 0;
}

int v4l2_ptr128_get_array_args(struct file *file, void *mbuf,
			       void __user *user_ptr, size_t array_size,
			       unsigned int cmd, void *arg)
{
	int err = 0;

	memset(mbuf, 0, array_size);

	switch (cmd) {
	case VIDIOC_G_FMT128:
	case VIDIOC_S_FMT128:
	case VIDIOC_TRY_FMT128: {
		struct v4l2_format *f64 = arg;
		struct v4l2_clip *c64 = mbuf;
		struct v4l2_clip128 __user *c128 = user_ptr;
		u32 clipcount = f64->fmt.win.clipcount;

		if ((f64->type != V4L2_BUF_TYPE_VIDEO_OVERLAY &&
		     f64->type != V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY) ||
		    clipcount == 0)
			return 0;
		if (clipcount > 2048)
			return -EINVAL;
		while (clipcount--) {
			if (copy_from_user(c64, c128, sizeof(c64->c)))
				return -EFAULT;
			c64->next = NULL;
			c64++;
			c128++;
		}
		break;
	}
	case VIDIOC_QUERYBUF128:
	case VIDIOC_QBUF128:
	case VIDIOC_DQBUF128:
	case VIDIOC_PREPARE_BUF128: {
		struct v4l2_buffer *b64 = arg;
		struct v4l2_plane *p64 = mbuf;
		struct v4l2_plane __user *p128 = user_ptr;

		if (V4L2_TYPE_IS_MULTIPLANAR(b64->type)) {
			u32 num_planes = b64->length;

			if (num_planes == 0)
				return 0;

			while (num_planes--) {
				if (copy_from_user(p64, p128, sizeof(struct v4l2_plane)))
					return -EFAULT;
				++p64;
				++p128;
			}
		}
		break;
	}
	case VIDIOC_G_EXT_CTRLS128:
	case VIDIOC_S_EXT_CTRLS128:
	case VIDIOC_TRY_EXT_CTRLS128: {
		struct v4l2_ext_controls *ecs64 = arg;
		struct v4l2_ext_control *ec64 = mbuf;
		struct v4l2_ext_control128 __user *ec128 = user_ptr;
		int n;

		for (n = 0; n < ecs64->count; n++) {
			if (copy_from_user(ec64, ec128, sizeof(*ec64)))
				return -EFAULT;

			if (ctrl_is_pointer(file, ec64->id)) {
				e2k_ap_t ap;
				int tag;
				if (get_user_tagged_16(ap.qword, tag, &ec128->string) ||
				    !IS_AP(ap, tag))
					return -EFAULT;
				ec64->string = (void __user *)AP_PTR(ap);
			}
			ec128++;
			ec64++;
		}
		set_max_u_border(); /* many ptrs */
		break;
	}
	default:
		if (copy_from_user(mbuf, user_ptr, array_size))
			err = -EFAULT;
		break;
	}

	return err;
}

int v4l2_ptr128_put_array_args(struct file *file, void __user *user_ptr,
			       void *mbuf, size_t array_size,
			       unsigned int cmd, void *arg)
{
	int err = 0;

	set_max_u_border();
	switch (cmd) {
	case VIDIOC_G_FMT128:
	case VIDIOC_S_FMT128:
	case VIDIOC_TRY_FMT128: {
		struct v4l2_format *f64 = arg;
		struct v4l2_clip *c64 = mbuf;
		struct v4l2_clip128 __user *c128 = user_ptr;
		u32 clipcount = f64->fmt.win.clipcount;

		if ((f64->type != V4L2_BUF_TYPE_VIDEO_OVERLAY &&
		     f64->type != V4L2_BUF_TYPE_VIDEO_OUTPUT_OVERLAY) ||
		    clipcount == 0)
			return 0;
		if (clipcount > 2048)
			return -EINVAL;
		while (clipcount--) {
			if (copy_to_user(c128, c64, sizeof(c64->c)))
				return -EFAULT;
			c64++;
			c128++;
		}
		break;
	}
	case VIDIOC_QUERYBUF128:
	case VIDIOC_QBUF128:
	case VIDIOC_DQBUF128:
	case VIDIOC_PREPARE_BUF128: {
		struct v4l2_buffer *b64 = arg;
		struct v4l2_plane *p64 = mbuf;
		struct v4l2_plane __user *p128 = user_ptr;

		if (V4L2_TYPE_IS_MULTIPLANAR(b64->type)) {
			u32 num_planes = b64->length;

			if (num_planes == 0)
				return 0;

			while (num_planes--) {
				if (copy_to_user(p128, p64, sizeof(struct v4l2_plane)))
					return -EFAULT;
				++p64;
				++p128;
			}
		}
		break;
	}
	case VIDIOC_G_EXT_CTRLS128:
	case VIDIOC_S_EXT_CTRLS128:
	case VIDIOC_TRY_EXT_CTRLS128: {
		struct v4l2_ext_controls *ecs64 = arg;
		struct v4l2_ext_control *ec64 = mbuf;
		struct v4l2_ext_control128 __user *ec128 = user_ptr;
		int n;

		for (n = 0; n < ecs64->count; n++) {
			unsigned int size = sizeof(*ec64);
			/*
			 * Do not modify the pointer when copying a pointer
			 * control.  The contents of the pointer was changed,
			 * not the pointer itself.
			 * The structures are otherwise compatible.
			 */
			if (ctrl_is_pointer(file, ec64->id))
				size = offsetof(struct v4l2_ext_control, value64);

			if (copy_to_user(ec128, ec64, size))
				return -EFAULT;

			ec128++;
			ec64++;
		}
		break;
	}
	default:
		if (copy_to_user(user_ptr, mbuf, array_size))
			err = -EFAULT;
		break;
	}

	return err;
}

/**
 * v4l2_ptr128_ioctl128() - Handles a ptr128 ioctl call
 *
 * @file: pointer to &struct file with the file handler
 * @cmd: ioctl to be called
 * @arg: arguments passed from/to the ioctl handler
 *
 * This function is meant to be used as .ptr128_ioctl fops at v4l2-dev.c
 * in order to deal with 128-bit ptr calls on a 64-bits Kernel.
 *
 * This function calls do_video_ioctl() for non-private V4L2 ioctls.
 * If the function is a private one it calls vdev->fops->ptr128_ioctl32
 * instead.
 */
long v4l2_ptr128_ioctl(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct video_device *vdev = video_devdata(file);
	long ret = -ENOIOCTLCMD;

	if (!file->f_op->unlocked_ioctl)
		return ret;

	if (!video_is_registered(vdev))
		return -ENODEV;

	if (_IOC_TYPE(cmd) == 'V' && _IOC_NR(cmd) < BASE_VIDIOC_PRIVATE)
		ret = file->f_op->unlocked_ioctl(file, cmd, arg);
	else if (vdev->fops->ptr128_ioctl)
		ret = vdev->fops->ptr128_ioctl(file, cmd, arg);

	if (ret == -ENOIOCTLCMD)
		pr_debug("compat_ioctl32: unknown ioctl '%c', dir=%d, #%d (0x%08x)\n",
			 _IOC_TYPE(cmd), _IOC_DIR(cmd), _IOC_NR(cmd), cmd);
	return ret;
}
EXPORT_SYMBOL_GPL(v4l2_ptr128_ioctl);
