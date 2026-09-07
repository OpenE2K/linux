/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/ratelimit.h>
#include <linux/export.h>

#include <drm/drm_file.h>
#include <drm/drm_print.h>

#include "drm_crtc_internal.h"
#include "drm_internal.h"
#include "drm_legacy.h"
#include <asm/e2k_ptypes.h>


#define DRM_IOCTL_VERSION128		DRM_IOWR(0x00, drm_version128_t)
#define DRM_IOCTL_GET_UNIQUE128		DRM_IOWR(0x01, drm_unique128_t)
#define DRM_IOCTL_GET_MAP128		DRM_IOWR(0x04, drm_map128_t)

#define DRM_IOCTL_SET_UNIQUE128		DRM_IOW(0x10, drm_unique128_t)
#define DRM_IOCTL_ADD_MAP128		DRM_IOWR(0x15, drm_map128_t)
#define DRM_IOCTL_INFO_BUFS128		DRM_IOWR(0x18, drm_buf_info128_t)
#define DRM_IOCTL_MAP_BUFS128		DRM_IOWR(0x19, drm_buf_map128_t)
#define DRM_IOCTL_FREE_BUFS128		DRM_IOW(0x1a, drm_buf_free128_t)

#define DRM_IOCTL_RM_MAP128		DRM_IOW(0x1b, drm_map128_t)

#define DRM_IOCTL_SET_SAREA_CTX128	DRM_IOW(0x1c, drm_ctx_priv_map128_t)
#define DRM_IOCTL_GET_SAREA_CTX128	DRM_IOWR(0x1d, drm_ctx_priv_map128_t)

#define DRM_IOCTL_RES_CTX128		DRM_IOWR(0x26, drm_ctx_res128_t)
#define DRM_IOCTL_DMA128		DRM_IOWR(0x29, drm_dma128_t)

typedef struct {
	int version_major;		/**< Major version */
	int version_minor;		/**< Minor version */
	int version_patchlevel;		/**< Patch level */
	__kernel_size_t name_len;	/**< Length of name buffer */
	e2k_ap_t	name;		/**< Name of driver */
	__kernel_size_t date_len;	/**< Length of date buffer */
	e2k_ap_t	date;		/**< User-space buffer to hold date */
	__kernel_size_t desc_len;	/**< Length of desc buffer */
	e2k_ap_t	desc;	/**< User-space buffer to hold desc */
} drm_version128_t;

static int ptr128_drm_version(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	drm_version128_t __user *v128p = (drm_version128_t __user *)arg;
	struct drm_version v;
	e2k_ap_t ap;
	int tag;
	int err;

	/* version_major, version_minor, version_patchlevel */
	if (copy_from_user(&v, (void __user *)arg, 3 * sizeof(int)))
		return -EFAULT;

	if (get_user(v.name_len, &v128p->name_len))
		return -EFAULT;
	if (v.name_len) {
		if (get_user_tagged_16(ap.qword, tag, &v128p->name) || !IS_AP(ap, tag))
			return -EFAULT;
		v.name = (char __user *)AP_PTR(ap);
	} else {
		v.name = NULL;
	}

	if (get_user(v.date_len, &v128p->date_len))
		return -EFAULT;
	if (v.date_len) {
		if (get_user_tagged_16(ap.qword, tag, &v128p->date) || !IS_AP(ap, tag))
			return -EFAULT;
		v.date = (char __user *)AP_PTR(ap);
	} else {
		v.date = NULL;
	}

	if (get_user(v.desc_len, &v128p->desc_len))
		return -EFAULT;
	if (v.desc_len) {
		if (get_user_tagged_16(ap.qword, tag, &v128p->desc) || !IS_AP(ap, tag))
			return -EFAULT;
		v.desc = (char __user *)AP_PTR(ap);
	} else {
		v.desc = NULL;
	}

	set_u_border(MAX_U_BORDER);
	err = drm_ioctl_kernel(file, drm_version, &v,
			       DRM_RENDER_ALLOW);
	if (err)
		return err;

	if (put_user(v.version_major, &v128p->version_major) ||
	    put_user(v.version_minor, &v128p->version_minor) ||
	    put_user(v.version_patchlevel, &v128p->version_patchlevel) ||
	    put_user(v.name_len, &v128p->name_len) ||
	    put_user(v.date_len, &v128p->date_len) ||
	    put_user(v.desc_len, &v128p->desc_len))
		return -EFAULT;
	return 0;
}



typedef struct  {
	__kernel_size_t unique_len;	/**< Length of unique */
	e2k_ap_t	unique;		/**< Unique name for driver instantiation */
} drm_unique128_t;


static int ptr128_drm_getunique(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	drm_unique128_t __user *uq128p = (drm_unique128_t __user *)arg;
	struct drm_unique uq;
	e2k_ap_t ap;
	int tag;
	int err;

	if (get_user(uq.unique_len, &uq128p->unique_len))
		return -EFAULT;
	if (uq.unique_len) {
		if (get_user_tagged_16(ap.qword, tag, &uq128p->unique) || !IS_AP(ap, tag))
			return -EFAULT;
		uq.unique = (char __user *)AP_PTR(ap);
	} else {
		 uq.unique = NULL;
	}


	set_u_border(MAX_U_BORDER);
	err = drm_ioctl_kernel(file, drm_getunique, &uq, 0);
	if (err)
		return err;

	if (put_user(uq.unique_len, &uq128p->unique_len))
		return -EFAULT;
	return 0;
}

static int ptr128_drm_setunique(struct file *file, unsigned int cmd,
				unsigned long arg)
{
	/* it's dead */
	return -EINVAL;
}

#if IS_ENABLED(CONFIG_DRM_LEGACY)

typedef struct {
	unsigned long offset;	/**< Requested physical address (0 for SAREA)*/
	unsigned long size;		/**< Requested physical size (bytes) */
	enum drm_map_type type;		/**< Type of memory to map */
	enum drm_map_flags flags;	/**< Flags */
	e2k_ap_t handle;		/**< User-space: "Handle" to pass to mmap()
					   < Kernel-space: kernel-virtual address */
	int mtrr;			/**< MTRR slot used */
} drm_map128_t;




static int ptr128_drm_getmap(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	drm_map128_t __user *argp = (void __user *)arg;
	drm_map128_t m128;
	struct drm_map map;
	int err;

	if (get_user(map.offset, &argp->offset))
		return -EFAULT;

	err = drm_ioctl_kernel(file, drm_legacy_getmap_ioctl, &map, 0);
	if (err)
		return err;

	m128.offset = map.offset;
	m128.size = map.size;
	m128.type = map.type;
	m128.flags = map.flags;
	m128.handle = MAKE_AP(map.handle, 0);
	m128.mtrr = map.mtrr;
	if (copy_to_user(argp, &m128, sizeof(m128)))
		return -EFAULT;
	return 0;

}

static int ptr128_drm_addmap(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	drm_map128_t __user *argp = (void __user *)arg;
	drm_map128_t m128;
	struct drm_map map;
	int err;

	if (copy_from_user(&m128, argp, sizeof(m128)))
		return -EFAULT;

	map.offset = m128.offset;
	map.size = m128.size;
	map.type = m128.type;
	map.flags = m128.flags;

	err = drm_ioctl_kernel(file, drm_legacy_addmap_ioctl, &map,
				DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY);
	if (err)
		return err;

	m128.offset = map.offset;
	m128.mtrr = map.mtrr;
	m128.handle = MAKE_AP(map.handle, 0);

	if (copy_to_user(argp, &m128, sizeof(m128)))
		return -EFAULT;

	return 0;
}

static int ptr128_drm_rmmap(struct file *file, unsigned int cmd,
			    unsigned long arg)
{
	drm_map128_t __user *argp = (void __user *)arg;
	struct drm_map map;
	int tag;
	e2k_ap_t handle;

	if (get_user_tagged_16(handle.qword, tag, &argp->handle))
		return -EFAULT;
	map.handle = (void *)AP_PTR(handle);
	return drm_ioctl_kernel(file, drm_legacy_rmmap_ioctl, &map, DRM_AUTH);
}
#endif


#if IS_ENABLED(CONFIG_DRM_LEGACY)

typedef struct {
	int count;		/**< Entries in list */
	e2k_ap_t list;
} drm_buf_info128_t;

static int copy_one_buf128(void *data, int count, struct drm_buf_entry *from)
{
	e2k_ap_t ap = *((e2k_ap_t *)data);
	u64 saved_u_border = get_u_border();
	struct drm_buf_desc __user *to;
	struct drm_buf_desc v = {.count = from->buf_count,
				 .size = from->buf_size,
				 .low_mark = from->low_mark,
				 .high_mark = from->high_mark};
	to = (struct drm_buf_desc __user *)AP_PTR(ap);
	set_u_border(AP_PTR(ap) + AP_OBJ_SIZE(ap));
	if (copy_to_user(to + count, &v, offsetof(struct drm_buf_desc, flags))) {
		set_u_border(saved_u_border);
		return -EFAULT;
	}
	set_u_border(saved_u_border);
	return 0;
}

static int drm_legacy_infobufs128(struct drm_device *dev, void *data,
			struct drm_file *file_priv)
{
	drm_buf_info128_t *bi128p = data;

	return __drm_legacy_infobufs(dev, &bi128p->list, &bi128p->count, copy_one_buf128);
}

static int ptr128_drm_infobufs(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	drm_buf_info128_t bi128;
	drm_buf_info128_t __user *argp = (void __user *)arg;
	e2k_ap_t ap;
	int tag;
	int err;

	if (copy_from_user(&bi128, argp, sizeof(bi128)))
		return -EFAULT;

	if (bi128.count < 0)
		bi128.count = 0;
	if (bi128.count) {
		if (get_user_tagged_16(ap.qword, tag, &argp->list) || !IS_AP(ap, tag))
			return -EFAULT;
	} else {
		bi128.list = (e2k_ap_t){ 0 };
	}
	err = drm_ioctl_kernel(file, drm_legacy_infobufs128, &bi128, DRM_AUTH);
	if (err)
		return err;

	if (put_user(bi128.count, &argp->count))
		return -EFAULT;

	return 0;
}

typedef struct  {
	int idx;		/**< Index into the master buffer list */
	int total;		/**< Buffer size */
	int used;		/**< Amount of buffer in use (for DMA) */
	e2k_ap_t address;	/**< Address of buffer> void __user * */
} drm_buf_pub128_t;

typedef struct drm_buf_map32 {
	int count;		/**< Length of the buffer list */
	e2k_ap_t virtual;	/**< Mmap'd area in user-virtual */
	e2k_ap_t list;		/**< Buffer information struct drm_buf_pub __user * */
} drm_buf_map128_t;

static int map_one_buf128(void *data, int idx, unsigned long virtual,
			struct drm_buf *buf)
{
	struct drm_buf_map *request = data;
	drm_buf_pub128_t __user *to = (drm_buf_pub128_t __user *)(request->list) + idx;
	drm_buf_pub128_t v;
	int tag;

	v.idx = buf->idx;
	v.total = buf->total;
	v.used = 0;
	if (copy_to_user(to, &v, 3 * sizeof(int)))
		return -EFAULT;
	MAKE_TAGGED_AP(v.address, tag, virtual + buf->offset, buf->total);
	if (put_user_tagged_16(v.address.qword, tag, &to->address))
		return -EFAULT;
	return 0;
}

static int drm_legacy_mapbufs128(struct drm_device *dev, void *data,
				 struct drm_file *file_priv)
{
	struct drm_buf_map *request = data;
	int err = __drm_legacy_mapbufs(dev, data, &request->count,
				    &request->virtual, map_one_buf128,
				    file_priv);
	return err;
}

static int ptr128_drm_mapbufs(struct file *file, unsigned int cmd,
			      unsigned long arg)
{
	drm_buf_map128_t __user *argp = (void __user *)arg;
	drm_buf_map128_t req128;
	struct drm_buf_map req64;
	e2k_ap_t ap;
	int	 tag;
	u64 saved_ub = get_u_border();
	int err;

	if (copy_from_user(&req128, argp, sizeof(req128)))
		return -EFAULT;
	if (req128.count < 0)
		return -EINVAL;
	if (get_user_tagged_16(ap.qword, tag, &argp->list))
		return -EFAULT;
	if (IS_AP(ap, tag)) {
		set_u_border(AP_PTR(ap) + AP_OBJ_SIZE(ap));
	} else {
		req128.list = (e2k_ap_t){ 0 };
		set_u_border(0);
	}
	req64.count = req128.count;

	err = drm_ioctl_kernel(file, drm_legacy_mapbufs128, &req64, DRM_AUTH);
	if (err)
		return err;

	set_u_border(saved_ub);
	if (put_user(req128.count, &argp->count))
		return -EFAULT;
	MAKE_TAGGED_AP(req128.virtual, tag, req64.virtual, req128.count * sizeof(drm_buf_pub128_t));
	if (put_user_tagged_16(req128.virtual.qword, tag, &argp->virtual))
		return -EFAULT;

	return 0;
}

typedef struct {
	int count;
	e2k_ap_t list;	/* int __user * */
} drm_buf_free128_t;

static int ptr128_drm_freebufs(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	struct drm_buf_free request;
	drm_buf_free128_t __user *argp = (void __user *)arg;
	e2k_ap_t ap;
	int tag;

	if (get_user(request.count, &argp->count))
		return -EFAULT;
	if (get_user_tagged_16(ap.qword, tag, &argp->list) || !IS_AP(ap, tag))
		return -EFAULT;
	request.list = (void __user *)AP_PTR(ap);
	set_u_border(AP_PTR(ap) + AP_OBJ_SIZE(ap));
	return drm_ioctl_kernel(file, drm_legacy_freebufs, &request, DRM_AUTH);
}

typedef struct {
	unsigned int ctx_id;	 /**< Context requesting private mapping */
	e2k_ap_t handle;		/**< Handle of map (void *) */
} drm_ctx_priv_map128_t;

static int ptr128_drm_setsareactx(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	drm_ctx_priv_map128_t req128;
	struct drm_ctx_priv_map request;
	drm_ctx_priv_map128_t __user *argp = (void __user *)arg;

	if (copy_from_user(&req128, argp, sizeof(req128)))
		return -EFAULT;

	request.ctx_id = req128.ctx_id;
	request.handle = (void *)AP_PTR(req128.handle);
	return drm_ioctl_kernel(file, drm_legacy_setsareactx, &request,
				DRM_AUTH|DRM_MASTER|DRM_ROOT_ONLY);
}

static int ptr128_drm_getsareactx(struct file *file, unsigned int cmd,
				  unsigned long arg)
{
	struct drm_ctx_priv_map req;
	drm_ctx_priv_map128_t __user *argp = (void __user *)arg;
	int err;
	e2k_ap_t ap;
	int tag;

	if (get_user(req.ctx_id, &argp->ctx_id))
		return -EFAULT;

	err = drm_ioctl_kernel(file, drm_legacy_getsareactx, &req, DRM_AUTH);
	if (err)
		return err;

	MAKE_TAGGED_AP(ap, tag, req.handle, 0);
	if (put_user_tagged_16(ap.qword, 0, &argp->handle))
		return -EFAULT;

	return 0;
}

typedef struct {
	int count;
	e2k_ap_t contexts;	/* struct drm_ctx __user * */
} drm_ctx_res128_t;

static int ptr128_drm_resctx(struct file *file, unsigned int cmd,
			     unsigned long arg)
{
	drm_ctx_res128_t __user *argp = (void __user *)arg;
	struct drm_ctx_res res;
	drm_ctx_res128_t res128;
	int err;

	if (copy_from_user(&res128, argp, sizeof(res128)))
		return -EFAULT;

	res.count = res128.count;
	res.contexts = (struct drm_ctx __user *)AP_PTR(res128.contexts);
	err = drm_ioctl_kernel(file, drm_legacy_resctx, &res, DRM_AUTH);
	if (err)
		return err;

	res128.count = res.count;
	if (put_user(res128.count, &argp->count))
		return -EFAULT;

	return 0;
}


typedef struct  {
	int context;			/* Context handle */
	int send_count;			/* Number of buffers to send */
	e2k_ap_t send_indices;		/* (int __user *) List of handles to buffers */
	e2k_ap_t send_sizes;		/* (int __user *)  Lengths of data to send */
	enum drm_dma_flags flags;	/* Flags */
	int request_count;		/* Number of buffers requested */
	int request_size;		/* Desired size for buffers */
	e2k_ap_t request_indices;	/* (int __user *)  Buffer information */
	e2k_ap_t request_sizes;		/* int __user * */
	int granted_count;		/*  Number of buffers granted */
} drm_dma128_t;

static int ptr128_drm_dma(struct file *file, unsigned int cmd,
			  unsigned long arg)
{
	drm_dma128_t d128;
	drm_dma128_t __user *argp = (void __user *)arg;
	struct drm_dma d;
	e2k_ap_t ap;
	int tag;
	int err;

	if (copy_from_user(&d128, argp, sizeof(d128)))
		return -EFAULT;

	d.context = d128.context;
	d.send_count = d128.send_count;
	if (d.send_count) {
		if (get_user_tagged_16(ap.qword, tag, &argp->send_indices) || !IS_AP(ap, tag))
			return -EFAULT;
		if (AP_OBJ_SIZE(ap) < d.send_count * sizeof(int *))
			return -EFAULT;
		d.send_indices = (int __user *)AP_PTR(ap);
		if (get_user_tagged_16(ap.qword, tag, &argp->send_sizes) || !IS_AP(ap, tag))
			return -EFAULT;
		if (AP_OBJ_SIZE(ap) < d.send_count * sizeof(int *))
			return -EFAULT;
		d.send_sizes = (int __user *)AP_PTR(ap);
	} else {
		d.send_indices = NULL;
		d.send_sizes = NULL;
	}
	d.flags = d128.flags;
	d.request_count = d128.request_count;
	if (d.request_count) {
		if (get_user_tagged_16(ap.qword, tag, &argp->request_indices) || !IS_AP(ap, tag))
			return -EFAULT;
		if (AP_OBJ_SIZE(ap) < d.request_count * sizeof(int *))
			return -EFAULT;
		d.request_indices = (int __user *)AP_PTR(ap);
		if (get_user_tagged_16(ap.qword, tag, &argp->request_sizes) || !IS_AP(ap, tag))
			return -EFAULT;
		if (AP_OBJ_SIZE(ap) < d.send_count * sizeof(int *))
			return -EFAULT;
		d.request_sizes = (int __user *)AP_PTR(ap);
	} else {
		d.request_indices = NULL;
		d.request_sizes = NULL;
	}
	set_u_border(MAX_U_BORDER);
	err = drm_ioctl_kernel(file, drm_legacy_dma_ioctl, &d, DRM_AUTH);
	if (err)
		return err;

	if (put_user(d.request_size, &argp->request_size)
	    || put_user(d.granted_count, &argp->granted_count))
		return -EFAULT;

	return 0;
}
#endif


#define DRM_IOCTL128_DEF(n, f) [DRM_IOCTL_NR(n##128)] = {.fn = f, .name = #n}
static struct {
	drm_ioctl_compat_t *fn;
	char *name;
} drm_ptr128_ioctls[] = {
	DRM_IOCTL128_DEF(DRM_IOCTL_VERSION, ptr128_drm_version),
	DRM_IOCTL128_DEF(DRM_IOCTL_GET_UNIQUE, ptr128_drm_getunique),
#if IS_ENABLED(CONFIG_DRM_LEGACY)
	DRM_IOCTL128_DEF(DRM_IOCTL_GET_MAP, ptr128_drm_getmap),
#endif
	DRM_IOCTL128_DEF(DRM_IOCTL_SET_UNIQUE, ptr128_drm_setunique),
#if IS_ENABLED(CONFIG_DRM_LEGACY)
	DRM_IOCTL128_DEF(DRM_IOCTL_ADD_MAP, ptr128_drm_addmap),
	DRM_IOCTL128_DEF(DRM_IOCTL_INFO_BUFS, ptr128_drm_infobufs),
	DRM_IOCTL128_DEF(DRM_IOCTL_MAP_BUFS, ptr128_drm_mapbufs),
	DRM_IOCTL128_DEF(DRM_IOCTL_FREE_BUFS, ptr128_drm_freebufs),
	DRM_IOCTL128_DEF(DRM_IOCTL_RM_MAP, ptr128_drm_rmmap),
	DRM_IOCTL128_DEF(DRM_IOCTL_SET_SAREA_CTX, ptr128_drm_setsareactx),
	DRM_IOCTL128_DEF(DRM_IOCTL_GET_SAREA_CTX, ptr128_drm_getsareactx),
	DRM_IOCTL128_DEF(DRM_IOCTL_RES_CTX, ptr128_drm_resctx),
	DRM_IOCTL128_DEF(DRM_IOCTL_DMA, ptr128_drm_dma),
#endif
};

/**
 * drm_ptr128_ioctl - 128bit ptr IOCTL compatibility handler for DRM drivers
 * @filp: file this ioctl is called on
 * @cmd: ioctl cmd number
 * @arg: user argument
 *
 * Compatibility handler for 128 bit ptr userspace running on 64 kernels. All actual
 * IOCTL handling is forwarded to drm_ioctl(), while marshalling structures as
 * appropriate. Note that this only handles DRM core IOCTLs, if the driver has
 * botched IOCTL itself, it must handle those by wrapping this function.
 *
 * Returns:
 * Zero on success, negative error code on failure.
 */
long drm_ptr128_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	unsigned int nr = DRM_IOCTL_NR(cmd);
	struct drm_file *file_priv = filp->private_data;
	drm_ioctl_compat_t *fn;
	int ret;

	/* Assume that ioctls without an explicit compat routine will just
	 * work.  This may not always be a good assumption, but it's better
	 * than always failing.
	 */
	if (nr >= ARRAY_SIZE(drm_ptr128_ioctls))
		return drm_ioctl(filp, cmd, arg);

	fn = drm_ptr128_ioctls[nr].fn;
	if (!fn)
		return drm_ioctl(filp, cmd, arg);

	DRM_DEBUG("comm=\"%s\", pid=%d, dev=0x%lx, auth=%d, %s\n",
		  current->comm, task_pid_nr(current),
		  (long)old_encode_dev(file_priv->minor->kdev->devt),
		  file_priv->authenticated,
		  drm_ptr128_ioctls[nr].name);
	ret = (*fn)(filp, cmd, arg);
	if (ret)
		DRM_DEBUG("ret = %d\n", ret);
	return ret;
}
EXPORT_SYMBOL(drm_ptr128_ioctl);
