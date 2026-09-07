/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/e2k_ptypes.h>
#include "mga_drv.h"


typedef struct {
	int param;
	e2k_ap_t value; /* (void __user *) */
} drm_mga_getparam128_t;

static int ptr128_mga_getparam(struct file *file, unsigned int cmd,
			       unsigned long arg)
{
	drm_mga_getparam_t getparam;
	drm_mga_getparam128_t __user *gp128 = (drm_mga_getparam128_t __user *)arg;
	int err;
	e2k_ap_t ap;
	int tag;
	u64 saved_ub = get_u_border();

	if (get_user(getparam.param, &gp128->param, sizeof(getparam.param)))
		return -EFAULT;
	if (get_user_tagged_16(ap.qword, tag, &gp128->value) || !IS_AP(ap, tag))
		return -EFAULT;
	getparam.value = (void __user *)AP_PTR(ap);
	set_ap_u_border(ap);
	err = drm_ioctl_kernel(file, mga_getparam, &getparam, DRM_AUTH);
	set_u_border(saved_ub);
	return err;
}

static struct {
	drm_ioctl_compat_t *fn;
	char *name;
} mga_ptr128_ioctls[] = {
#define DRM_IOCTL128_DEF(n, f)	([DRM_##n] = {.fn = f, .name = #n})
	DRM_IOCTL128_DEF(MGA_GETPARAM, ptr128_mga_getparam),
};

/**
 * mga_compat_ioctl - Called whenever a 32-bit process running under
 *                    a 64-bit kernel performs an ioctl on /dev/dri/card<n>.
 *
 * @filp: file pointer.
 * @cmd:  command.
 * @arg:  user argument.
 * return: zero on success or negative number on failure.
 */
long mga_ptr128_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	unsigned int nr = DRM_IOCTL_NR(cmd);
	struct drm_file *file_priv = filp->private_data;
	drm_ioctl_compat_t *fn = NULL;
	int ret;

	if (nr < DRM_COMMAND_BASE)
		return drm_ptr128_ioctl(filp, cmd, arg);

	if (nr >= DRM_COMMAND_BASE + ARRAY_SIZE(mga_ptr128_ioctls))
		return drm_ioctl(filp, cmd, arg);

	fn = mga_ptr128_ioctls[nr - DRM_COMMAND_BASE].fn;
	if (!fn)
		return drm_ioctl(filp, cmd, arg);

	DRM_DEBUG("pid=%d, dev=0x%lx, auth=%d, %s\n",
		  task_pid_nr(current),
		  (long)old_encode_dev(file_priv->minor->kdev->devt),
		  file_priv->authenticated,
		  mga_ptr128_ioctls[nr - DRM_COMMAND_BASE].name);
	ret = (*fn) (filp, cmd, arg);
	if (ret)
		DRM_DEBUG("ret = %d\n", ret);
	return ret;
}
