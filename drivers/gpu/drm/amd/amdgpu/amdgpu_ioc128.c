/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <drm/amdgpu_drm.h>
#include <drm/drm_ioctl.h>

#include "amdgpu_drv.h"

long amdgpu_kms_ptr128_ioctl(struct file *filp, unsigned int cmd, unsigned long arg)
{
	unsigned int nr = DRM_IOCTL_NR(cmd);

	if (nr < DRM_COMMAND_BASE)
		return drm_ptr128_ioctl(filp, cmd, arg);

	return amdgpu_drm_ioctl(filp, cmd, arg);
}
