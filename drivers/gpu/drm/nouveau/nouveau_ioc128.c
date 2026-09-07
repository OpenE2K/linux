/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <drm/drm.h>
#include <drm/drm_ioctl.h>

#include "nouveau_ioctl.h"

/**
 * Called whenever a 128-bit ptr process running under a 64-bit kernel
 * performs an ioctl on /dev/dri/card<n>.
 *
 * \param filp file pointer.
 * \param cmd command.
 * \param arg user argument.
 * \return zero on success or negative number on failure.
 */
long nouveau_ptr128_ioctl(struct file *filp, unsigned int cmd,
			 unsigned long arg)
{
	unsigned int nr = DRM_IOCTL_NR(cmd);

	if (nr < DRM_COMMAND_BASE)
		return drm_ptr128_ioctl(filp, cmd, arg);

	return nouveau_drm_ioctl(filp, cmd, arg);
}
