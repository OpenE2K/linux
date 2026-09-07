/*
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2023 MCST
 */

#ifndef	_UAPI_E2K_KEXEC_H_
#define	_UAPI_E2K_KEXEC_H_

#include <linux/ioctl.h>
#include <linux/types.h>

#define	E2K_KEXEC_IOCTL_BASE	'E'

struct kexec_reboot_param {
	char	__user *cmdline;
	int	cmdline_size;
	void	__user *image;
	__u64	image_size;
	void	*initrd;
	__u64	initrd_size;
};

struct lintel_reboot_param {
	void	*image;
	__u64	image_size;
};

#define	KEXEC_REBOOT  _IOR(E2K_KEXEC_IOCTL_BASE, 0, struct kexec_reboot_param)
#define	LINTEL_REBOOT _IOR(E2K_KEXEC_IOCTL_BASE, 0, struct lintel_reboot_param)

#endif
