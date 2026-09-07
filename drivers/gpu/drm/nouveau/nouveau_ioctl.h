/* SPDX-License-Identifier: MIT */
#ifndef __NOUVEAU_IOCTL_H__
#define __NOUVEAU_IOCTL_H__

long nouveau_compat_ioctl(struct file *, unsigned int cmd, unsigned long arg);
long nouveau_drm_ioctl(struct file *, unsigned int cmd, unsigned long arg);
#if defined(CONFIG_E2K) && defined(CONFIG_PROTECTED_MODE)
long nouveau_ptr128_ioctl(struct file *, unsigned int cmd, unsigned long arg);
#endif
#endif
