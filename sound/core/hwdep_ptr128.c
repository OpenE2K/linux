/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * 128bit ptr  -> 64bit ptr ioctl wrapper for hwdep API
 *
 * This file is included from hwdep.c
 */

#include <asm/e2k_ptypes.h>

struct snd_hwdep_dsp_image128 {
	unsigned int index;
	unsigned char name[64];
	e2k_ap_t image;	/* pointer */
	size_t length;
	unsigned long driver_data;
} /* don't set packed attribute here */;

static int snd_hwdep_dsp_load_ptr128(struct snd_hwdep *hw,
				     struct snd_hwdep_dsp_image128 __user *src)
{
	struct snd_hwdep_dsp_image info = {};
	e2k_ap_t ap;
	int tag;
	if (copy_from_user(&info, src, sizeof(unsigned int) + 64) ||
	    get_user(info.length, &src->length) ||
	    get_user(info.driver_data, &src->driver_data))
		return -EFAULT;
	if (get_user_tagged_16(ap.qword, tag, &src->image) || !IS_AP(ap, tag))
		return -EFAULT;
	info.image = U_AP_PTR(ap);
	set_ap_u_border(ap);

	return snd_hwdep_dsp_load(hw, &info);
}

enum {
	SNDRV_HWDEP_IOCTL_DSP_LOAD128   = _IOW('H', 0x03, struct snd_hwdep_dsp_image128)
};

static long snd_hwdep_ioctl_ptr128(struct file *file, unsigned int cmd,
				   unsigned long arg)
{
	struct snd_hwdep *hw = file->private_data;
	switch (cmd) {
	case SNDRV_HWDEP_IOCTL_PVERSION:
	case SNDRV_HWDEP_IOCTL_INFO:
	case SNDRV_HWDEP_IOCTL_DSP_STATUS:
		return snd_hwdep_ioctl(file, cmd, arg);
	case SNDRV_HWDEP_IOCTL_DSP_LOAD128:
		return snd_hwdep_dsp_load_ptr128(hw, (void __user *)arg);
	}
	if (hw->ops.ioctl_compat)
		return hw->ops.ioctl_compat(hw, file, cmd, arg);
	return -ENOIOCTLCMD;
}
