/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * 128bit ptr -> 64bit ptr ioctl wrapper for PCM API
 *
 * This file included from pcm_native.c
 */

#include <asm/e2k_ptypes.h>

/*
 */
struct snd_xferi128 {
	snd_pcm_sframes_t result;
	e2k_ap_t buf;
	snd_pcm_sframes_t frames;
};

static int snd_pcm_ioctl_xferi_ptr128(struct snd_pcm_substream *substream,
				      int dir, struct snd_xferi128 __user *data128)
{
	e2k_ap_t	ap;
	int		tag;
	u64		saved_u_border = get_u_border();
	snd_pcm_sframes_t frames;
	void __user *buf;
	int err;

	if (!substream->runtime)
		return -ENOTTY;
	if (substream->stream != dir)
		return -EINVAL;
	if (substream->runtime->state == SNDRV_PCM_STATE_OPEN)
		return -EBADFD;

	if (get_user(frames, &data128->frames))
		return -EFAULT;
	if (get_user_tagged_16(ap.qword, tag, &data128->buf) || !IS_AP(ap, tag))
		return -EFAULT;
	buf = U_AP_PTR(ap);
	set_ap_u_border(ap);
	if (dir == SNDRV_PCM_STREAM_PLAYBACK)
		err = snd_pcm_lib_write(substream, buf, frames);
	else
		err = snd_pcm_lib_read(substream, buf, frames);
	if (err < 0)
		return err;
	/* copy the result */
	set_u_border(saved_u_border);
	if (put_user(err, &data128->result))
		return -EFAULT;
	return 0;
}


/* snd_xfern needs remapping of bufs */
struct snd_xfern128 {
	snd_pcm_sframes_t result;
	e2k_ap_t bufs;  /* this is void **; */
	snd_pcm_sframes_t frames;
};

/*
 * xfern ioctl nees to copy (up to) 128 pointers on stack.
 * although we may pass the copied pointers through f_op->ioctl, but the ioctl
 * handler there expands again the same 128 pointers on stack, so it is better
 * to handle the function (calling pcm_readv/writev) directly in this handler.
 */
static int snd_pcm_ioctl_xfern_ptr128(struct snd_pcm_substream *substream,
				      int dir, struct snd_xfern128 __user *data128)
{
	e2k_ap_t  __user *bufptr;
	e2k_ap_t	ap;
	int		tag;
	u64 saved_u_border = get_u_border();
	u32 frames;
	void __user **bufs;
	int err, ch, i;

	if (!substream->runtime)
		return -ENOTTY;
	if (substream->stream != dir)
		return -EINVAL;
	if (substream->runtime->state == SNDRV_PCM_STATE_OPEN)
		return -EBADFD;

	ch = substream->runtime->channels;
	if (ch > 128)
		return -EINVAL;


	if (get_user(frames, &data128->frames))
		return -EFAULT;
	if (get_user_tagged_16(ap.qword, tag, &data128->bufs) || !IS_AP(ap, tag)) {
		return -EFAULT;
	}
	bufptr = U_AP_PTR(ap);

	bufs = kmalloc_array(ch, sizeof(void __user *), GFP_KERNEL);
	if (bufs == NULL)
		return -ENOMEM;
	set_ap_u_border(ap);
	for (i = 0; i < ch; i++) {
		if (get_user_tagged_16(ap.qword, tag, bufptr)) {
			kfree(bufs);
			return -EFAULT;
		}
		bufs[i] = IS_AP(ap, tag) ? U_AP_PTR(ap) : NULL;
		bufptr++;
	}
	/* Too complex, turn off checking */
	set_u_border(MAX_U_BORDER);
	if (dir == SNDRV_PCM_STREAM_PLAYBACK)
		err = snd_pcm_lib_writev(substream, bufs, frames);
	else
		err = snd_pcm_lib_readv(substream, bufs, frames);
	set_u_border(saved_u_border);
	if (err >= 0) {
		if (put_user(err, &data128->result))
			err = -EFAULT;
	}
	kfree(bufs);
	return err;
}

enum {
	SNDRV_PCM_IOCTL_WRITEI_FRAMES128 = _IOW('A', 0x50, struct snd_xferi128),
	SNDRV_PCM_IOCTL_READI_FRAMES128 = _IOR('A', 0x51, struct snd_xferi128),
	SNDRV_PCM_IOCTL_WRITEN_FRAMES128 = _IOW('A', 0x52, struct snd_xfern128),
	SNDRV_PCM_IOCTL_READN_FRAMES128 = _IOR('A', 0x53, struct snd_xfern128),
};

static long snd_pcm_ioctl_ptr128(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct snd_pcm_file *pcm_file;
	struct snd_pcm_substream *substream;
	void __user *argp = compat_ptr(arg);

	pcm_file = file->private_data;
	if (!pcm_file)
		return -ENOTTY;
	substream = pcm_file->substream;
	if (!substream)
		return -ENOTTY;

	/*
	 * When PCM is used on 32bit mode, we need to disable
	 * mmap of the old PCM status/control records because
	 * of the size incompatibility.
	 */
	pcm_file->no_compat_mmap = 1;

	switch (cmd) {
	case SNDRV_PCM_IOCTL_PVERSION:
	case SNDRV_PCM_IOCTL_INFO:
	case SNDRV_PCM_IOCTL_TSTAMP:
	case SNDRV_PCM_IOCTL_TTSTAMP:
	case SNDRV_PCM_IOCTL_USER_PVERSION:
	case SNDRV_PCM_IOCTL_HWSYNC:
	case SNDRV_PCM_IOCTL_PREPARE:
	case SNDRV_PCM_IOCTL_RESET:
	case SNDRV_PCM_IOCTL_START:
	case SNDRV_PCM_IOCTL_DROP:
	case SNDRV_PCM_IOCTL_DRAIN:
	case SNDRV_PCM_IOCTL_PAUSE:
	case SNDRV_PCM_IOCTL_HW_FREE:
	case SNDRV_PCM_IOCTL_RESUME:
	case SNDRV_PCM_IOCTL_XRUN:
	case SNDRV_PCM_IOCTL_LINK:
	case SNDRV_PCM_IOCTL_UNLINK:
	case __SNDRV_PCM_IOCTL_SYNC_PTR64:
	case SNDRV_PCM_IOCTL_HW_REFINE:
	case SNDRV_PCM_IOCTL_HW_PARAMS:
	case SNDRV_PCM_IOCTL_SW_PARAMS:
	case SNDRV_PCM_IOCTL_STATUS32:
	case SNDRV_PCM_IOCTL_STATUS_EXT32:
	case SNDRV_PCM_IOCTL_STATUS64:
	case SNDRV_PCM_IOCTL_STATUS_EXT64:
	case SNDRV_PCM_IOCTL_CHANNEL_INFO:
	case SNDRV_PCM_IOCTL_DELAY:
	case SNDRV_PCM_IOCTL_REWIND:
	case SNDRV_PCM_IOCTL_FORWARD:
		return snd_pcm_common_ioctl(file, substream, cmd, argp);
	case SNDRV_PCM_IOCTL_WRITEI_FRAMES128:
		return snd_pcm_ioctl_xferi_ptr128(substream, SNDRV_PCM_STREAM_PLAYBACK, argp);
	case SNDRV_PCM_IOCTL_READI_FRAMES128:
		return snd_pcm_ioctl_xferi_ptr128(substream, SNDRV_PCM_STREAM_CAPTURE, argp);
	case SNDRV_PCM_IOCTL_WRITEN_FRAMES:
		return snd_pcm_ioctl_xfern_ptr128(substream, SNDRV_PCM_STREAM_PLAYBACK, argp);
	case SNDRV_PCM_IOCTL_READN_FRAMES32:
		return snd_pcm_ioctl_xfern_ptr128(substream, SNDRV_PCM_STREAM_CAPTURE, argp);
	}

	return -ENOIOCTLCMD;
}
