/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * ptr128 ioctls for control API
 *
 * this file included from control.c
 */

#include <asm/e2k_ptypes.h>

struct snd_ctl_elem_list128 {
	u32 offset;
	u32 space;
	u32 used;
	u32 count;
	e2k_ap_t pids;
	unsigned char reserved[50];
} /* don't set packed attribute here */;

static int snd_ctl_elem_list_ptr128(struct snd_card *card,
				    struct snd_ctl_elem_list128 __user *data128)
{
	struct snd_ctl_elem_list data = {};
	e2k_ap_t ap;
	int tag;
	u64 saved_u_border;
	int err;

	/* offset, space, used, count */
	if (copy_from_user(&data, data128, 4 * sizeof(u32)))
		return -EFAULT;
	/* pids */
	if (get_user_tagged_16(ap.qword, tag, &data128->pids) || !IS_AP(ap, tag))
		return -EFAULT;
	data.pids = (struct snd_ctl_elem_id __user *)AP_PTR(ap);
	saved_u_border = get_u_border();
	set_ap_u_border(ap);
	err = snd_ctl_elem_list(card, &data);
	set_u_border(saved_u_border);
	if (err < 0)
		return err;
	/* copy the result */
	if (copy_to_user(data128, &data, 4 * sizeof(u32)))
		return -EFAULT;
	return 0;
}

/*
 * control element info
 */
static int snd_ctl_elem_info_ptr128(struct snd_ctl_file *ctl,
				    struct snd_ctl_elem_info __user *datap)
{
	u64 saved_u_border = get_u_border();
	int err;

	set_u_border(MAX_U_BORDER);
	err = snd_ctl_elem_info_user(ctl, datap);
	set_u_border(saved_u_border);
	return err;
}


/* add or replace a user control */
static int snd_ctl_elem_add_ptr128(struct snd_ctl_file *file,
				   struct snd_ctl_elem_info __user *datap,
				   int replace)
{
	struct snd_ctl_elem_info data;
	u64 saved_u_border = get_u_border();
	int err;

	if (copy_from_user(&data, datap, sizeof(data)))
		return -EFAULT;
	set_u_border(MAX_U_BORDER);
	err = snd_ctl_elem_add(file, &data, replace);
	set_u_border(saved_u_border);
	return err;
}

enum {
	SNDRV_CTL_IOCTL_ELEM_LIST128 = _IOWR('U', 0x10, struct snd_ctl_elem_list128),
};

static inline long snd_ctl_ioctl_ptr128(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct snd_ctl_file *ctl;
	struct snd_kctl_ioctl *p;
	void __user *argp = (void __user *)arg;
	int err;

	ctl = file->private_data;
	if (snd_BUG_ON(!ctl || !ctl->card))
		return -ENXIO;

	switch (cmd) {
	case SNDRV_CTL_IOCTL_PVERSION:
	case SNDRV_CTL_IOCTL_CARD_INFO:
	case SNDRV_CTL_IOCTL_SUBSCRIBE_EVENTS:
	case SNDRV_CTL_IOCTL_POWER:
	case SNDRV_CTL_IOCTL_POWER_STATE:
	case SNDRV_CTL_IOCTL_ELEM_LOCK:
	case SNDRV_CTL_IOCTL_ELEM_UNLOCK:
	case SNDRV_CTL_IOCTL_ELEM_REMOVE:
	case SNDRV_CTL_IOCTL_TLV_READ:
	case SNDRV_CTL_IOCTL_TLV_WRITE:
	case SNDRV_CTL_IOCTL_TLV_COMMAND:
	case SNDRV_CTL_IOCTL_ELEM_READ:
	case SNDRV_CTL_IOCTL_ELEM_WRITE:
		return snd_ctl_ioctl(file, cmd, (unsigned long)argp);
	case SNDRV_CTL_IOCTL_ELEM_LIST128:
		return snd_ctl_elem_list_ptr128(ctl->card, argp);
	case SNDRV_CTL_IOCTL_ELEM_INFO:
		return snd_ctl_elem_info_ptr128(ctl, argp);
	case SNDRV_CTL_IOCTL_ELEM_ADD:
		return snd_ctl_elem_add_ptr128(ctl, argp, 0);
	case SNDRV_CTL_IOCTL_ELEM_REPLACE:
		return snd_ctl_elem_add_ptr128(ctl, argp, 1);
	default:
		break;
	}

	down_read(&snd_ioctl_rwsem);
	list_for_each_entry(p, &snd_control_ptr128_ioctls, list) {
		if (p->fioctl) {
			err = p->fioctl(ctl->card, ctl, cmd, arg);
			if (err != -ENOIOCTLCMD) {
				up_read(&snd_ioctl_rwsem);
				return err;
			}
		}
	}
	up_read(&snd_ioctl_rwsem);
	return -ENOIOCTLCMD;
}
