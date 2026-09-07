/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * 128bit ptr -> 64bit ioctl wrapper for sequencer API
 *
 * This file included from seq.c
 */

#include <linux/compat.h>
#include <linux/slab.h>
#include <asm/e2k_ptypes.h>
struct snd_seq_port_info128 {
	struct snd_seq_addr addr;	/* client/port numbers */
	char name[64];			/* port name */

	u32 capability;			/* port capability bits */
	u32 type;			/* port type bits */
	s32 midi_channels;		/* channels per MIDI port */
	s32 midi_voices;		/* voices per MIDI port */
	s32 synth_voices;		/* voices per SYNTH port */

	s32 read_use;			/* R/O: subscribers for output (from this port) */
	s32 write_use;			/* R/O: subscribers for input (to this port) */

	e2k_ap_t kernel;		/* reserved for kernel use (must be NULL) */
	u32 flags;			/* misc. conditioning */
	unsigned char time_queue;	/* queue # for timestamping */
	char reserved[59];		/* for future use */
};

static int snd_seq_call_ptr128_info_ioctl(struct snd_seq_client *client, unsigned int cmd,
					struct snd_seq_port_info128 __user *data128p)
{
	int err = -EFAULT;
	struct snd_seq_port_info data;


	if (copy_from_user(&data, data128p, sizeof(data)) ||
	    get_user(data.flags, &data128p->flags) ||
	    get_user(data.time_queue, &data128p->time_queue))
		goto error;
	data.kernel = NULL;

	err = snd_seq_kernel_client_ctl(client->number, cmd, &data);
	if (err < 0)
		goto error;

	if (copy_to_user(data128p, &data, sizeof(data)) ||
	    put_user(data.flags, &data128p->flags) ||
	    put_user(data.time_queue, &data128p->time_queue))
		err = -EFAULT;

 error:
	return err;
}




enum {
	SNDRV_SEQ_IOCTL_CREATE_PORT128 = _IOWR('S', 0x20, struct snd_seq_port_info128),
	SNDRV_SEQ_IOCTL_DELETE_PORT128 = _IOW('S', 0x21, struct snd_seq_port_info128),
	SNDRV_SEQ_IOCTL_GET_PORT_INFO128 = _IOWR('S', 0x22, struct snd_seq_port_info128),
	SNDRV_SEQ_IOCTL_SET_PORT_INFO128 = _IOW('S', 0x23, struct snd_seq_port_info128),
	SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT128 = _IOWR('S', 0x52, struct snd_seq_port_info128),
};

static long snd_seq_ioctl_ptr128(struct file *file, unsigned int cmd, unsigned long arg)
{
	struct snd_seq_client *client = file->private_data;
	void __user *argp = (void __user *)arg;

	if (snd_BUG_ON(!client))
		return -ENXIO;

	switch (cmd) {
	case SNDRV_SEQ_IOCTL_PVERSION:
	case SNDRV_SEQ_IOCTL_CLIENT_ID:
	case SNDRV_SEQ_IOCTL_SYSTEM_INFO:
	case SNDRV_SEQ_IOCTL_GET_CLIENT_INFO:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_INFO:
	case SNDRV_SEQ_IOCTL_SUBSCRIBE_PORT:
	case SNDRV_SEQ_IOCTL_UNSUBSCRIBE_PORT:
	case SNDRV_SEQ_IOCTL_CREATE_QUEUE:
	case SNDRV_SEQ_IOCTL_DELETE_QUEUE:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_INFO:
	case SNDRV_SEQ_IOCTL_GET_NAMED_QUEUE:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_STATUS:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TEMPO:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TEMPO:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_TIMER:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_TIMER:
	case SNDRV_SEQ_IOCTL_GET_QUEUE_CLIENT:
	case SNDRV_SEQ_IOCTL_SET_QUEUE_CLIENT:
	case SNDRV_SEQ_IOCTL_GET_CLIENT_POOL:
	case SNDRV_SEQ_IOCTL_SET_CLIENT_POOL:
	case SNDRV_SEQ_IOCTL_REMOVE_EVENTS:
	case SNDRV_SEQ_IOCTL_QUERY_SUBS:
	case SNDRV_SEQ_IOCTL_GET_SUBSCRIPTION:
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_CLIENT:
	case SNDRV_SEQ_IOCTL_RUNNING_MODE:
		return snd_seq_ioctl(file, cmd, arg);
	case SNDRV_SEQ_IOCTL_CREATE_PORT128:
		return snd_seq_call_ptr128_info_ioctl(client, SNDRV_SEQ_IOCTL_CREATE_PORT, argp);
	case SNDRV_SEQ_IOCTL_DELETE_PORT128:
		return snd_seq_call_ptr128_info_ioctl(client, SNDRV_SEQ_IOCTL_DELETE_PORT, argp);
	case SNDRV_SEQ_IOCTL_GET_PORT_INFO128:
		return snd_seq_call_ptr128_info_ioctl(client, SNDRV_SEQ_IOCTL_GET_PORT_INFO, argp);
	case SNDRV_SEQ_IOCTL_SET_PORT_INFO128:
		return snd_seq_call_ptr128_info_ioctl(client, SNDRV_SEQ_IOCTL_SET_PORT_INFO, argp);
	case SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT128:
		return snd_seq_call_ptr128_info_ioctl(client,
						      SNDRV_SEQ_IOCTL_QUERY_NEXT_PORT, argp);
	}
	return -ENOIOCTLCMD;
}
