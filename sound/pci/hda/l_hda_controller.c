/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 *
 *  Implementation of primary alsa driver code base for MCST HD Audio.
 *
 */

#include <linux/clocksource.h>
#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>

#include <sound/core.h>
#include <sound/initval.h>
#include "hda_controller.h"
#include <sound/soc.h>
#include <linux/pci.h>

#define CREATE_TRACE_POINTS

/* DSP lock helpers */
#define dsp_lock(dev)		snd_hdac_dsp_lock(azx_stream(dev))
#define dsp_unlock(dev)		snd_hdac_dsp_unlock(azx_stream(dev))
#define dsp_is_locked(dev)	snd_hdac_stream_is_locked(azx_stream(dev))

/* assign a stream for the PCM */
static inline struct azx_dev *
azx_assign_device(struct azx *chip, struct snd_pcm_substream *substream)
{
	struct hdac_stream *s;

	s = snd_hdac_stream_assign(azx_bus(chip), substream);
	if (!s)
		return NULL;
	return stream_to_azx_dev(s);
}

/* release the assigned stream */
static inline void azx_release_device(struct azx_dev *azx_dev)
{
	snd_hdac_stream_release(azx_stream(azx_dev));
}

static inline struct hda_pcm_stream *
to_hda_pcm_stream(struct snd_pcm_substream *substream)
{
	struct azx_pcm *apcm = snd_pcm_substream_chip(substream);
	return &apcm->info->stream[substream->stream];
}

/*
 * DAI ops
 */
static void azx_hda_shutdown(struct snd_pcm_substream *substream,
                                            struct snd_soc_dai *dai)
{
	struct azx *chip = dai->dev->driver_data;
	struct azx_dev *azx_dev = get_azx_dev(substream);
	mutex_lock(&chip->open_mutex);
	azx_release_device(azx_dev);
	mutex_unlock(&chip->open_mutex);
}

static int azx_hda_hw_params(struct snd_pcm_substream *substream,
			     struct snd_pcm_hw_params *hw_params, struct snd_soc_dai *dai)
{
	struct azx_dev *azx_dev = get_azx_dev(substream);
	int ret;

	dsp_lock(azx_dev);
	if (dsp_is_locked(azx_dev)) {
		ret = -EBUSY;
		goto unlock;
	}

	azx_dev->core.bufsize = 0;
	azx_dev->core.period_bytes = 0;
	azx_dev->core.format_val = 0;
	ret = snd_pcm_lib_malloc_pages(substream,
				       params_buffer_bytes(hw_params));

unlock:
	dsp_unlock(azx_dev);
	return ret;
}

static int azx_hda_hw_free(struct snd_pcm_substream *substream,
                                        struct snd_soc_dai *dai)
{
	struct azx_dev *azx_dev = get_azx_dev(substream);
	int err;

	/* reset BDL address */
	dsp_lock(azx_dev);
	if (!dsp_is_locked(azx_dev))
		snd_hdac_stream_cleanup(azx_stream(azx_dev));

	err = snd_pcm_lib_free_pages(substream);
	azx_stream(azx_dev)->prepared = 0;
	dsp_unlock(azx_dev);
	return err;
}

#define STR(x) #x
#define SHOW_DEFINE(x) printk("%s=%s\n", #x, STR(x))

static unsigned int l_snd_hdac_make_cmd(u32 addr, hda_nid_t nid,
							unsigned int verb, unsigned int parm) {
	u32 val;
	if ((addr & ~0xf) || (nid & ~0x7f) ||
		(verb & ~0xfff) || (parm & ~0xffff)) {
		return -1;
	}
	val = addr << 28;
	val |= (u32)nid << 20;
	val |= verb << 8;
	val |= parm;
	return val;
}

static int azx_hda_prepare(struct snd_pcm_substream *substream,
                                           struct snd_soc_dai *dai)
{
	struct azx *chip = dai->dev->driver_data;
	struct azx_dev *azx_dev = get_azx_dev(substream);
	struct hda_pcm_stream *hinfo = to_hda_pcm_stream(substream);
	struct snd_pcm_runtime *runtime = substream->runtime;
	struct hdac_bus *bus = azx_dev->core.bus;
	unsigned int format_val, stream_tag;
	int err;
	unsigned int maxbps = 32;
	u8 strm = 0;
	u16 fmt = 0;
	u32 cmd;
	hda_nid_t nid;

	unsigned short ctls = 0;
	dsp_lock(azx_dev);
	if (dsp_is_locked(azx_dev)) {
		err = -EBUSY;
		goto unlock;
	}

	snd_hdac_stream_reset(azx_stream(azx_dev));
	format_val = snd_hdac_calc_stream_format(runtime->rate,
						runtime->channels,
						runtime->format,
						maxbps,
						ctls);
	SHOW_DEFINE(rtd->format);
	if (!format_val) {
		dev_err(&chip->pci->dev,
			"invalid format_val, rate=%d, ch=%d, format=%d\n",
			runtime->rate, runtime->channels, runtime->format);
		err = -EINVAL;
		goto unlock;
	}

	err = snd_hdac_stream_set_params(azx_stream(azx_dev), format_val);
	if (err < 0)
		goto unlock;

	snd_hdac_stream_setup(azx_stream(azx_dev));

	stream_tag = azx_dev->core.stream_tag;
	/* CA-IBG chips need the playback stream starting from 1 */
	if ((chip->driver_caps & AZX_DCAPS_CTX_WORKAROUND) &&
	    stream_tag > chip->capture_streams)
		stream_tag -= chip->capture_streams;

	/* hack for setting string id and format for input/output convertor */
	nid = (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) ? 0x2 : 0x4;

	if (runtime->rate == 44100) {
		fmt |= 1<<14;
	}
	switch (snd_pcm_format_width(runtime->format)) {
	case 16:
		fmt |= 1<<4;
		break;
	case 20:
		fmt |= 2<<4;
		break;
	case 24:
		fmt |= 3<<4;
		break;
	case 32:
		fmt |= 4<<4;
	default:
        break;
	}
	if (runtime->channels > 0 && runtime->channels <= 16) {
		fmt |= (runtime->channels - 1);
	}

	strm = stream_tag << 4;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		strm |= 1;

	cmd = l_snd_hdac_make_cmd(0x0, nid, AC_VERB_SET_CHANNEL_STREAMID, strm);

	/* set stream id for input converter */
	mutex_lock(&bus->cmd_mutex);
	err = snd_hdac_bus_exec_verb_unlocked(bus, 0x0, cmd, NULL);
	mutex_unlock(&bus->cmd_mutex);
	if (err)
		goto unlock;

	cmd = l_snd_hdac_make_cmd(0x0, nid, AC_VERB_SET_STREAM_FORMAT, fmt);

	/* set format for input conveter */
	mutex_lock(&bus->cmd_mutex);
	err = snd_hdac_bus_exec_verb_unlocked(bus, 0x0, cmd, NULL);
	mutex_unlock(&bus->cmd_mutex);

 unlock:
	if (!err)
		azx_stream(azx_dev)->prepared = 1;
	dsp_unlock(azx_dev);
	return err;
}

static int azx_hda_trigger(struct snd_pcm_substream *substream, int cmd,
				struct snd_soc_dai *dai)
{
	struct azx *chip = dai->dev->driver_data;
	struct hdac_bus *bus = azx_bus(chip);
	struct azx_dev *azx_dev;
	struct snd_pcm_substream *s;
	struct hdac_stream *hstr;
	bool start;
	int sbits = 0;
	int sync_reg;

	azx_dev = get_azx_dev(substream);

	hstr = azx_stream(azx_dev);
	if (chip->driver_caps & AZX_DCAPS_OLD_SSYNC)
		sync_reg = AZX_REG_OLD_SSYNC;
	else
		sync_reg = AZX_REG_SSYNC;

	if (dsp_is_locked(azx_dev) || !hstr->prepared)
	{
		return -EPIPE;
	}
	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
	case SNDRV_PCM_TRIGGER_PAUSE_RELEASE:
	case SNDRV_PCM_TRIGGER_RESUME:
		start = true;
		break;
	case SNDRV_PCM_TRIGGER_PAUSE_PUSH:
	case SNDRV_PCM_TRIGGER_SUSPEND:
	case SNDRV_PCM_TRIGGER_STOP:
		start = false;
		break;
	default:
		return -EINVAL;
	}

	snd_pcm_group_for_each_entry(s, substream) {
		if (s->pcm->card != substream->pcm->card)
			continue;
		azx_dev = get_azx_dev(s);
		sbits |= 1 << azx_dev->core.index;
		snd_pcm_trigger_done(s, substream);
	}

	spin_lock(&bus->reg_lock);

	/* first, set SYNC bits of corresponding streams */
	snd_hdac_stream_sync_trigger(hstr, true, sbits, sync_reg);

	snd_pcm_group_for_each_entry(s, substream) {
		if (s->pcm->card != substream->pcm->card)
			continue;
		azx_dev = get_azx_dev(s);
		if (start) {
			azx_dev->insufficient = 1;
			snd_hdac_stream_start(azx_stream(azx_dev), true);
		} else {
			snd_hdac_stream_stop(azx_stream(azx_dev));
		}
	}
	spin_unlock(&bus->reg_lock);

	snd_hdac_stream_sync(hstr, start, sbits);

	spin_lock(&bus->reg_lock);
	/* reset SYNC bits */
	snd_hdac_stream_sync_trigger(hstr, false, sbits, sync_reg);
	if (start)
		snd_hdac_stream_timecounter_init(hstr, sbits);
	spin_unlock(&bus->reg_lock);
	return 0;
}

unsigned int azx_get_pos_lpib(struct azx *chip, struct azx_dev *azx_dev)
{
	return snd_hdac_stream_get_pos_lpib(azx_stream(azx_dev));
}

unsigned int azx_get_pos_posbuf(struct azx *chip, struct azx_dev *azx_dev)
{
	return snd_hdac_stream_get_pos_posbuf(azx_stream(azx_dev));
}

unsigned int azx_get_position(struct azx *chip,
			      struct azx_dev *azx_dev)
{
	struct snd_pcm_substream *substream = azx_dev->core.substream;
	unsigned int pos;
	int stream = substream->stream;
	int delay = 0;

	if (chip->get_position[stream])
	{
		pos = chip->get_position[stream](chip, azx_dev);
	}
	else /* use the position buffer as default */
	{
		pos = azx_get_pos_posbuf(chip, azx_dev);
	}

	if (pos >= azx_dev->core.bufsize)
	{
		pos = 0;
	}

	if (substream->runtime) {

		if (chip->get_delay[stream]){
			delay += chip->get_delay[stream](chip, azx_dev, pos);
		}
		substream->runtime->delay = delay;
	}

	return pos;
}

static snd_pcm_uframes_t azx_pcm_pointer(struct snd_soc_component *component,
					 struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = snd_pcm_substream_chip(substream);
	struct snd_soc_dai *cpu_dai = asoc_rtd_to_cpu(rtd, 0);
	struct azx *chip = cpu_dai->dev->driver_data;
	struct azx_dev *azx_dev = get_azx_dev(substream);
	return bytes_to_frames(substream->runtime,
			       azx_get_position(chip, azx_dev));
}

static struct snd_pcm_hardware azx_pcm_hw = {
	.info =			(SNDRV_PCM_INFO_MMAP |
				 SNDRV_PCM_INFO_INTERLEAVED |
				 SNDRV_PCM_INFO_BLOCK_TRANSFER |
				 SNDRV_PCM_INFO_MMAP_VALID |
				 /* No full-resume yet implemented */
				 /* SNDRV_PCM_INFO_RESUME |*/
				 SNDRV_PCM_INFO_PAUSE |
				 SNDRV_PCM_INFO_SYNC_START |
				 SNDRV_PCM_INFO_HAS_WALL_CLOCK | /* legacy */
				 SNDRV_PCM_INFO_HAS_LINK_ATIME |
				 SNDRV_PCM_INFO_NO_PERIOD_WAKEUP),
	.formats =		SNDRV_PCM_FMTBIT_S16_LE,
	.rates =		SNDRV_PCM_RATE_48000,
	.rate_min =		48000,
	.rate_max =		48000,
	.channels_min =		2,
	.channels_max =		2,
	.buffer_bytes_max =	AZX_MAX_BUF_SIZE,
	.period_bytes_min =	128,
	.period_bytes_max =	AZX_MAX_BUF_SIZE / 2,
	.periods_min =		2,
	.periods_max =		AZX_MAX_FRAG,
	.fifo_size =		0,
};

#define MAX_PREALLOC_SIZE (32 * 1024 * 1024)
static int azx_hda_startup(struct snd_pcm_substream *substream,
                                        struct snd_soc_dai *dai)
{
	struct hda_pcm_stream *hinfo = to_hda_pcm_stream(substream);
	struct azx *chip = dai->dev->driver_data;
	struct azx_dev *azx_dev;
	struct snd_pcm_runtime *runtime = substream->runtime;
	int err;
	int buff_step;

	unsigned int size;
	int type = SNDRV_DMA_TYPE_DEV_SG;

	mutex_lock(&chip->open_mutex);
	azx_dev = azx_assign_device(chip, substream);
	if (azx_dev == NULL) {
		err = -EBUSY;
		goto unlock;
	}
	runtime->private_data = azx_dev;

	runtime->hw = azx_pcm_hw;
	if (chip->gts_present)
		runtime->hw.info |= SNDRV_PCM_INFO_HAS_LINK_SYNCHRONIZED_ATIME;
	snd_pcm_hw_constraint_integer(runtime, SNDRV_PCM_HW_PARAM_PERIODS);

	/* avoid wrap-around with wall-clock */
	snd_pcm_hw_constraint_minmax(runtime, SNDRV_PCM_HW_PARAM_BUFFER_TIME,
				     20,
				     178000000);

	/* by some reason, the playback stream stalls on PulseAudio with
	 * tsched=1 when a capture stream triggers.  Until we figure out the
	 * real cause, disable tsched mode by telling the PCM info flag.
	 */
	if (chip->driver_caps & AZX_DCAPS_AMD_WORKAROUND)
		runtime->hw.info |= SNDRV_PCM_INFO_BATCH;

	if (chip->align_buffer_size)
		/* constrain buffer sizes to be multiple of 128
		   bytes. This is more efficient in terms of memory
		   access but isn't required by the HDA spec and
		   prevents users from specifying exact period/buffer
		   sizes. For example for 44.1kHz, a period size set
		   to 20ms will be rounded to 19.59ms. */
		buff_step = 128;
	else
		/* Don't enforce steps on buffer sizes, still need to
		   be multiple of 4 bytes (HDA spec). Tested on Intel
		   HDA controllers, may not work on all devices where
		   option needs to be disabled */
		buff_step = 4;

	snd_pcm_hw_constraint_step(runtime, 0, SNDRV_PCM_HW_PARAM_BUFFER_BYTES,
				   buff_step);
	snd_pcm_hw_constraint_step(runtime, 0, SNDRV_PCM_HW_PARAM_PERIOD_BYTES,
				   buff_step);
	snd_pcm_limit_hw_rates(runtime);
	/* sanity check */
	if (snd_BUG_ON(!runtime->hw.channels_min) ||
	    snd_BUG_ON(!runtime->hw.channels_max) ||
	    snd_BUG_ON(!runtime->hw.formats) ||
	    snd_BUG_ON(!runtime->hw.rates)) {
		azx_release_device(azx_dev);
		err = -EINVAL;
		/*goto powerdown;*/
		goto unlock;
	}

	/* disable LINK_ATIME timestamps for capture streams
	   until we figure out how to handle digital inputs */
	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
		runtime->hw.info &= ~SNDRV_PCM_INFO_HAS_WALL_CLOCK; /* legacy */
		runtime->hw.info &= ~SNDRV_PCM_INFO_HAS_LINK_ATIME;
	}

	snd_pcm_set_sync(substream);
	mutex_unlock(&chip->open_mutex);

	/* buffer pre-allocation */
	size = CONFIG_SND_HDA_PREALLOC_SIZE * 1024;
	if (size > MAX_PREALLOC_SIZE)
		size = MAX_PREALLOC_SIZE;
	snd_pcm_lib_preallocate_pages(substream, type,
                    dai->dev, size, MAX_PREALLOC_SIZE);

	return 0;

 unlock:
	mutex_unlock(&chip->open_mutex);
	return err;
}

static int azx_pcm_mmap(struct snd_soc_component *component,
			struct snd_pcm_substream *substream,
			struct vm_area_struct *area)
{
	return snd_pcm_lib_default_mmap(substream, area);
}

static const struct snd_soc_dai_ops azx_soc_dai_ops = {
	.startup = azx_hda_startup,
	.shutdown = azx_hda_shutdown,
	.hw_params = azx_hda_hw_params,
	.hw_free = azx_hda_hw_free,
	.prepare = azx_hda_prepare,
	.trigger = azx_hda_trigger,
};

int azx_pcm_new(struct snd_soc_component *component,
		struct snd_soc_pcm_runtime *rtd)
{
	struct snd_card *card = rtd->card->snd_card;
	struct snd_pcm *pcm = rtd->pcm;
	unsigned int size;
	int type = SNDRV_DMA_TYPE_DEV_SG;

	size = CONFIG_SND_HDA_PREALLOC_SIZE * 1024;
	if (size > MAX_PREALLOC_SIZE)
		size = MAX_PREALLOC_SIZE;
	snd_pcm_lib_preallocate_pages_for_all(pcm, type,
							card->dev,
							size, MAX_PREALLOC_SIZE);

	return 0;
}

static struct snd_soc_component_driver azx_soc_dai_comp = {
	.name = "azx-soc-dai-component",
	.pointer = azx_pcm_pointer,
	.mmap = azx_pcm_mmap,
};

static struct snd_soc_dai_driver azx_soc_dai = {
		.name = "azx-soc-dai",
		.playback = {
			.stream_name = "Playback",
			.channels_min = 1,
			.channels_max = 6,
			.rates = SNDRV_PCM_RATE_48000,
			.formats = SNDRV_PCM_FMTBIT_S16_LE,
		},
		.capture = {
			.stream_name = "Capture",
			.channels_min = 1,
			.channels_max = 6,
			.rates = SNDRV_PCM_RATE_48000,
			.formats = SNDRV_PCM_FMTBIT_S16_LE,
		},
		.ops = &azx_soc_dai_ops,
};

int azx_pcm_platform_register(struct device *dev)
{
	return devm_snd_soc_register_component(dev, &azx_soc_dai_comp,
							&azx_soc_dai, 1);
}
EXPORT_SYMBOL(azx_pcm_platform_register);

/* receive a response */
static int azx_rirb_get_response(struct hdac_bus *bus, unsigned int addr,
				 unsigned int *res)
{
	struct azx *chip = bus_to_azx(bus);
	struct hda_bus *hbus = &chip->bus;
	unsigned long timeout;
	unsigned long loopcounter;
	int do_poll = 0;
	bool warned = false;

 again:
	timeout = jiffies + msecs_to_jiffies(1000);

	for (loopcounter = 0;; loopcounter++) {
		spin_lock_irq(&bus->reg_lock);
		if (bus->polling_mode || do_poll)
			snd_hdac_bus_update_rirb(bus);
		if (!bus->rirb.cmds[addr]) {
			if (!do_poll)
				bus->poll_count = 0;
			if (res)
				*res = bus->rirb.res[addr]; /* the last value */
			spin_unlock_irq(&bus->reg_lock);
			return 0;
		}
		spin_unlock_irq(&bus->reg_lock);
		if (time_after(jiffies, timeout))
			break;
#define LOOP_COUNT_MAX	3000
		if (bus->needs_damn_long_delay ||
		    loopcounter > LOOP_COUNT_MAX) {
			if (loopcounter > LOOP_COUNT_MAX && !warned) {
				dev_dbg_ratelimited(&chip->pci->dev,
						    "too slow response, last cmd=%#08x\n",
						    bus->last_cmd[addr]);
				warned = true;
			}
			msleep(2); /* temporary workaround */
		} else {
			udelay(10);
			cond_resched();
		}
	}

	if (hbus->no_response_fallback)
	{
		return -EIO;
	}

	if (!bus->polling_mode && bus->poll_count < 2) {
		dev_dbg(&chip->pci->dev,
			"azx_get_response timeout, polling \
            the codec once: last cmd=0x%08x\n",
			bus->last_cmd[addr]);
		do_poll = 1;
		bus->poll_count++;
		goto again;
	}


	if (!bus->polling_mode) {
		dev_warn(&chip->pci->dev,
			 "azx_get_response timeout, switching \
             to polling mode: last cmd=0x%08x\n",
			 bus->last_cmd[addr]);
		bus->polling_mode = 1;
		goto again;
	}

	if (chip->msi) {
		dev_warn(&chip->pci->dev,
			 "No response from codec, disabling MSI: last cmd=0x%08x\n",
			 bus->last_cmd[addr]);
		if (chip->ops->disable_msi_reset_irq &&
		    chip->ops->disable_msi_reset_irq(chip) < 0)
		{
			return -EIO;
		}
		goto again;
	}

	if (chip->probing) {
		/* If this critical timeout happens during the codec probing
		 * phase, this is likely an access to a non-existing codec
		 * slot.  Better to return an error and reset the system.
		 */
		return -EIO;
	}

	/* no fallback mechanism? */
	if (!chip->fallback_to_single_cmd)
	{
		return -EIO;
	}

	/* a fatal communication error; need either to reset or to fallback
	 * to the single_cmd mode
	 */
	if (hbus->allow_bus_reset && !hbus->response_reset && !hbus->in_reset) {
		hbus->response_reset = 1;
		dev_err(&chip->pci->dev,
			"No response from codec, resetting bus: last cmd=0x%08x\n",
			bus->last_cmd[addr]);
		return -EAGAIN; /* give a chance to retry */
	}

	dev_err(&chip->pci->dev,
		"azx_get_response timeout, switching \
        to single_cmd mode: last cmd=0x%08x\n",
		bus->last_cmd[addr]);
	chip->single_cmd = 1;
	hbus->response_reset = 0;
	snd_hdac_bus_stop_cmd_io(bus);
	return -EIO;
}

/*
 * The below are the main callbacks from hda_codec.
 *
 * They are just the skeleton to call sub-callbacks according to the
 * current setting of chip->single_cmd.
 */

/* send a command */
static int azx_send_cmd(struct hdac_bus *bus, unsigned int val)
{
	struct azx *chip = bus_to_azx(bus);

	if (chip->disabled)
		return 0;
	return snd_hdac_bus_send_cmd(bus, val);
}

/* get a response */
static int azx_get_response(struct hdac_bus *bus, unsigned int addr,
			    unsigned int *res)
{
	struct azx *chip = bus_to_azx(bus);

	if (chip->disabled)
		return 0;
	return azx_rirb_get_response(bus, addr, res);
}

static const struct hdac_bus_ops bus_core_ops = {
	.command = azx_send_cmd,
	.get_response = azx_get_response,
};

/*
 * reset and start the controller registers
 */
void azx_init_chip(struct azx *chip, bool full_reset)
{
	if (snd_hdac_bus_init_chip(azx_bus(chip), full_reset)) {
		/* correct RINTCNT for CXT */
		if (chip->driver_caps & AZX_DCAPS_CTX_WORKAROUND)
			azx_writew(chip, RINTCNT, 0xc0);
	}
}

void azx_stop_all_streams(struct azx *chip)
{
	struct hdac_bus *bus = azx_bus(chip);
	struct hdac_stream *s;

	list_for_each_entry(s, &bus->stream_list, list)
		snd_hdac_stream_stop(s);
}

void azx_stop_chip(struct azx *chip)
{
	snd_hdac_bus_stop_chip(azx_bus(chip));
}

/*
 * interrupt handler
 */
static void stream_update(struct hdac_bus *bus, struct hdac_stream *s)
{
	struct azx *chip = bus_to_azx(bus);
	struct azx_dev *azx_dev = stream_to_azx_dev(s);

	/* check whether this IRQ is really acceptable */
	if (!chip->ops->position_check ||
	    chip->ops->position_check(chip, azx_dev)) {
		spin_unlock(&bus->reg_lock);
		snd_pcm_period_elapsed(azx_stream(azx_dev)->substream);
		spin_lock(&bus->reg_lock);
	}
}

irqreturn_t azx_interrupt(int irq, void *dev_id)
{
	struct azx *chip = dev_id;
	struct hdac_bus *bus = azx_bus(chip);
	u32 status;
	bool active, handled = false;
	int repeat = 0; /* count for avoiding endless loop */

#ifdef CONFIG_PM
	if (azx_has_pm_runtime(chip))
		if (!pm_runtime_active(chip->card->dev))
			return IRQ_NONE;
#endif

	spin_lock(&bus->reg_lock);

	if (chip->disabled)
		goto unlock;

	do {
		status = azx_readl(chip, INTSTS);
		if (status == 0 || status == 0xffffffff)
			break;

		handled = true;
		active = false;
		if (snd_hdac_bus_handle_stream_irq(bus, status, stream_update))
			active = true;

		/* clear rirb int */
		status = azx_readb(chip, RIRBSTS);
		if (status & RIRB_INT_MASK) {
			active = true;
			if (status & RIRB_INT_RESPONSE) {
				if (chip->driver_caps & AZX_DCAPS_CTX_WORKAROUND)
					udelay(80);
				snd_hdac_bus_update_rirb(bus);
			}
			azx_writeb(chip, RIRBSTS, RIRB_INT_MASK);
		}
	} while (active && ++repeat < 10);

 unlock:
	spin_unlock(&bus->reg_lock);

	return IRQ_RETVAL(handled);
}

/*
 * Codec initerface
 */

void snd_hda_bus_reset(struct hda_bus *bus)
{
	struct azx *chip = bus_to_azx(&bus->core);

	bus->in_reset = 1;
	azx_stop_chip(chip);
	azx_init_chip(chip, true);
	bus->in_reset = 0;
}

/* HD-audio bus initialization */
int azx_bus_init(struct azx *chip, const char *model)
{
	struct hda_bus *bus = &chip->bus;
	int err;

	err = snd_hdac_bus_init(&bus->core, &chip->pci->dev, &bus_core_ops);
	if (err < 0)
		return err;

	mutex_init(&bus->prepare_mutex);
	bus->pci = chip->pci;
	bus->modelname = model;
	bus->mixer_assigned = -1;
	bus->core.snoop = azx_snoop(chip);
	if (chip->get_position[0] != azx_get_pos_lpib ||
	    chip->get_position[1] != azx_get_pos_lpib)
		bus->core.use_posbuf = true;
	bus->core.bdl_pos_adj = chip->bdl_pos_adj;
	if (chip->driver_caps & AZX_DCAPS_CORBRP_SELF_CLEAR)
		bus->core.corbrp_self_clear = true;

	if (chip->driver_caps & AZX_DCAPS_4K_BDLE_BOUNDARY)
		bus->core.align_bdle_4k = true;

	/* enable sync_write flag for stable communication as default */
	bus->core.sync_write = 1;

	return 0;
}

static int stream_direction(struct azx *chip, unsigned char index)
{
	if (index >= chip->capture_index_offset &&
	    index < chip->capture_index_offset + chip->capture_streams)
		return SNDRV_PCM_STREAM_CAPTURE;
	return SNDRV_PCM_STREAM_PLAYBACK;
}

/* initialize SD streams */
int azx_init_streams(struct azx *chip)
{
	int i;
	int stream_tags[2] = { 0, 0 };

	/* initialize each stream (aka device)
	 * assign the starting bdl address to each stream (device)
	 * and initialize
	 */
	for (i = 0; i < chip->num_streams; i++) {
		struct azx_dev *azx_dev = kzalloc(sizeof(*azx_dev), GFP_KERNEL);
		int dir, tag;

		if (!azx_dev)
			return -ENOMEM;

		dir = stream_direction(chip, i);
		/* stream tag must be unique throughout
		 * the stream direction group,
		 * valid values 1...15
		 * use separate stream tag if the flag
		 * AZX_DCAPS_SEPARATE_STREAM_TAG is used
		 */
		if (chip->driver_caps & AZX_DCAPS_SEPARATE_STREAM_TAG)
			tag = ++stream_tags[dir];
		else
			tag = i + 1;
		snd_hdac_stream_init(azx_bus(chip), azx_stream(azx_dev),
				     i, dir, tag);
	}

	return 0;
}

void azx_free_streams(struct azx *chip)
{
	struct hdac_bus *bus = azx_bus(chip);
	struct hdac_stream *s;

	while (!list_empty(&bus->stream_list)) {
		s = list_first_entry(&bus->stream_list, struct hdac_stream, list);
		list_del(&s->list);
		kfree(stream_to_azx_dev(s));
	}
}
