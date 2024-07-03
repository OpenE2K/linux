/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 *  l_hda.c - Implementation of primary alsa driver code base
 *                for MCST HD Audio. Based on hda_intel.c
 *
 *  CHANGES:
 *
 *  2022.03.01  Changed for MCST hda controller by nikulin_d@mcst.ru
 */

#include <linux/delay.h>
#include <linux/interrupt.h>
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/moduleparam.h>
#include <linux/init.h>
#include <linux/slab.h>
#include <linux/pci.h>
#include <linux/mutex.h>
#include <linux/io.h>
#include <linux/pm_runtime.h>
#include <linux/clocksource.h>
#include <linux/time.h>
#include <linux/completion.h>

#include <sound/core.h>
#include <sound/initval.h>
#include <sound/hdaudio.h>
#include <sound/intel-nhlt.h>
#include <linux/firmware.h>
#include "hda_controller.h"
#include "hda_intel.h"
#include <sound/soc.h>
#include <sound/hda_component.h>

/* position fix mode */
enum {
	POS_FIX_AUTO,
	POS_FIX_LPIB,
	POS_FIX_POSBUF,
	POS_FIX_VIACOMBO,
	POS_FIX_COMBO,
	POS_FIX_SKL,
	POS_FIX_FIFO,
};

/* max number of SDs */
/* ICH, ATI and VIA have 4 playback and 4 capture */
#define ICH6_NUM_CAPTURE	4
#define ICH6_NUM_PLAYBACK	4

static bool enable[SNDRV_CARDS] = SNDRV_DEFAULT_ENABLE_PNP;
static char *model[SNDRV_CARDS];
static int position_fix[SNDRV_CARDS] = {[0 ... (SNDRV_CARDS-1)] = -1};
static int probe_only[SNDRV_CARDS];
static int enable_msi = -1;

#ifdef CONFIG_PM
static int param_set_xint(const char *val, const struct kernel_param *kp);
static const struct kernel_param_ops param_ops_xint = {
	.set = param_set_xint,
	.get = param_get_int,
};
#define param_check_xint param_check_int

static int power_save = CONFIG_SND_HDA_POWER_SAVE_DEFAULT;
module_param(power_save, xint, 0644);
MODULE_PARM_DESC(power_save, "Automatic power-saving timeout "
		 "(in second, 0 = disable).");
/* reset the HD-audio controller in power save mode.
 * this may give more power-saving, but will take longer time to
 * wake up.
 */
static bool power_save_controller = 1;
module_param(power_save_controller, bool, 0644);
MODULE_PARM_DESC(power_save_controller,
		"Reset controller in power save mode.");
#else
#define power_save	0
#endif /* CONFIG_PM */

static int align_buffer_size = -1;
module_param(align_buffer_size, bint, 0644);
MODULE_PARM_DESC(align_buffer_size,
		"Force buffer and period sizes to be multiple of 128 bytes.");

#define hda_snoop		true

MODULE_AUTHOR("MCST");
MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("MCST HDA driver");

/*
 */

/* driver types */
enum {
	AZX_DRIVER_IOHUB2,
	AZX_NUM_DRIVERS, /* keep this as last entry */
};

static int azx_acquire_irq(struct azx *chip, int do_disconnect);
static void set_default_power_save(struct azx *chip);

/*
 * initialize the PCI registers
 */
/* update bits in a PCI register byte */
static void update_pci_byte(struct pci_dev *pci, unsigned int reg,
			    unsigned char mask, unsigned char val)
{
	unsigned char data;

	pci_read_config_byte(pci, reg, &data);
	data &= ~mask;
	data |= (val & mask);
	pci_write_config_byte(pci, reg, data);
}

static void azx_init_pci(struct azx *chip)
{
	/* Clear bits 0-2 of PCI register TCSEL (at offset 0x44)
	 * TCSEL == Traffic Class Select Register, which sets PCI express QOS
	 * Ensuring these bits are 0 clears playback static on some HD Audio
	 * codecs.
	 * The PCI register TCSEL is defined in the Intel manuals.
	 */
	if (!(chip->driver_caps & AZX_DCAPS_NO_TCSEL)) {
		dev_dbg(&chip->pci->dev, "Clearing TCSEL\n");
		update_pci_byte(chip->pci, AZX_PCIREG_TCSEL, 0x07, 0);
	}
}

/*
 * ML_LCAP bits:
 *  bit 0: 6 MHz Supported
 *  bit 1: 12 MHz Supported
 *  bit 2: 24 MHz Supported
 *  bit 3: 48 MHz Supported
 *  bit 4: 96 MHz Supported
 *  bit 5: 192 MHz Supported
 */
static int intel_get_lctl_scf(struct azx *chip)
{
	struct hdac_bus *bus = azx_bus(chip);
	static int preferred_bits[] = { 2, 3, 1, 4, 5 };
	u32 val, t;
	int i;

	val = readl(bus->mlcap + AZX_ML_BASE + AZX_REG_ML_LCAP);

	for (i = 0; i < ARRAY_SIZE(preferred_bits); i++) {
		t = preferred_bits[i];
		if (val & (1 << t))
			return t;
	}

	dev_warn(&chip->pci->dev, "set audio clock frequency to 6MHz");
	return 0;
}

static int intel_ml_lctl_set_power(struct azx *chip, int state)
{
	struct hdac_bus *bus = azx_bus(chip);
	u32 val;
	int timeout;

	/*
	 * the codecs are sharing the first link setting by default
	 * If other links are enabled for stream, they need similar fix
	 */
	val = readl(bus->mlcap + AZX_ML_BASE + AZX_REG_ML_LCTL);
	val &= ~AZX_MLCTL_SPA;
	val |= state << AZX_MLCTL_SPA_SHIFT;
	writel(val, bus->mlcap + AZX_ML_BASE + AZX_REG_ML_LCTL);
	/* wait for CPA */
	timeout = 50;
	while (timeout) {
		if (((readl(bus->mlcap + AZX_ML_BASE + AZX_REG_ML_LCTL)) &
		    AZX_MLCTL_CPA) == (state << AZX_MLCTL_CPA_SHIFT))
			return 0;
		timeout--;
		udelay(10);
	}

	return -1;
}

static void intel_init_lctl(struct azx *chip)
{
	struct hdac_bus *bus = azx_bus(chip);
	u32 val;
	int ret;

	/* 0. check lctl register value is correct or not */
	val = readl(bus->mlcap + AZX_ML_BASE + AZX_REG_ML_LCTL);
	/* if SCF is already set, let's use it */
	if ((val & ML_LCTL_SCF_MASK) != 0)
		return;

	/*
	 * Before operating on SPA, CPA must match SPA.
	 * Any deviation may result in undefined behavior.
	 */
	if (((val & AZX_MLCTL_SPA) >> AZX_MLCTL_SPA_SHIFT) !=
		((val & AZX_MLCTL_CPA) >> AZX_MLCTL_CPA_SHIFT))
		return;

	/* 1. turn link down: set SPA to 0 and wait CPA to 0 */
	ret = intel_ml_lctl_set_power(chip, 0);
	udelay(100);
	if (ret)
		goto set_spa;

	/* 2. update SCF to select a properly audio clock*/
	val &= ~ML_LCTL_SCF_MASK;
	val |= intel_get_lctl_scf(chip);
	writel(val, bus->mlcap + AZX_ML_BASE + AZX_REG_ML_LCTL);

set_spa:
	/* 4. turn link up: set SPA to 1 and wait CPA to 1 */
	intel_ml_lctl_set_power(chip, 1);
	udelay(100);
}

static void hda_intel_init_chip(struct azx *chip, bool full_reset)
{
	struct hdac_bus *bus = azx_bus(chip);

	snd_hdac_set_codec_wakeup(bus, true);
	azx_init_chip(chip, full_reset);

	snd_hdac_set_codec_wakeup(bus, false);

	if (bus->mlcap != NULL)
		intel_init_lctl(chip);
}

/* calculate runtime delay from LPIB */
static int azx_get_delay_from_lpib(struct azx *chip, struct azx_dev *azx_dev,
				   unsigned int pos)
{
	struct snd_pcm_substream *substream = azx_dev->core.substream;
	int stream = substream->stream;
	unsigned int lpib_pos = azx_get_pos_lpib(chip, azx_dev);
	int delay;

	if (stream == SNDRV_PCM_STREAM_PLAYBACK)
		delay = pos - lpib_pos;
	else
		delay = lpib_pos - pos;
	if (delay < 0) {
		if (delay >= azx_dev->core.delay_negative_threshold)
			delay = 0;
		else
			delay += azx_dev->core.bufsize;
	}

	if (delay >= azx_dev->core.period_bytes) {
		dev_info(&chip->pci->dev,
			 "Unstable LPIB (%d >= %d); disabling LPIB delay counting\n",
			 delay, azx_dev->core.period_bytes);
		delay = 0;
		chip->driver_caps &= ~AZX_DCAPS_COUNT_LPIB_DELAY;
		chip->get_delay[stream] = NULL;
	}

	return bytes_to_frames(substream->runtime, delay);
}

static int azx_position_ok(struct azx *chip, struct azx_dev *azx_dev);

/* called from IRQ */
static int azx_position_check(struct azx *chip, struct azx_dev *azx_dev)
{
	struct hda_intel *hda = container_of(chip, struct hda_intel, chip);
	int ok;

	ok = azx_position_ok(chip, azx_dev);
	if (ok == 1) {
		azx_dev->irq_pending = 0;
		return ok;
	} else if (ok == 0) {
		/* bogus IRQ, process it later */
		azx_dev->irq_pending = 1;
		schedule_work(&hda->irq_pending_work);
	}
	return 0;
}

#define display_power(chip, enable) \
	snd_hdac_display_power(azx_bus(chip), HDA_CODEC_IDX_CONTROLLER, enable)

/*
 * Check whether the current DMA position is acceptable for updating
 * periods.  Returns non-zero if it's OK.
 *
 * Many HD-audio controllers appear pretty inaccurate about
 * the update-IRQ timing.  The IRQ is issued before actually the
 * data is processed.  So, we need to process it afterwords in a
 * workqueue.
 */
static int azx_position_ok(struct azx *chip, struct azx_dev *azx_dev)
{
	struct snd_pcm_substream *substream = azx_dev->core.substream;
	int stream = substream->stream;
	u32 wallclk;
	unsigned int pos;

	wallclk = azx_readl(chip, WALLCLK) - azx_dev->core.start_wallclk;
	if (wallclk < (azx_dev->core.period_wallclk * 2) / 3)
		return -1;	/* bogus (too early) interrupt */

	if (chip->get_position[stream]) {
		pos = chip->get_position[stream](chip, azx_dev);
	} else { /* use the position buffer as default */
		pos = azx_get_pos_posbuf(chip, azx_dev);
		if (!pos || pos == (u32)-1) {
			dev_info(&chip->pci->dev,
				 "Invalid position buffer, using LPIB read method instead.\n");
			chip->get_position[stream] = azx_get_pos_lpib;
			if (chip->get_position[0] == azx_get_pos_lpib &&
			    chip->get_position[1] == azx_get_pos_lpib)
				azx_bus(chip)->use_posbuf = false;
			pos = azx_get_pos_lpib(chip, azx_dev);
			chip->get_delay[stream] = NULL;
		} else {
			chip->get_position[stream] = azx_get_pos_posbuf;
			if (chip->driver_caps & AZX_DCAPS_COUNT_LPIB_DELAY)
				chip->get_delay[stream] = azx_get_delay_from_lpib;
		}
	}

	if (pos >= azx_dev->core.bufsize)
		pos = 0;

	if (WARN_ONCE(!azx_dev->core.period_bytes,
		      "hda-intel: zero azx_dev->period_bytes"))
		return -1; /* this shouldn't happen! */
	if (wallclk < (azx_dev->core.period_wallclk * 5) / 4 &&
	    pos % azx_dev->core.period_bytes > azx_dev->core.period_bytes / 2)
		/* NG - it's below the first next period boundary */
		return chip->bdl_pos_adj ? 0 : -1;
	azx_dev->core.start_wallclk += wallclk;
	return 1; /* OK, it's fine */
}

/*
 * The work for pending PCM period updates.
 */
static void azx_irq_pending_work(struct work_struct *work)
{
	struct hda_intel *hda = container_of(work,
		struct hda_intel, irq_pending_work);
	struct azx *chip = &hda->chip;
	struct hdac_bus *bus = azx_bus(chip);
	struct hdac_stream *s;
	int pending, ok;

	if (!hda->irq_pending_warned) {
		dev_info(&chip->pci->dev,
			"IRQ timing workaround is activated for card. \
				Suggest a bigger bdl_pos_adj.\n");
		hda->irq_pending_warned = 1;
	}

	for (;;) {
		pending = 0;
		spin_lock_irq(&bus->reg_lock);
		list_for_each_entry(s, &bus->stream_list, list) {
			struct azx_dev *azx_dev = stream_to_azx_dev(s);
			if (!azx_dev->irq_pending ||
			    !s->substream ||
			    !s->running)
				continue;
			ok = azx_position_ok(chip, azx_dev);
			if (ok > 0) {
				azx_dev->irq_pending = 0;
				spin_unlock(&bus->reg_lock);
				snd_pcm_period_elapsed(s->substream);
				spin_lock(&bus->reg_lock);
			} else if (ok < 0) {
				pending = 0;	/* too early */
			} else {
				pending++;
			}
		}
		spin_unlock_irq(&bus->reg_lock);
		if (!pending)
			return;
		msleep(1);
	}
}

/* clear irq_pending flags and assure no on-going workq */
static void azx_clear_irq_pending(struct azx *chip)
{
	struct hdac_bus *bus = azx_bus(chip);
	struct hdac_stream *s;

	spin_lock_irq(&bus->reg_lock);
	list_for_each_entry(s, &bus->stream_list, list) {
		struct azx_dev *azx_dev = stream_to_azx_dev(s);
		azx_dev->irq_pending = 0;
	}
	spin_unlock_irq(&bus->reg_lock);
}

static int azx_acquire_irq(struct azx *chip, int do_disconnect)
{
	struct hdac_bus *bus = azx_bus(chip);

	if (request_irq(chip->pci->irq, azx_interrupt,
			chip->msi ? 0 : IRQF_SHARED,
			dev_name(bus->dev), chip)) {
		dev_err(&chip->pci->dev,
			"unable to grab IRQ %d, disabling device\n",
			chip->pci->irq);
		if (do_disconnect)
			snd_card_disconnect(chip->card);
		return -1;
	}
	bus->irq = chip->pci->irq;
	pci_intx(chip->pci, !chip->msi);
	return 0;
}

/* get the current DMA position with correction on VIA chips */
static unsigned int azx_via_get_position(struct azx *chip,
					 struct azx_dev *azx_dev)
{
	unsigned int link_pos, mini_pos, bound_pos;
	unsigned int mod_link_pos, mod_dma_pos, mod_mini_pos;
	unsigned int fifo_size;

	link_pos = snd_hdac_stream_get_pos_lpib(azx_stream(azx_dev));
	if (azx_dev->core.substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		/* Playback, no problem using link position */
		return link_pos;
	}

	/* Capture */
	/* For new chipset,
	 * use mod to get the DMA position just like old chipset
	 */
	mod_dma_pos = le32_to_cpu(*azx_dev->core.posbuf);
	mod_dma_pos %= azx_dev->core.period_bytes;

	fifo_size = azx_stream(azx_dev)->fifo_size - 1;

	if (azx_dev->insufficient) {
		/* Link position never gather than FIFO size */
		if (link_pos <= fifo_size)
			return 0;

		azx_dev->insufficient = 0;
	}

	if (link_pos <= fifo_size)
		mini_pos = azx_dev->core.bufsize + link_pos - fifo_size;
	else
		mini_pos = link_pos - fifo_size;

	/* Find nearest previous boudary */
	mod_mini_pos = mini_pos % azx_dev->core.period_bytes;
	mod_link_pos = link_pos % azx_dev->core.period_bytes;
	if (mod_link_pos >= fifo_size) {
		bound_pos = link_pos - mod_link_pos;
	} else if (mod_dma_pos >= mod_mini_pos) {
		bound_pos = mini_pos - mod_mini_pos;
	} else {
		bound_pos = mini_pos - mod_mini_pos + azx_dev->core.period_bytes;
		if (bound_pos >= azx_dev->core.bufsize) {
			bound_pos = 0;
		}
	}

	/* Calculate real DMA position we want */
	return bound_pos + mod_dma_pos;
}

#define AMD_FIFO_SIZE	32

/* get the current DMA position with FIFO size correction */
static unsigned int azx_get_pos_fifo(struct azx *chip, struct azx_dev *azx_dev)
{
	struct snd_pcm_substream *substream = azx_dev->core.substream;
	struct snd_pcm_runtime *runtime = substream->runtime;
	unsigned int pos, delay;

	pos = snd_hdac_stream_get_pos_lpib(azx_stream(azx_dev));
	if (!runtime)
		return pos;

	runtime->delay = AMD_FIFO_SIZE;
	delay = frames_to_bytes(runtime, AMD_FIFO_SIZE);
	if (azx_dev->insufficient) {
		if (pos < delay) {
			delay = pos;
			runtime->delay = bytes_to_frames(runtime, pos);
		} else {
			azx_dev->insufficient = 0;
		}
	}

	/* correct the DMA position for capture stream */
	if (substream->stream == SNDRV_PCM_STREAM_CAPTURE) {
		if (pos < delay)
			pos += azx_dev->core.bufsize;
		pos -= delay;
	}

	return pos;
}

static int azx_get_delay_from_fifo(struct azx *chip, struct azx_dev *azx_dev,
				   unsigned int pos)
{
	struct snd_pcm_substream *substream = azx_dev->core.substream;

	/* just read back the calculated value in the above */
	return substream->runtime->delay;
}

static unsigned int azx_skl_get_dpib_pos(struct azx *chip,
					 struct azx_dev *azx_dev)
{
	return _snd_hdac_chip_readl(azx_bus(chip),
				    AZX_REG_VS_SDXDPIB_XBASE +
				    (AZX_REG_VS_SDXDPIB_XINTERVAL *
				     azx_dev->core.index));
}

/* get the current DMA position with correction on SKL+ chips */
static unsigned int azx_get_pos_skl(struct azx *chip, struct azx_dev *azx_dev)
{
	/* DPIB register gives a more accurate position for playback */
	if (azx_dev->core.substream->stream == SNDRV_PCM_STREAM_PLAYBACK)
		return azx_skl_get_dpib_pos(chip, azx_dev);

	/* For capture, we need to read posbuf, but it requires a delay
	 * for the possible boundary overlap; the read of DPIB fetches the
	 * actual posbuf
	 */
	udelay(20);
	azx_skl_get_dpib_pos(chip, azx_dev);
	return azx_get_pos_posbuf(chip, azx_dev);
}

#ifdef CONFIG_PM
static DEFINE_MUTEX(card_list_lock);
static LIST_HEAD(card_list);

static void azx_add_card_list(struct azx *chip)
{
	struct hda_intel *hda = container_of(chip, struct hda_intel, chip);
	mutex_lock(&card_list_lock);
	list_add(&hda->list, &card_list);
	mutex_unlock(&card_list_lock);
}

static void azx_del_card_list(struct azx *chip)
{
	struct hda_intel *hda = container_of(chip, struct hda_intel, chip);
	mutex_lock(&card_list_lock);
	list_del_init(&hda->list);
	mutex_unlock(&card_list_lock);
}

/* trigger power-save check at writing parameter */
static int param_set_xint(const char *val, const struct kernel_param *kp)
{
	struct hda_intel *hda;
	struct azx *chip;
	int prev = power_save;
	int ret = param_set_int(val, kp);

	if (ret || prev == power_save)
		return ret;

	mutex_lock(&card_list_lock);
	list_for_each_entry(hda, &card_list, list) {
		chip = &hda->chip;
		if (!hda->probe_continued || chip->disabled)
			continue;
		snd_hda_set_power_save(&chip->bus, power_save * 1000);
	}
	mutex_unlock(&card_list_lock);
	return 0;
}

/*
 * power management
 */
static bool azx_is_pm_ready(struct azx *chip)
{
	struct hda_intel *hda;

	hda = container_of(chip, struct hda_intel, chip);
	if (chip->disabled || hda->init_failed || !chip->running)
		return false;
	return true;
}

static void __azx_runtime_suspend(struct azx *chip)
{
	azx_stop_chip(chip);
	azx_enter_link_reset(chip);
	azx_clear_irq_pending(chip);
	display_power(chip, false);
}

static void __azx_runtime_resume(struct azx *chip)
{
	struct hda_intel *hda = container_of(chip, struct hda_intel, chip);

	display_power(chip, true);

	azx_init_pci(chip);
	hda_intel_init_chip(chip, true);

}

#ifdef CONFIG_PM_SLEEP
static int azx_suspend(struct device *dev)
{
	struct azx *chip = dev_get_drvdata(dev);
	struct hdac_bus *bus;

	if (!azx_is_pm_ready(chip))
		return 0;

	bus = azx_bus(chip);
	__azx_runtime_suspend(chip);
	if (bus->irq >= 0) {
		free_irq(bus->irq, chip);
		bus->irq = -1;
	}

	if (chip->msi)
		pci_disable_msi(chip->pci);

	return 0;
}

static int azx_resume(struct device *dev)
{
	struct azx *chip = dev_get_drvdata(dev);

	if (!azx_is_pm_ready(chip))
		return 0;

	if (chip->msi)
		if (pci_enable_msi(chip->pci) < 0)
			chip->msi = 0;
	if (azx_acquire_irq(chip, 1) < 0)
		return -EIO;
	__azx_runtime_resume(chip);

	return 0;
}

/* put codec down to D3 at hibernation for Intel SKL+;
 * otherwise BIOS may still access the codec and screw up the driver
 */
static int azx_freeze_noirq(struct device *dev)
{
	struct azx *chip = dev_get_drvdata(dev);
	struct pci_dev *pci = to_pci_dev(dev);

	if (!azx_is_pm_ready(chip))
		return 0;

	return 0;
}

static int azx_thaw_noirq(struct device *dev)
{
	struct azx *chip = dev_get_drvdata(dev);
	struct pci_dev *pci = to_pci_dev(dev);

	if (!azx_is_pm_ready(chip))
		return 0;

	return 0;
}
#endif /* CONFIG_PM_SLEEP */

static int azx_runtime_suspend(struct device *dev)
{
	struct azx *chip = dev_get_drvdata(dev);

	if (!azx_is_pm_ready(chip))
		return 0;
	if (!azx_has_pm_runtime(chip))
		return 0;

	/* enable controller wake up event */
	azx_writew(chip, WAKEEN, azx_readw(chip, WAKEEN) |
		  STATESTS_INT_MASK);

	__azx_runtime_suspend(chip);
	return 0;
}

static int azx_runtime_resume(struct device *dev)
{
	struct azx *chip = dev_get_drvdata(dev);

	if (!azx_is_pm_ready(chip))
		return 0;
	if (!azx_has_pm_runtime(chip))
		return 0;
	__azx_runtime_resume(chip);

	/* disable controller Wake Up event */
	azx_writew(chip, WAKEEN, azx_readw(chip, WAKEEN) &
			~STATESTS_INT_MASK);

	return 0;
}

static int azx_runtime_idle(struct device *dev)
{
	struct azx *chip = dev_get_drvdata(dev);
	struct hda_intel *hda;

	hda = container_of(chip, struct hda_intel, chip);
	if (chip->disabled || hda->init_failed)
		return 0;

	if (!power_save_controller || !azx_has_pm_runtime(chip) ||
	    azx_bus(chip)->codec_powered || !chip->running)
	if (!power_save_controller || !azx_has_pm_runtime(chip) ||
	    !chip->running)
		return -EBUSY;

	return 0;
}

static const struct dev_pm_ops azx_pm = {
	SET_SYSTEM_SLEEP_PM_OPS(azx_suspend, azx_resume)
#ifdef CONFIG_PM_SLEEP
	.freeze_noirq = azx_freeze_noirq,
	.thaw_noirq = azx_thaw_noirq,
#endif
	SET_RUNTIME_PM_OPS(azx_runtime_suspend,
		azx_runtime_resume, azx_runtime_idle)
};

#define AZX_PM_OPS	(&azx_pm)
#else
#define azx_add_card_list(chip) /* NOP */
#define azx_del_card_list(chip) /* NOP */
#define AZX_PM_OPS	NULL
#endif /* CONFIG_PM */


static int azx_probe_continue(struct azx *chip);

/*
 * destructor
 */
static void azx_free(struct azx *chip)
{
	struct pci_dev *pci = chip->pci;
	struct hda_intel *hda = container_of(chip, struct hda_intel, chip);
	struct hdac_bus *bus = azx_bus(chip);

	if (hda->freed)
		return;

	if (azx_has_pm_runtime(chip) && chip->running)
		pm_runtime_get_noresume(&pci->dev);
	chip->running = 0;

	azx_del_card_list(chip);

	hda->init_failed = 1; /* to be sure */
	complete_all(&hda->probe_wait);

	if (bus->chip_init) {
		azx_clear_irq_pending(chip);
		azx_stop_all_streams(chip);
		azx_stop_chip(chip);
	}

	if (bus->irq >= 0)
		free_irq(bus->irq, (void *)chip);
	if (chip->msi)
		pci_disable_msi(chip->pci);
	iounmap(bus->remap_addr);

	azx_free_stream_pages(chip);
	azx_free_streams(chip);
	snd_hdac_bus_exit(bus);

	if (chip->region_requested)
		pci_release_regions(chip->pci);

	pci_disable_device(chip->pci);
#ifdef CONFIG_SND_HDA_PATCH_LOADER
	release_firmware(chip->fw);
#endif
	display_power(chip, false);

	hda->freed = 1;
}

static int check_position_fix(struct azx *chip, int fix)
{
	switch (fix) {
	case POS_FIX_AUTO:
	case POS_FIX_LPIB:
	case POS_FIX_POSBUF:
	case POS_FIX_VIACOMBO:
	case POS_FIX_COMBO:
	case POS_FIX_SKL:
	case POS_FIX_FIFO:
		return fix;
	}

	/* Check VIA/ATI HD Audio Controller exist */
	if (chip->driver_caps & AZX_DCAPS_AMD_WORKAROUND) {
		dev_dbg(&chip->pci->dev, "Using FIFO position fix\n");
		return POS_FIX_FIFO;
	}
	if (chip->driver_caps & AZX_DCAPS_POSFIX_LPIB) {
		dev_dbg(&chip->pci->dev, "Using LPIB position fix\n");
		return POS_FIX_LPIB;
	}
	return POS_FIX_AUTO;
}

static void assign_position_fix(struct azx *chip, int fix)
{
	static azx_get_pos_callback_t callbacks[] = {
		[POS_FIX_AUTO] = NULL,
		[POS_FIX_LPIB] = azx_get_pos_lpib,
		[POS_FIX_POSBUF] = azx_get_pos_posbuf,
		[POS_FIX_VIACOMBO] = azx_via_get_position,
		[POS_FIX_COMBO] = azx_get_pos_lpib,
		[POS_FIX_SKL] = azx_get_pos_skl,
		[POS_FIX_FIFO] = azx_get_pos_fifo,
	};

	chip->get_position[0] = callbacks[fix];
	chip->get_position[1] = callbacks[fix];
	/* combo mode uses LPIB only for playback */
	if (fix == POS_FIX_COMBO)
		chip->get_position[1] = NULL;

	if ((fix == POS_FIX_POSBUF || fix == POS_FIX_SKL) &&
	    (chip->driver_caps & AZX_DCAPS_COUNT_LPIB_DELAY)) {
		chip->get_delay[0] = azx_get_delay_from_lpib;
		chip->get_delay[1] = azx_get_delay_from_lpib;
	}

	if (fix == POS_FIX_FIFO) {
		chip->get_delay[0] = azx_get_delay_from_fifo;
		chip->get_delay[1] = azx_get_delay_from_fifo;
	}
}

#define AZX_FORCE_CODEC_MASK	0x100

static void check_msi(struct azx *chip)
{
	if (enable_msi >= 0) {
		chip->msi = !!enable_msi;
		return;
	}
	chip->msi = 1;	/* enable MSI as default */

	/* NVidia chipsets seem to cause troubles with MSI */
	if (chip->driver_caps & AZX_DCAPS_NO_MSI) {
		dev_info(&chip->pci->dev, "Disabling MSI\n");
		chip->msi = 0;
	}
}

/* check the snoop mode availability */
static void azx_check_snoop_available(struct azx *chip)
{
	int snoop = hda_snoop;

	if (snoop >= 0) {
		dev_info(&chip->pci->dev, "Force to %s mode by module option\n",
			 snoop ? "snoop" : "non-snoop");
		chip->snoop = snoop;
		chip->uc_buffer = !snoop;
		return;
	}

	snoop = true;

	if (chip->driver_caps & AZX_DCAPS_SNOOP_OFF)
		snoop = false;

	chip->snoop = snoop;
}

static void azx_probe_work(struct work_struct *work)
{
	struct hda_intel *hda = container_of(work, struct hda_intel, probe_work.work);
	azx_probe_continue(&hda->chip);
}

static int default_bdl_pos_adj(struct azx *chip)
{
	switch (chip->driver_type) {
	case AZX_DRIVER_IOHUB2:
		/* iohub2 hda have problems with short buffers */
		return 0;
	default:
		return 32;
	}
}

/*
 * constructor
 */
static const struct hda_controller_ops pci_hda_ops;

static int azx_create(struct pci_dev *pci,
		      int dev, unsigned int driver_caps,
		      struct azx **rchip)
{
	struct hda_intel *hda;
	struct azx *chip;
	int err;

	*rchip = NULL;

	err = pci_enable_device(pci);
	if (err < 0)
		return err;

	hda = devm_kzalloc(&pci->dev, sizeof(*hda), GFP_KERNEL);
	if (!hda) {
		pci_disable_device(pci);
		return -ENOMEM;
	}

	chip = &hda->chip;
	mutex_init(&chip->open_mutex);
	chip->pci = pci;
	chip->ops = &pci_hda_ops;
	if (of_find_compatible_node(NULL, NULL, "mcst,hda-controller")) {
		chip->pci->dev.of_node = of_find_compatible_node(NULL,
			NULL, "mcst,hda-controller");
	} else {
		dev_warn(&chip->pci->dev, "Unable to read node for hda-controller!\n");
	}
	chip->driver_caps = driver_caps;
	chip->driver_type = driver_caps & 0xff;
	check_msi(chip);
	chip->dev_index = dev;
	INIT_LIST_HEAD(&chip->pcm_list);
	INIT_WORK(&hda->irq_pending_work, azx_irq_pending_work);
	INIT_LIST_HEAD(&hda->list);
	init_completion(&hda->probe_wait);

	assign_position_fix(chip, check_position_fix(chip, position_fix[dev]));

	chip->fallback_to_single_cmd = 1;

	azx_check_snoop_available(chip);

	chip->bdl_pos_adj = default_bdl_pos_adj(chip);

	err = azx_bus_init(chip, model[dev]);
	if (err < 0) {
		pci_disable_device(pci);
		return err;
	}

	/* use the non-cached pages in non-snoop mode */
	if (!azx_snoop(chip))
		azx_bus(chip)->dma_type = SNDRV_DMA_TYPE_DEV_UC;

#if defined(CONFIG_MCST) && (defined(CONFIG_E90S) || defined(CONFIG_E2K))
	{
		struct pci_dev *pci = chip->pci;
		/* read codec twice to fix hardware syncronization error. */
		if (pci->vendor == PCI_VENDOR_ID_MCST_TMP &&
				pci->device == PCI_DEVICE_ID_MCST_HDA &&
				iohub_generation(pci) == 1 &&
				iohub_revision(pci) < 2)
			chip->bus.needs_retry_on_codec_write = 1;
	}
#endif

	/* continue probing in work context as may trigger request module */
	INIT_DELAYED_WORK(&hda->probe_work, azx_probe_work);

	*rchip = chip;

	return 0;
}

static int azx_first_init(struct azx *chip)
{
	int dev = chip->dev_index;
	struct pci_dev *pci = chip->pci;
	struct hdac_bus *bus = azx_bus(chip);
	int err;
	unsigned short gcap;
	unsigned int dma_bits = 64;

	err = pci_request_regions(pci, "ICH HD audio");
	if (err < 0)
		return err;
	chip->region_requested = 1;

	bus->addr = pci_resource_start(pci, 0);
	bus->remap_addr = pci_ioremap_bar(pci, 0);
	if (bus->remap_addr == NULL) {
		dev_err(&chip->pci->dev, "ioremap error\n");
		return -ENXIO;
	}

	/*
	 * Some Intel CPUs has always running timer (ART) feature and
	 * controller may have Global time sync reporting capability, so
	 * check both of these before declaring synchronized time reporting
	 * capability SNDRV_PCM_INFO_HAS_LINK_SYNCHRONIZED_ATIME
	 */
	chip->gts_present = false;

	if (chip->msi) {
		if (chip->driver_caps & AZX_DCAPS_NO_MSI64) {
			dev_dbg(&chip->pci->dev, "Disabling 64bit MSI\n");
			pci->no_64bit_msi = true;
		}
		if (pci_enable_msi(pci) < 0)
			chip->msi = 0;
	}

	pci_set_master(pci);
	synchronize_irq(bus->irq);

	gcap = azx_readw(chip, GCAP);
	dev_dbg(&chip->pci->dev, "chipset global capabilities = 0x%x\n", gcap);

	/* disable 64bit DMA address on some devices */
	if (chip->driver_caps & AZX_DCAPS_NO_64BIT) {
		dev_dbg(&chip->pci->dev, "Disabling 64bit DMA\n");
		gcap &= ~AZX_GCAP_64OK;
	}

	/* disable buffer size rounding to 128-byte multiples if supported */
	if (align_buffer_size >= 0) {
		chip->align_buffer_size = !!align_buffer_size;
	} else {
		if (chip->driver_caps & AZX_DCAPS_NO_ALIGN_BUFSIZE) {
			chip->align_buffer_size = 0;
		} else {
			chip->align_buffer_size = 1;
		}
	}

	/* allow 64bit DMA address if supported by H/W */
	if (!(gcap & AZX_GCAP_64OK))
		dma_bits = 32;
	if (!dma_set_mask(&pci->dev, DMA_BIT_MASK(dma_bits))) {
		dma_set_coherent_mask(&pci->dev, DMA_BIT_MASK(dma_bits));
	} else {
		dma_set_mask(&pci->dev, DMA_BIT_MASK(32));
		dma_set_coherent_mask(&pci->dev, DMA_BIT_MASK(32));
	}

	/* read number of streams from GCAP register instead of using
	 * hardcoded value
	 */
	chip->capture_streams = (gcap >> 8) & 0x0f;
	chip->playback_streams = (gcap >> 12) & 0x0f;
	if (!chip->playback_streams && !chip->capture_streams) {
		/* gcap didn't give any info, switching to old method */
		chip->playback_streams = ICH6_NUM_PLAYBACK;
		chip->capture_streams = ICH6_NUM_CAPTURE;
	}
	chip->capture_index_offset = 0;
	chip->playback_index_offset = chip->capture_streams;
	chip->num_streams = chip->playback_streams + chip->capture_streams;

	/* sanity check for the SDxCTL.STRM field overflow */
	if (chip->num_streams > 15 &&
	    (chip->driver_caps & AZX_DCAPS_SEPARATE_STREAM_TAG) == 0) {
		dev_warn(&chip->pci->dev, "number of I/O streams is %d, "
			 "forcing separate stream tags", chip->num_streams);
		chip->driver_caps |= AZX_DCAPS_SEPARATE_STREAM_TAG;
	}

	/* initialize streams */
	err = azx_init_streams(chip);
	if (err < 0)
		return err;

	err = azx_alloc_stream_pages(chip);
	if (err < 0)
		return err;

	/* initialize chip */
	azx_init_pci(chip);

	hda_intel_init_chip(chip, (probe_only[dev] & 2) == 0);

	if (azx_acquire_irq(chip, 0) < 0)
		return -EBUSY;

	return 0;
}

static int disable_msi_reset_irq(struct azx *chip)
{
	struct hdac_bus *bus = azx_bus(chip);
	int err;

	free_irq(bus->irq, chip);
	bus->irq = -1;
	pci_disable_msi(chip->pci);
	chip->msi = 0;
	err = azx_acquire_irq(chip, 1);
	if (err < 0)
		return err;

	return 0;
}

static const struct hda_controller_ops pci_hda_ops = {
	.disable_msi_reset_irq = disable_msi_reset_irq,
	.position_check = azx_position_check,
};

static int azx_probe(struct pci_dev *pci,
		     const struct pci_device_id *pci_id)
{
	static int dev;
	struct hda_intel *hda;
	struct azx *chip;
	bool schedule_probe;
	int err;

	if (dev >= SNDRV_CARDS)
		return -ENODEV;
	if (!enable[dev]) {
		dev++;
		return -ENOENT;
	}

	err = azx_create(pci, dev, pci_id->driver_data, &chip);
	if (err < 0)
		goto out_free;
	hda = container_of(chip, struct hda_intel, chip);

	pci_set_drvdata(pci, chip);

	schedule_probe = !chip->disabled;

	if (schedule_probe)
		schedule_delayed_work(&hda->probe_work, 0);

	dev++;
	if (chip->disabled)
		complete_all(&hda->probe_wait);
	return 0;

out_free:
	return err;
}

static void set_default_power_save(struct azx *chip)
{
	int val = power_save;

	snd_hda_set_power_save(&chip->bus, val * 1000);
}

int azx_pcm_platform_register(struct device *dev);

static int azx_probe_continue(struct azx *chip)
{
	struct hda_intel *hda = container_of(chip, struct hda_intel, chip);
	struct hdac_bus *bus = azx_bus(chip);
	struct pci_dev *pci = chip->pci;
	int err;

	to_hda_bus(bus)->bus_probing = 1;
	hda->probe_continued = 1;

	/* Request display power well for the HDA controller or codec. For
	 * Haswell/Broadwell, both the display HDA controller and codec need
	 * this power. For other platforms, like Baytrail/Braswell, only the
	 * display codec needs the power and it can be released after probe.
	 */
	display_power(chip, true);

	err = azx_first_init(chip);
	if (err < 0)
		goto out_free;

	err = azx_pcm_platform_register(&pci->dev);
	if (err < 0) {
		dev_err(&pci->dev, "Error registring platform!\n");
		goto out_free;
	}

	chip->running = 1;
	azx_add_card_list(chip);

	set_default_power_save(chip);

	if (azx_has_pm_runtime(chip)) {
		pm_runtime_use_autosuspend(&pci->dev);
		pm_runtime_put_autosuspend(&pci->dev);
	}

out_free:
	if (err < 0) {
		azx_free(chip);
		return err;
	}

	if (!hda->need_i915_power)
		display_power(chip, false);
	complete_all(&hda->probe_wait);
	to_hda_bus(bus)->bus_probing = 0;
	return 0;
}

static void azx_remove(struct pci_dev *pci)
{
	struct azx *chip = pci_get_drvdata(pci);
	struct hda_intel *hda;

	hda = container_of(chip, struct hda_intel, chip);
    /* FIXME: below is an ugly workaround.
     * Both device_release_driver() and driver_probe_device()
     * take *both* the device's and its parent's lock before
     * calling the remove() and probe() callbacks.  The codec
     * probe takes the locks of both the codec itself and its
     * parent, i.e. the PCI controller dev.  Meanwhile, when
     * the PCI controller is unbound, it takes its lock, too
     * ==> ouch, a deadlock!
     * As a workaround, we unlock temporarily here the controller
     * device during cancel_work_sync() call.
     */
	device_unlock(&pci->dev);
	cancel_delayed_work_sync(&hda->probe_work);
	device_lock(&pci->dev);

	azx_free(chip);
}

static void azx_shutdown(struct pci_dev *pci)
{
	struct azx *chip = pci_get_drvdata(pci);

	if (chip && chip->running)
		azx_stop_chip(chip);
}

/* PCI IDs */
static const struct pci_device_id azx_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, 0x8045),
		      .driver_data = AZX_DRIVER_IOHUB2 },
	{ 0, }
};
MODULE_DEVICE_TABLE(pci, azx_ids);

/* pci_driver definition */
static struct pci_driver azx_driver = {
	.name = KBUILD_MODNAME,
	.id_table = azx_ids,
	.probe = azx_probe,
	.remove = azx_remove,
	.shutdown = azx_shutdown,
	.driver = {
		.pm = AZX_PM_OPS,
	},
};

module_pci_driver(azx_driver);
