/*
 * MCST I2S controller
 */

#include <linux/platform_device.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/interrupt.h>
#include <linux/module.h>
#include <linux/dma-mapping.h>
#include <linux/dmaengine.h>
#include <linux/acpi.h>

#include <sound/pcm.h>
#include <sound/core.h>
#include <sound/initval.h>
#include <sound/dmaengine_pcm.h>

#include "l_i2s.h"

static bool enable[SNDRV_CARDS] = SNDRV_DEFAULT_ENABLE_PNP;

module_param_array(enable, bool, NULL, 0444);
MODULE_PARM_DESC(enable, "Enable MCST I2S soundcard.");

struct l_i2s_chip {
	struct pci_dev *pci;
	struct snd_pcm *pcm;
	struct snd_pcm_substream *psubs;	/* playback substream */
	struct snd_pcm_substream *csubs;	/* capture substream */
	struct platform_device *spi_ctrl;	/* spi controller to manage codec's registers */
	int irq;
	unsigned long iobase_phys;
	void __iomem *iobase_virt;
	spinlock_t lock;
};

static int l_i2s_read_reg(struct l_i2s_chip *chip, u8 reg)
{
	int data;
	data = readl(chip->iobase_virt + reg);
	dev_dbg(&chip->pci->dev,
				"I2S audio controller reg %02x now is %04x\n", reg, data);
	return data;
}

static void l_i2s_write_reg(struct l_i2s_chip *chip, u8 reg, u32 val)
{
	int data;
	dev_dbg(&chip->pci->dev,
		"I2S audio controller try to set val %04x to reg %02x\n", val, reg);
	writel(val, chip->iobase_virt + reg);
	data = readl(chip->iobase_virt + reg);
	dev_dbg(&chip->pci->dev,
		"I2S audio controller reg %02x set to %04x\n", reg, data);
}

/* hardware definition */
static const struct snd_pcm_hardware l_i2s_pcm_hw = {
	.info = (SNDRV_PCM_INFO_MMAP |
			SNDRV_PCM_INFO_INTERLEAVED),
	.formats = SNDRV_PCM_FMTBIT_S16_LE,
	.rates = SNDRV_PCM_RATE_48000,
	.rate_min = 48000,
	.rate_max = 48000,
	.channels_min = 1,
	.channels_max = 2,
	.buffer_bytes_max = 2 * L_I2S_BUFFER_MAX_SIZE,
	.period_bytes_min = 64,
	.period_bytes_max = L_I2S_BUFFER_MAX_SIZE,
	.periods_min = 1,
	.periods_max = 1024,
};

/* pointer callback */
static snd_pcm_uframes_t l_i2s_pointer(struct snd_soc_component *component,
		struct snd_pcm_substream *substream)
{
	struct snd_soc_pcm_runtime *rtd = snd_pcm_substream_chip(substream);
	struct snd_soc_dai *cpu_dai = asoc_rtd_to_cpu(rtd, 0);
	struct l_i2s_chip *chip = cpu_dai->dev->driver_data;
	struct snd_pcm_runtime *runtime = substream->runtime;
	unsigned int current_ptr, ctrl_status;

	/* get current hardware pointer */
	ctrl_status = l_i2s_read_reg(chip, CONTROL_STATUS);
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		current_ptr = l_i2s_read_reg(chip, SPKER_BUF_PTR);
		if (ctrl_status & SPKER_BUF2_ACTIVE) {
			current_ptr += (runtime->dma_bytes / 2);
		}
	} else {
		current_ptr = l_i2s_read_reg(chip, MIC_BUF_PTR);
		if (ctrl_status & MIC_BUF2_ACTIVE) {
			current_ptr += (runtime->dma_bytes / 2);
		}
	}
	int ret;
	ret = bytes_to_frames(runtime, current_ptr);
	return ret;
}

static int l_i2s_startup(struct snd_pcm_substream *substream, struct snd_soc_dai *dai)
{
	struct l_i2s_chip *chip = dai->dev->driver_data;

	struct snd_pcm_runtime *runtime = substream->runtime;

	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		chip->psubs = substream;
	} else {
		chip->csubs = substream;
	}
	runtime->hw = l_i2s_pcm_hw;
	/* buffer pre-allocation */
	snd_pcm_set_managed_buffer(substream, SNDRV_DMA_TYPE_DEV,
					dai->dev, 2 * L_I2S_BUFFER_MAX_SIZE,
					2 * L_I2S_BUFFER_MAX_SIZE);

	return 0;
}

static void l_i2s_shutdown(struct snd_pcm_substream *substream, struct snd_soc_dai *dai)
{
	struct l_i2s_chip *chip = dai->dev->driver_data;

	kfree(substream->runtime->private_data);
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		chip->psubs = NULL;
	} else {
		chip->csubs = NULL;
	}
}

/* prepare callback */
static int l_i2s_prepare(struct snd_pcm_substream *substream, struct snd_soc_dai *dai)
{
	struct l_i2s_chip *chip = dai->dev->driver_data;

	struct snd_pcm_runtime *runtime = substream->runtime;

	/* set up the hardware */
	if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
		l_i2s_write_reg(chip, SPKER_BUF1_ADDR, runtime->dma_addr);
		l_i2s_write_reg(chip, SPKER_BUF2_ADDR,
				runtime->dma_addr + (runtime->dma_bytes / 2));
		l_i2s_write_reg(chip, SPKER_BUF_SIZE, runtime->dma_bytes / 2);
	} else {
		l_i2s_write_reg(chip, MIC_BUF1_ADDR, runtime->dma_addr);
		l_i2s_write_reg(chip, MIC_BUF2_ADDR,
				runtime->dma_addr + (runtime->dma_bytes / 2));
		l_i2s_write_reg(chip, MIC_BUF_SIZE, runtime->dma_bytes / 2);
	}

	return 0;
}

/* trigger callback */
static int l_i2s_trigger(struct snd_pcm_substream *substream,
							int cmd, struct snd_soc_dai *dai)
{
	struct l_i2s_chip *chip = dai->dev->driver_data;

	int status;
	switch (cmd) {
	case SNDRV_PCM_TRIGGER_START:
		/* start PCM engine */
		status = l_i2s_read_reg(chip, CONTROL_STATUS);
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			status |= START_PLAYBACK;
		} else {
			status |= START_CAPTURE;
		}
		l_i2s_write_reg(chip, CONTROL_STATUS, status);
		status = l_i2s_read_reg(chip, CONTROL_STATUS);
		break;
	case SNDRV_PCM_TRIGGER_STOP:
		/* stop PCM engine */
		status = l_i2s_read_reg(chip, CONTROL_STATUS);
		if (substream->stream == SNDRV_PCM_STREAM_PLAYBACK) {
			status |= STOP_PLAYBACK;
		} else {
			status &= ~START_CAPTURE;
		}
		l_i2s_write_reg(chip, CONTROL_STATUS, status);
		break;
	default:
		return -EINVAL;
	}

	return 0;
}

static const struct snd_soc_dai_ops l_i2s_soc_dai_ops = {
	.startup	= l_i2s_startup,
	.shutdown	= l_i2s_shutdown,
	.prepare	= l_i2s_prepare,
	.trigger	= l_i2s_trigger,
};

/* create a pcm device */
static int l_i2s_pcm_new(struct snd_soc_component *component,
		struct snd_soc_pcm_runtime *rtd)
{
	struct snd_pcm *pcm = rtd->pcm;
	struct snd_soc_dai *cpu_dai = asoc_rtd_to_cpu(rtd, 0);
	struct l_i2s_chip *chip = cpu_dai->dev->driver_data;
	struct device *dev = &chip->pci->dev;

	/* pre-allocations of buffers */
	snd_pcm_set_managed_buffer_all(pcm, SNDRV_DMA_TYPE_DEV,
							dev, 4 * L_I2S_BUFFER_MAX_SIZE,
							4 * L_I2S_BUFFER_MAX_SIZE);
	return 0;
}

static irqreturn_t l_i2s_interrupt(int irq, void *dev_id)
{
	struct l_i2s_chip *chip = dev_id;
	int int_status;
	int data = 0;

	spin_lock(&chip->lock);
	int_status = l_i2s_read_reg(chip, INTSTS);
	if (((int_status & INTSTS_SB1E) || (int_status & INTSTS_SB2E)) && chip->psubs) {
		spin_unlock(&chip->lock);
		snd_pcm_period_elapsed(chip->psubs);
		spin_lock(&chip->lock);
		data |= int_status & INTSTS_SB1E;
		data |= int_status & INTSTS_SB2E;
	}
	if (((int_status & INTSTS_MB1F) || (int_status & INTSTS_MB2F)) && chip->csubs) {
		spin_unlock(&chip->lock);
		snd_pcm_period_elapsed(chip->csubs);
		spin_lock(&chip->lock);
		data |= int_status & INTSTS_MB1F;
		data |= int_status & INTSTS_MB2F;
	}
	/* clear bits 5 and 6 if enabled */
	data |= int_status & INTSTS_DMA_SDOD;
	data |= int_status & INTSTS_DMA_MDD;
	l_i2s_write_reg(chip, INTSTS, data);
	spin_unlock(&chip->lock);

	return IRQ_HANDLED;
}

static int l_i2s_free(struct l_i2s_chip *chip)
{

	/* Disable hardware here */

	/* free spi controller */
	platform_device_unregister(chip->spi_ctrl);
	/* release the irq */
	if (chip->irq >= 0)
		free_irq(chip->irq, chip);
	/* release the I/O ports & memory */
	if (chip->iobase_virt)
		iounmap(chip->iobase_virt);
	pci_release_region(chip->pci, 0);
	/* disable the PCI entry */
	pci_disable_device(chip->pci);
	/* release the data */
	kfree(chip);

	return 0;
}

/* probe spi controller to manage codecs registers */
static struct platform_device *l_i2s_spi_probe(struct pci_dev *pci)
{
	struct platform_device *pdev;
	int ret = -ENOMEM;
	struct resource res[] = {
		{
			.flags	= IORESOURCE_MEM,
			.start	= pci_resource_start(pci, 1),
			.end	= pci_resource_end(pci, 1),
		}, {
			.flags	= IORESOURCE_MEM,
			.start	= pci_resource_start(pci, 2),
			.end	= pci_resource_end(pci, 2),
		}, {
			.flags	= IORESOURCE_IRQ,
			.start	= pci->irq,
			.end	= pci->irq,
		},
	};

	/* The platform device id has been hard coded and number 29 has no special
	 * meaning. When using PLATFORM_DEVID_AUTO it has conflict with id of
	 * default spi controller.
	 */
	pdev = platform_device_alloc("l_spi", 29);

	if (!pdev) {
		return ERR_PTR(-ENOMEM);
	}

	pdev->dev.parent = &pci->dev;
	pdev->dev.fwnode = NULL;
	/* set up field from device tree */
	if (of_find_node_by_name(NULL, "sound-spi")) {
		pdev->dev.of_node = of_find_node_by_name(NULL, "sound-spi");
	} else {
		dev_warn(&pci->dev,
				"Unable to read node for sound spi controller!\n");
	}
	pdev->dev.of_node_reused = false;

	ret = platform_device_add_resources(pdev, res, ARRAY_SIZE(res));
	if (ret) {
		goto err;
	}

	ret = platform_device_add(pdev);
	if (ret) {
err:
		ACPI_COMPANION_SET(&pdev->dev, NULL);
		platform_device_put(pdev);
		return ERR_PTR(ret);
	}
	return pdev;
}

static int l_i2s_create(struct pci_dev *pci, struct l_i2s_chip **rchip)
{
	struct l_i2s_chip *chip;
	int err;

	*rchip = NULL;

	/* Initialize the PCI entry */
	err = pci_enable_device(pci);
	if (err < 0)
		return err;

	chip = kzalloc(sizeof(*chip), GFP_KERNEL);
	if (chip == NULL) {
		pci_disable_device(pci);
		return -ENOMEM;
	}

	/* initialize the stuff */
	chip->pci = pci;
	chip->irq = -1;

	if (of_find_compatible_node(NULL, NULL, "mcst,sound-controller")) {
		chip->pci->dev.of_node = of_find_compatible_node(NULL,
				NULL, "mcst,sound-controller");
	} else {
		dev_warn(&chip->pci->dev,
				"Unable to read node for sound-controller!\n");
	}

	/* PCI resourse allocation */
	err = pci_request_region(pci, 0, "MCST I2S Chip");
	if (err < 0) {
		kfree(chip);
		pci_disable_device(pci);
		return err;
	}
	chip->iobase_phys = pci_resource_start(pci, 0);
	chip->iobase_virt = ioremap(chip->iobase_phys,
								pci_resource_len(pci, 0));
	if (chip->iobase_virt == NULL) {
		dev_err(&pci->dev, "ioremap error\n");
		return -ENXIO;
	}
	if (request_irq(pci->irq, l_i2s_interrupt,
					IRQF_SHARED, KBUILD_MODNAME, chip)) {
		dev_err(&pci->dev, "cannot grab irq %d\n", pci->irq);
		l_i2s_free(chip);
		return -EBUSY;
	}
	chip->irq = pci->irq;

	/* Clear interrupt status */
	l_i2s_write_reg(chip, INTSTS, (
						INTSTS_SB1E |
						INTSTS_SB2E |
						INTSTS_MB1F |
						INTSTS_MB2F |
						INTSTS_DMA_SDOD |
						INTSTS_DMA_MDD));
	/* Unmask interrupts */
	l_i2s_write_reg(chip, INT_EN_MASK, (
						INTSTS_SB1E |
						INTSTS_SB2E |
						INTSTS_MB1F |
						INTSTS_MB2F));

	/* Initialization of the chip hardware */

	chip->spi_ctrl = l_i2s_spi_probe(pci);
	if (IS_ERR(chip->spi_ctrl)) {
		dev_err(&pci->dev, "problem with probing spi controller\n");
		l_i2s_free(chip);
		return -EINVAL;
	}

	*rchip = chip;
	return 0;
}

static const struct snd_soc_component_driver l_i2s_dai_component = {
	.name		= "l_i2s_dai_component",
	.pcm_construct	= l_i2s_pcm_new,
	.pointer	= l_i2s_pointer,
};

static struct snd_soc_dai_driver l_i2s_soc_dai = {
	.name = "l_i2s_soc_dai",
	.playback = {
		.channels_min = 1,
		.channels_max = 2,
		.rates = SNDRV_PCM_RATE_48000,
		.rate_min = 48000,
		.rate_max = 48000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE,
	},
	.capture = {
		.channels_min = 1,
		.channels_max = 2,
		.rates = SNDRV_PCM_RATE_48000,
		.rate_min = 48000,
		.rate_max = 48000,
		.formats = SNDRV_PCM_FMTBIT_S16_LE,
	},
	.symmetric_rates = 1,
	.ops = &l_i2s_soc_dai_ops,
};

static int l_i2s_probe(struct pci_dev *pci, const struct pci_device_id *pci_id)
{
	static int dev;
	struct l_i2s_chip *chip;
	int err;

	if (dev >= SNDRV_CARDS)
		return -ENODEV;
	if (!enable[dev]) {
		dev++;
		return -ENOENT;
	}

	err = l_i2s_create(pci, &chip);
	if (err < 0) {
		return err;
	}

	err = devm_snd_soc_register_component(&pci->dev, &l_i2s_dai_component,
							 &l_i2s_soc_dai, 1);

	pci_set_drvdata(pci, chip);
	dev++;
	return 0;
}

static void l_i2s_remove(struct pci_dev *pci)
{
	struct l_i2s_chip *chip;
	chip = pci_get_drvdata(pci);
	l_i2s_free(chip);
	pci_set_drvdata(pci, NULL);
}

/* PCI IDs */
static const struct pci_device_id l_i2s_ids[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MCST_TMP, 0x8048) },
	{ 0, },
};
MODULE_DEVICE_TABLE(pci, l_i2s_ids);

/* pci driver definition */
static struct pci_driver l_i2s_pci_driver = {
	.name = "l_i2s",
	.id_table = l_i2s_ids,
	.probe = l_i2s_probe,
	.remove = l_i2s_remove,
};

module_pci_driver(l_i2s_pci_driver);

MODULE_AUTHOR("MCST");
MODULE_DESCRIPTION("MCST I2S controller driver");
MODULE_LICENSE("GPL v2");
