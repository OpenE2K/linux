/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/**
 * mxgbe_gpio.c - MXGBE module device driver
 *
 */

#include <linux/gpio.h>

#include "mxgbe.h"
#include "mxgbe_dbg.h"
#include "mxgbe_hw.h"
#include "kcompat.h"

#include "mxgbe_gpio.h"


#define GPIO_LED_LINK		SET_BIT(3)
#define GPIO_LED_TX		SET_BIT(2)
#define GPIO_LED_RX		SET_BIT(1)
#define GPIO_PHY_RESET		SET_BIT(0)

#define GPIO_ALL_LED	(GPIO_LED_RX | GPIO_LED_TX | GPIO_LED_LINK)


static int gpio_get(struct gpio_chip *chip, unsigned offset)
{
	u32 val;
	mxgbe_priv_t *priv = dev_get_drvdata(chip->MXGBE_I2C_CHIPDEV);
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_GPIO, &priv->pdev->dev,
		"gpio_get: offset=%u\n", offset);

	val = mxgbe_rreg32(base, GPIO_IN);

	return (val >> (offset + 1)) & 1;
} /* gpio_get */


static int gpio_direction_out(struct gpio_chip *chip, unsigned offset,
				   int value)
{
#ifdef DEBUG
	mxgbe_priv_t *priv = dev_get_drvdata(chip->MXGBE_I2C_CHIPDEV);
#endif /* DEBUG */

	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_GPIO, &priv->pdev->dev,
		"gpio_direction_out: offset=%u, value=%d\n", offset, value);

	/* This only drives GPOs, and can't change direction */
	return 0;
} /* gpio_direction_out */


static void gpio_set(struct gpio_chip *chip, unsigned offset, int value)
{
	u32 gpoctl = 0;
	mxgbe_priv_t *priv = dev_get_drvdata(chip->MXGBE_I2C_CHIPDEV);
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	DEV_DBG(MXGBE_DBG_MSK_GPIO, &priv->pdev->dev,
		"gpio_set: offset=%u, value=%d\n", offset, value);

	gpoctl = 1 << (offset + 1); /* don't change reset */
	if (value)
		mxgbe_wreg32(base, GPIO_OUTSETRST, gpoctl << 8); /* Set */
	else
		mxgbe_wreg32(base, GPIO_OUTSETRST, gpoctl); /* Clean */
} /* gpio_set */


static struct gpio_chip gpio_chip = {
	.label			= KBUILD_MODNAME,
	.owner			= THIS_MODULE,
	.get			= gpio_get,
	.direction_output	= gpio_direction_out,
	.set			= gpio_set,
	.can_sleep		= true,
};


/**
 ******************************************************************************
 * GPIO Init
 ******************************************************************************
 */

/**
 * First Init MAC (ch2.pdf) at start of probe
 */
void mxgbe_gpio_init(mxgbe_priv_t *priv)
{
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	mxgbe_wreg32(base, GPIO_PUP, 0xFF); /* All P-UP */

	mxgbe_wreg32(base, GPIO_DIR, 0x00); /* All Input */
	mxgbe_wreg32(base, GPIO_OUT, 0x00); /* Clean */
	mxgbe_wreg32(base, GPIO_MUX, 0x00); /* Use as GPIO */

#ifdef GPIO_RESET_PHY
	/* Use GPIO.0 to reset Phy */
	mxgbe_wreg32(base, GPIO_OUTSETRST, GPIO_PHY_RESET << 8); /* Set */
	mxgbe_wreg32(base, GPIO_DIRSETRST, GPIO_PHY_RESET << 8); /* Set */
	DEV_DBG(MXGBE_DBG_MSK_GPIO, &priv->pdev->dev,
		"gpio_init: Use GPIO.0 to reset Phy\n");
#else /* !GPIO_RESET_PHY */
	/* Use MDIO_CSR to reset Phy */
	mxgbe_wreg32(base, GPIO_MUXSETRST, GPIO_PHY_RESET << 8); /* Set */
	DEV_DBG(MXGBE_DBG_MSK_GPIO, &priv->pdev->dev,
		"gpio_init: Use MDIO_CSR to reset Phy\n");
#endif /* GPIO_RESET_PHY */

	if (0 == mxgbe_led_gpio) {
		/* Autocontrol led */
		mxgbe_wreg32(base, GPIO_MUXSETRST, GPIO_ALL_LED << 8);
		DEV_DBG(MXGBE_DBG_MSK_GPIO, &priv->pdev->dev,
			"gpio_init: Autocontrol led\n");
	} else {
		/* Enable led as gpio */
		mxgbe_wreg32(base, GPIO_OUTSETRST, GPIO_ALL_LED); /* Clean */
		mxgbe_wreg32(base, GPIO_DIRSETRST, GPIO_ALL_LED << 8);
		DEV_DBG(MXGBE_DBG_MSK_GPIO, &priv->pdev->dev,
			"gpio_init: Enable led as gpio\n");
	}
} /* mxgbe_gpio_init */


#ifdef GPIO_RESET_PHY

void mxgbe_gpio_phy_reset(mxgbe_priv_t *priv)
{
	void __iomem *base = priv->bar0_base;

	FDEBUG;

	/* Use GPIO.0 to reset Phy */
	mxgbe_wreg32(base, GPIO_OUTSETRST, GPIO_PHY_RESET); /* Clean */
	mdelay(1);
	mxgbe_wreg32(base, GPIO_OUTSETRST, GPIO_PHY_RESET << 8); /* Set */
	mdelay(1);
} /* mxgbe_gpio_phy_reset */

#endif /* GPIO_RESET_PHY */


int mxgbe_gpio_probe(mxgbe_priv_t *priv)
{
	int ret;

	FDEBUG;

	gpio_chip.ngpio = 0;
	if (0 == mxgbe_led_gpio)
		return 0;

	gpio_chip.base = -1;
	gpio_chip.ngpio = 3; /* have 3 GPO */
	gpio_chip.MXGBE_I2C_CHIPDEV = &priv->pdev->dev;

	ret = gpiochip_add(&gpio_chip);
	if (ret < 0) {
		dev_err(&priv->pdev->dev,
			"ERROR: could not register gpiochip, %d\n", ret);
		gpio_chip.ngpio = 0;
	}
	dev_info(&priv->pdev->dev, "register gpiochip: ngpio=%d, base=%d\n",
		 gpio_chip.ngpio, gpio_chip.base);

	return ret;
} /* mxgbe_gpio_probe */


void mxgbe_gpio_remove(void)
{
	FDEBUG;

	if (0 == gpio_chip.ngpio)
		return;

	gpiochip_remove(&gpio_chip);
} /* mxgbe_gpio_remove */
