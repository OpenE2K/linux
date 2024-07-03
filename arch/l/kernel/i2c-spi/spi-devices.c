/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/platform_device.h>
#include <linux/spi/spi.h>
#include <asm/mpspec.h>
#include <asm-l/i2c-spi.h>
#include <asm-l/devtree.h>

#if defined(CONFIG_RTC_DRV_CY14B101P)
static struct spi_board_info spi_rtc_cy14b101p = {
	.modalias	= "rtc-cy14b101p",
	.max_speed_hz	= 16 * 1000 * 1000, /* 16 MHz */
	.mode		= SPI_MODE_0,
	.bus_num	= 0,	/* Matches 'id' of spi_controller device */
	.chip_select	= 1
};
#endif /* CONFIG_RTC_DRV_CY14B101P */

static struct spi_board_info spi_rtc_fm33256 = {
	.modalias	= "rtc-fm33256",
	.max_speed_hz	= 16 * 1000 * 1000, /* 16 MHz */
	.mode		= SPI_MODE_0,
	.bus_num	= 0,	/* Matches 'id' of spi_controller device */
	.chip_select	= 1
};

static struct spi_board_info spi_rom_s25fl064a = {
#ifdef CONFIG_L_MTD_SPI_NOR
	.modalias	= "spi-nor",
#else
	.modalias	= "spidev",
#endif
	/* Actually 50 MHz is supported, but not for the READ
	 * command which is usually used by userspace. */
	.max_speed_hz	= 25 * 1000 * 1000, /* 25 MHz */
	.mode		= SPI_MODE_0,
	.bus_num	= 0,
	.chip_select	= 0
};

static int is_cy14b101p_exist(void)
{
	int mbtype = bootblock_virt->info.bios.mb_type;

	/* At first try to use explist definition */
	if (rtc_model) {
		return (rtc_model == MP_RTC_VER_CY14B101P);
	}
	switch (mbtype) {
	case 0: /* use cy14b101p by default */
#ifdef CONFIG_E2K
	case MB_TYPE_E1CP_IOHUB2_RAZBRAKOVSCHIK:
	case MB_TYPE_E1CP_PMC:
#endif
#ifdef CONFIG_E90S
	case MB_TYPE_E90S_SIVUCH2:
	case MB_TYPE_E90S_ATX:
#endif
		return 1;
	default:
#ifdef CONFIG_E2K
		return 1;
#endif
#ifdef CONFIG_E90S
		if (mbtype >= MB_TYPE_E90S_CY14B101P) {
			return 1;
		}
#endif
	}
	return 0;
}

static int register_spi_devices(void)
{
#ifdef CONFIG_OF
	if (devtree_detected)
		return 0;
#endif
	/* Declare SPI devices to the SPI core */
	if (!is_cy14b101p_exist())
		spi_register_board_info(&spi_rtc_fm33256, 1);
# ifdef CONFIG_RTC_DRV_CY14B101P
	else
		spi_register_board_info(&spi_rtc_cy14b101p, 1);
# endif

	spi_register_board_info(&spi_rom_s25fl064a, 1);

	return 0;
}

module_init(register_spi_devices);
