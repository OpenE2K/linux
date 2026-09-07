/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _I2C_SPI_H_
#define _I2C_SPI_H_

/*
 * The platform data for i2c-spi controller devices
 * (resides in device.platform_data).
 */
struct i2c_spi_data {
	int num_chipselect;
	bool i2c_device_exist;
	bool mode1_unsupported;
	bool ext_freq_unsupported;
};
#endif
