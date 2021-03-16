/*
 * i2c-l-i2c2.h - Elbrus l-i2c2 I2C driver header file
 *
 *
 * This file is released under the GPLv2
 */

#ifndef __ASM_L_I2C2_H_
#define __ASM_L_I2C2_H_

/**
 * struct l_i2c2_platform_data - structure of platform data for Elbrus I2C driver
 * @bus_nr:		Bus number
 * @base_freq_hz:	base frequency measured in Hz
 * @desired_freq_hz:	Bus speed measured in Hz
 * @two_stage_register_access:	write address, then read value
 *
 **/
struct l_i2c2_platform_data {
	int bus_nr;
	unsigned base_freq_hz;
	unsigned desired_freq_hz;
	bool two_stage_register_access;
};

#endif /* __ASM_L_I2C2_H_ */
