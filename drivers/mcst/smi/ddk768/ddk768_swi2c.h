/*******************************************************************
* 
*         Copyright (c) 2007 by Silicon Motion, Inc. (SMI)
* 
*  All rights are reserved. Reproduction or in part is prohibited
*  without the written consent of the copyright owner.
* 
*  swi2c.h --- SM750/SM718 DDK 
*  This file contains the definitions for i2c using software 
*  implementation.
* 
*******************************************************************/
#ifndef _DDK768_SWI2C_H_
#define _DDK768_SWI2C_H_

/* Default i2c CLK and Data GPIO. These are the default i2c pins */
#define DEFAULT_I2C0_SCL                     30
#define DEFAULT_I2C0_SDA                     31

#define DEFAULT_I2C1_SCL                     6
#define DEFAULT_I2C1_SDA                     7

/*
 * This function initializes the i2c attributes and bus
 *
 * Parameters:
 *      i2cClkGPIO  - The GPIO pin to be used as i2c SCL
 *      i2cDataGPIO - The GPIO pin to be used as i2c SDA
 *
 * Return Value:
 *      -1   - Fail to initialize the i2c
 *       0   - Success
 */
long ddk768_swI2CInit(
	struct smi_device *sdev,
    unsigned char i2cClkGPIO, 
    unsigned char i2cDataGPIO
);

/*
 *  This function reads the slave device's register
 *
 *  Parameters:
 *      deviceAddress   - i2c Slave device address which register
 *                        to be read from
 *      registerIndex   - Slave device's register to be read
 *
 *  Return Value:
 *      Register value
 */
unsigned char ddk768_swI2CReadReg(
	struct smi_device *sdev,
    unsigned char deviceAddress, 
    unsigned char registerIndex
);

/*
 *  This function writes a value to the slave device's register
 *
 *  Parameters:
 *      deviceAddress   - i2c Slave device address which register
 *                        to be written
 *      registerIndex   - Slave device's register to be written
 *      data            - Data to be written to the register
 *
 *  Result:
 *          0   - Success
 *         -1   - Fail
 */
long ddk768_swI2CWriteReg(
	struct smi_device *sdev,
    unsigned char deviceAddress, 
    unsigned char registerIndex, 
    unsigned char data
);

/*
 *  These two functions are used to toggle the data on the SCL and SDA I2C lines.
 *  The used of these two functions are not recommended unless it is necessary.
 */

/*
 *  This function set/reset the SCL GPIO pin
 *
 *  Parameters:
 *      value	- Bit value to set to the SCL or SDA (0 = low, 1 = high)
 */ 
void ddk768_swI2CSCL(struct smi_device *sdev, unsigned char value);

/*
 *  This function set/reset the SDA GPIO pin
 *
 *  Parameters:
 *      value	- Bit value to set to the SCL or SDA (0 = low, 1 = high)
 */
void ddk768_swI2CSDA(struct smi_device *sdev, unsigned char value);

#endif  /* _SWI2C_H_ */
