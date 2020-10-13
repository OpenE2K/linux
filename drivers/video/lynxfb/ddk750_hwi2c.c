/*******************************************************************
*Copyright (c) 2012 by Silicon Motion, Inc. (SMI)
*Permission is hereby granted, free of charge, to any person obtaining a copy
*of this software and associated documentation files (the "Software"), to deal
*in the Software without restriction, including without limitation the rights to
*use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
*of the Software, and to permit persons to whom the Software is furnished to
*do so, subject to the following conditions:
*
*THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
*EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
*OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
*NONINFRINGEMENT.  IN NO EVENT SHALL Mill.Chen and Monk.Liu OR COPYRIGHT
*HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
*WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
*FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
*OTHER DEALINGS IN THE SOFTWARE.
*******************************************************************/
#ifdef USE_HW_I2C
#include "ddk750_help.h"
#include "ddk750_reg.h"
#include "ddk750_hwi2c.h"
#include "ddk750_power.h"

#define MAX_HWI2C_FIFO                  16
#define HWI2C_WAIT_TIMEOUT              0xF0000

#ifdef CONFIG_FB_LYNXFB_DOMAINS
int hwI2CInit(unsigned char busSpeedMode, int domain)
{
	unsigned int value;

	/* Enable GPIO 30 & 31 as IIC clock & data */
	value = PEEK32(GPIO_MUX, domain);

	value |= (1 << GPIO_MUX_30_LSB) | (1 << GPIO_MUX_31_LSB);
	POKE32(GPIO_MUX, value, domain);

	/* Enable Hardware I2C power.
	   TODO: Check if we need to enable GPIO power?
	 */
	enableI2C(1, domain);

	/* Enable the I2C Controller and set the bus speed mode */
	value = PEEK32(I2C_CTRL, domain);

	if (busSpeedMode == 0)
		value &= ~(1 << I2C_CTRL_MODE_LSB);
	else
		value |= 1 << I2C_CTRL_MODE_LSB;
	value |= 1 << I2C_CTRL_EN_LSB;

	POKE32(I2C_CTRL, value, domain);

	return 0;
}


void hwI2CClose(int domain)
{
	unsigned int value;

	/* Disable I2C controller */
	value = PEEK32(I2C_CTRL, domain);

	value &= ~(1 << I2C_CTRL_EN_LSB);
	POKE32(I2C_CTRL, value, domain);

	/* Disable I2C Power */
	enableI2C(0, domain);

	/* Set GPIO 30 & 31 back as GPIO pins */
	value = PEEK32(GPIO_MUX, domain);
	value &= ~(1 << GPIO_MUX_30_LSB);
	value &= ~(1 << GPIO_MUX_31_LSB);
	POKE32(GPIO_MUX, value, domain);
}


long hwI2CWaitTXDone(int domain)
{
	unsigned int timeout;

	/* Wait until the transfer is completed. */
	timeout = HWI2C_WAIT_TIMEOUT;

	while (((1 & (PEEK32(I2C_STATUS, domain) >> I2C_STATUS_TX_LSB)) !=
		I2C_STATUS_TX_COMPLETED) && (timeout != 0))
		timeout--;

	if (timeout == 0)
		return -1;

	return 0;
}



/*
 *  This function writes data to the i2c slave device registers.
 *
 *  Parameters:
 *      deviceAddress   - i2c Slave device address
 *      length          - Total number of bytes to be written to the device
 *      pBuffer         - The buffer that contains the data to be written to the
 *                     i2c device.
 *	domain		- NUMA domain id, where chip belongs to
 *
 *  Return Value:
 *      Total number of bytes those are actually written.
 */
unsigned int hwI2CWriteData(unsigned char deviceAddress,
		    unsigned int length, unsigned char *pBuffer, int domain)
{
	unsigned char count, i;
	unsigned int totalBytes = 0;

	/* Set the Device Address */
	POKE32(I2C_SLAVE_ADDRESS, deviceAddress & ~0x01, domain);

	/* Write data.
	 * Note:
	 *      Only 16 byte can be accessed per i2c start instruction.
	 */
	do {
		/* Reset I2C by writing 0 to I2C_RESET register to clear the previous status. */
		POKE32(I2C_RESET, 0, domain);

		/* Set the number of bytes to be written */
		if (length < MAX_HWI2C_FIFO)
			count = length - 1;
		else
			count = MAX_HWI2C_FIFO - 1;
		POKE32(I2C_BYTE_COUNT, count, domain);

		/* Move the data to the I2C data register */
		for (i = 0; i <= count; i++)
			POKE32(I2C_DATA0 + i, *pBuffer++, domain);

		/* Start the I2C */

		POKE32(I2C_CTRL,
		       PEEK32(I2C_CTRL, domain) | (1 << I2C_CTRL_CTRL_LSB), domain);

		/* Wait until the transfer is completed. */
		if (hwI2CWaitTXDone(domain) != 0)
			break;

		/* Substract length */
		length -= (count + 1);

		/* Total byte written */
		totalBytes += (count + 1);

	} while (length > 0);

	return totalBytes;
}




/*
 *  This function reads data from the slave device and stores them
 *  in the given buffer
 *
 *  Parameters:
 *      deviceAddress   - i2c Slave device address
 *      length          - Total number of bytes to be read
 *      pBuffer         - Pointer to a buffer to be filled with the data read
 *                     from the slave device. It has to be the same size as the
 *                     length to make sure that it can keep all the data read.
 *	domain		- NUMA domain id, where chip belongs to
 *
 *  Return Value:
 *      Total number of actual bytes read from the slave device
 */
unsigned int hwI2CReadData(unsigned char deviceAddress,
		   unsigned int length, unsigned char *pBuffer, int domain)
{
	unsigned char count, i;
	unsigned int totalBytes = 0;

	/* Set the Device Address */
	POKE32(I2C_SLAVE_ADDRESS, deviceAddress | 0x01, domain);

	/* Read data and save them to the buffer.
	 * Note:
	 *      Only 16 byte can be accessed per i2c start instruction.
	 */
	do {
		/* Reset I2C by writing 0 to I2C_RESET register to clear all the status. */
		POKE32(I2C_RESET, 0, domain);

		/* Set the number of bytes to be read */
		if (length <= MAX_HWI2C_FIFO)
			count = length - 1;
		else
			count = MAX_HWI2C_FIFO - 1;
		POKE32(I2C_BYTE_COUNT, count, domain);

		/* Start the I2C */
		POKE32(I2C_CTRL,
		       PEEK32(I2C_CTRL, domain) | (1 << I2C_CTRL_CTRL_LSB), domain);

		/* Wait until transaction done. */
		if (hwI2CWaitTXDone(domain) != 0)
			break;

		/* Save the data to the given buffer */
		for (i = 0; i <= count; i++)
			*pBuffer++ = PEEK32(I2C_DATA0 + i, domain);

		/* Substract length by 16 */
		length -= (count + 1);

		/* Number of bytes read. */
		totalBytes += (count + 1);

	} while (length > 0);

	return totalBytes;
}




/*
 *  This function reads the slave device's register
 *
 *  Parameters:
 *      deviceAddress   - i2c Slave device address which register
 *                        to be read from
 *      registerIndex   - Slave device's register to be read
 *	domain		- NUMA domain id, where chip belongs to
 *
 *  Return Value:
 *      Register value
 */
unsigned char hwI2CReadReg(unsigned char deviceAddress,
			   unsigned char registerIndex,
			   int domain)
{
	unsigned char value = (0xFF);

	if (hwI2CWriteData(deviceAddress, 1, &registerIndex, domain) == 1)
		hwI2CReadData(deviceAddress, 1, &value, domain);

	return value;
}





/*
 *  This function writes a value to the slave device's register
 *
 *  Parameters:
 *      deviceAddress   - i2c Slave device address which register
 *                        to be written
 *      registerIndex   - Slave device's register to be written
 *      data            - Data to be written to the register
 *	domain		- NUMA domain id, where chip belongs to
 *
 *  Result:
 *          0   - Success
 *         -1   - Fail
 */
int hwI2CWriteReg(unsigned char deviceAddress,
		  unsigned char registerIndex, unsigned char data,
		  int domain)
{
	unsigned char value[2];

	value[0] = registerIndex;
	value[1] = data;
	if (hwI2CWriteData(deviceAddress, 2, value, domain) == 2)
		return 0;

	return -1;
}
#else /* !CONFIG_FB_LYNXFB_DOMAINS: */
int hwI2CInit(unsigned char busSpeedMode)
{
	unsigned int value;

	/* Enable GPIO 30 & 31 as IIC clock & data */
	value = PEEK32(GPIO_MUX);

	value |= (1 << GPIO_MUX_30_LSB) | (1 << GPIO_MUX_31_LSB);
	POKE32(GPIO_MUX, value);

	/* Enable Hardware I2C power.
	   TODO: Check if we need to enable GPIO power?
	 */
	enableI2C(1);

	/* Enable the I2C Controller and set the bus speed mode */
	value = PEEK32(I2C_CTRL);

	if (busSpeedMode == 0)
		value &= ~(1 << I2C_CTRL_MODE_LSB);
	else
		value |= 1 << I2C_CTRL_MODE_LSB;
	value |= 1 << I2C_CTRL_EN_LSB;

	POKE32(I2C_CTRL, value);

	return 0;
}


void hwI2CClose(void)
{
	unsigned int value;

	/* Disable I2C controller */
	value = PEEK32(I2C_CTRL);

	value &= ~(1 << I2C_CTRL_EN_LSB);
	POKE32(I2C_CTRL, value);

	/* Disable I2C Power */
	enableI2C(0);

	/* Set GPIO 30 & 31 back as GPIO pins */
	value = PEEK32(GPIO_MUX);
	value &= ~(1 << GPIO_MUX_30_LSB);
	value &= ~(1 << GPIO_MUX_31_LSB);
	POKE32(GPIO_MUX, value);
}


long hwI2CWaitTXDone(void)
{
	unsigned int timeout;

	/* Wait until the transfer is completed. */
	timeout = HWI2C_WAIT_TIMEOUT;

	while (((1 & (PEEK32(I2C_STATUS) >> I2C_STATUS_TX_LSB)) !=
		I2C_STATUS_TX_COMPLETED) && (timeout != 0))
		timeout--;

	if (timeout == 0)
		return -1;

	return 0;
}



/*
 *  This function writes data to the i2c slave device registers.
 *
 *  Parameters:
 *      deviceAddress   - i2c Slave device address
 *      length          - Total number of bytes to be written to the device
 *      pBuffer         - The buffer that contains the data to be written to the
 *                     i2c device.
 *
 *  Return Value:
 *      Total number of bytes those are actually written.
 */
unsigned int hwI2CWriteData(unsigned char deviceAddress,
			    unsigned int length, unsigned char *pBuffer)
{
	unsigned char count, i;
	unsigned int totalBytes = 0;

	/* Set the Device Address */
	POKE32(I2C_SLAVE_ADDRESS, deviceAddress & ~0x01);

	/* Write data.
	 * Note:
	 *      Only 16 byte can be accessed per i2c start instruction.
	 */
	do {
		/* Reset I2C by writing 0 to I2C_RESET register to clear the previous status. */
		POKE32(I2C_RESET, 0);

		/* Set the number of bytes to be written */
		if (length < MAX_HWI2C_FIFO)
			count = length - 1;
		else
			count = MAX_HWI2C_FIFO - 1;
		POKE32(I2C_BYTE_COUNT, count);

		/* Move the data to the I2C data register */
		for (i = 0; i <= count; i++)
			POKE32(I2C_DATA0 + i, *pBuffer++);

		/* Start the I2C */

		POKE32(I2C_CTRL,
		       PEEK32(I2C_CTRL) | (1 << I2C_CTRL_CTRL_LSB));

		/* Wait until the transfer is completed. */
		if (hwI2CWaitTXDone() != 0)
			break;

		/* Substract length */
		length -= (count + 1);

		/* Total byte written */
		totalBytes += (count + 1);

	} while (length > 0);

	return totalBytes;
}




/*
 *  This function reads data from the slave device and stores them
 *  in the given buffer
 *
 *  Parameters:
 *      deviceAddress   - i2c Slave device address
 *      length          - Total number of bytes to be read
 *      pBuffer         - Pointer to a buffer to be filled with the data read
 *                     from the slave device. It has to be the same size as the
 *                     length to make sure that it can keep all the data read.
 *
 *  Return Value:
 *      Total number of actual bytes read from the slave device
 */
unsigned int hwI2CReadData(unsigned char deviceAddress,
			   unsigned int length, unsigned char *pBuffer)
{
	unsigned char count, i;
	unsigned int totalBytes = 0;

	/* Set the Device Address */
	POKE32(I2C_SLAVE_ADDRESS, deviceAddress | 0x01);

	/* Read data and save them to the buffer.
	 * Note:
	 *      Only 16 byte can be accessed per i2c start instruction.
	 */
	do {
		/* Reset I2C by writing 0 to I2C_RESET register to clear all the status. */
		POKE32(I2C_RESET, 0);

		/* Set the number of bytes to be read */
		if (length <= MAX_HWI2C_FIFO)
			count = length - 1;
		else
			count = MAX_HWI2C_FIFO - 1;
		POKE32(I2C_BYTE_COUNT, count);

		/* Start the I2C */
		POKE32(I2C_CTRL,
		       PEEK32(I2C_CTRL) | (1 << I2C_CTRL_CTRL_LSB));

		/* Wait until transaction done. */
		if (hwI2CWaitTXDone() != 0)
			break;

		/* Save the data to the given buffer */
		for (i = 0; i <= count; i++)
			*pBuffer++ = PEEK32(I2C_DATA0 + i);

		/* Substract length by 16 */
		length -= (count + 1);

		/* Number of bytes read. */
		totalBytes += (count + 1);

	} while (length > 0);

	return totalBytes;
}




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
unsigned char hwI2CReadReg(unsigned char deviceAddress,
			   unsigned char registerIndex)
{
	unsigned char value = (0xFF);

	if (hwI2CWriteData(deviceAddress, 1, &registerIndex) == 1)
		hwI2CReadData(deviceAddress, 1, &value);

	return value;
}





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
int hwI2CWriteReg(unsigned char deviceAddress,
		  unsigned char registerIndex, unsigned char data)
{
	unsigned char value[2];

	value[0] = registerIndex;
	value[1] = data;
	if (hwI2CWriteData(deviceAddress, 2, value) == 2)
		return 0;

	return -1;
}
#endif /* !CONFIG_FB_LYNXFB_DOMAINS */

#endif
