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
#include "ddk750_help.h"
#include "ddk750_reg.h"
#include "ddk750_swi2c.h"
#include "ddk750_power.h"
#include "lynx_drv.h"


/*******************************************************************
 * I2C Software Master Driver:
 * ===========================
 * Each i2c cycle is split into 4 sections. Each of these section marks
 * a point in time where the SCL or SDA may be changed.
 *
 * 1 Cycle == |  Section I. |  Section 2. |  Section 3. |  Section 4. |
 *            +-------------+-------------+-------------+-------------+
 *            | SCL set LOW |SCL no change| SCL set HIGH|SCL no change|
 *
 *                                          ____________ _____________
 * SCL == XXXX _____________ ____________ /
 *
 * I.e. the SCL may only be changed in section 1. and section 3. while
 * the SDA may only be changed in section 2. and section 4. The table
 * below gives the changes for these 2 lines in the varios sections.
 *
 * Section changes Table:
 * ======================
 * blank = no change, L = set bit LOW, H = set bit HIGH
 *
 *                                | 1.| 2.| 3.| 4.|
 *                 ---------------+---+---+---+---+
 *                 Tx Start   SDA |   | H |   | L |
 *                            SCL | L |   | H |   |
 *                 ---------------+---+---+---+---+
 *                 Tx Stop    SDA |   | L |   | H |
 *                            SCL | L |   | H |   |
 *                 ---------------+---+---+---+---+
 *                 Tx bit H   SDA |   | H |   |   |
 *                            SCL | L |   | H |   |
 *                 ---------------+---+---+---+---+
 *                 Tx bit L   SDA |   | L |   |   |
 *                            SCL | L |   | H |   |
 *                 ---------------+---+---+---+---+
 *
 ******************************************************************/

/* GPIO pins used for this I2C. It ranges from 0 to 63. */
static unsigned char g_i2cClockGPIO = DEFAULT_I2C_SCL;
static unsigned char g_i2cDataGPIO = DEFAULT_I2C_SDA;

/*
 *  Below is the variable declaration for the GPIO pin register usage
 *  for the i2c Clock and i2c Data.
 *
 *  Note:
 *      Notice that the GPIO usage for the i2c clock and i2c Data are
 *      separated. This is to make this code flexible enough when
 *      two separate GPIO pins for the clock and data are located
 *      in two different GPIO register set (worst case).
 */

/* i2c Clock GPIO Register usage */
static unsigned long g_i2cClkGPIOMuxReg = GPIO_MUX;
static unsigned long g_i2cClkGPIODataReg = GPIO_DATA;
static unsigned long g_i2cClkGPIODataDirReg = GPIO_DATA_DIRECTION;

/* i2c Data GPIO Register usage */
static unsigned long g_i2cDataGPIOMuxReg = GPIO_MUX;
static unsigned long g_i2cDataGPIODataReg = GPIO_DATA;
static unsigned long g_i2cDataGPIODataDirReg = GPIO_DATA_DIRECTION;

/*
 *  This function puts a delay between command
 */
static void swI2CWait(void)
{
	/* find a bug:
	 * peekIO method works well before suspend/resume
	 * but after suspend, peekIO(0x3ce,0x61) & 0x10
	 * always be non-zero,which makes the while loop
	 * never finish.
	 * use non-ultimate for loop below is safe
	 * */
	int i, Temp;

	for (i = 0; i < 600; i++) {
		Temp = i;
		Temp += i;
	}
}

/*
 *  This function set/reset the SCL GPIO pin
 *
 *  Parameters:
 *      value    - Bit value to set to the SCL or SDA (0 = low, 1 = high)
 *
 *  Notes:
 *      When setting SCL to high, just set the GPIO as input where the pull up
 *      resistor will pull the signal up. Do not use software to pull up the
 *      signal because the i2c will fail when other device try to drive the
 *      signal due to SM50x will drive the signal to always high.
 */
void swI2CSCL(struct lynx_share *share, unsigned char value)
{
	unsigned long ulGPIOData;
	unsigned long ulGPIODirection;

	ulGPIODirection = PEEK32(share->pvReg, g_i2cClkGPIODataDirReg);
	if (value) {		/* High */
		/* Set direction as input. This will automatically pull the signal up. */
		ulGPIODirection &= ~(1 << g_i2cClockGPIO);
		POKE32(share->pvReg, g_i2cClkGPIODataDirReg, ulGPIODirection);
	} else {		/* Low */
		/* Set the signal down */
		ulGPIOData = PEEK32(share->pvReg, g_i2cClkGPIODataReg);
		ulGPIOData &= ~(1 << g_i2cClockGPIO);
		POKE32(share->pvReg, g_i2cClkGPIODataReg, ulGPIOData);

		/* Set direction as output */
		ulGPIODirection |= (1 << g_i2cClockGPIO);
		POKE32(share->pvReg, g_i2cClkGPIODataDirReg, ulGPIODirection);
	}
}

/*
 *  This function set/reset the SDA GPIO pin
 *
 *  Parameters:
 *      value    - Bit value to set to the SCL or SDA (0 = low, 1 = high)
 *
 *  Notes:
 *      When setting SCL to high, just set the GPIO as input where the pull up
 *      resistor will pull the signal up. Do not use software to pull up the
 *      signal because the i2c will fail when other device try to drive the
 *      signal due to SM50x will drive the signal to always high.
 */
void swI2CSDA(struct lynx_share *share, unsigned char value)
{
	unsigned long ulGPIOData;
	unsigned long ulGPIODirection;

	ulGPIODirection = PEEK32(share->pvReg, g_i2cDataGPIODataDirReg);
	if (value) {		/* High */
		/* Set direction as input. This will automatically pull the signal up. */
		ulGPIODirection &= ~(1 << g_i2cDataGPIO);
		POKE32(share->pvReg, g_i2cDataGPIODataDirReg, ulGPIODirection);
	} else {		/* Low */
		/* Set the signal down */
		ulGPIOData = PEEK32(share->pvReg, g_i2cDataGPIODataReg);
		ulGPIOData &= ~(1 << g_i2cDataGPIO);
		POKE32(share->pvReg, g_i2cDataGPIODataReg, ulGPIOData);

		/* Set direction as output */
		ulGPIODirection |= (1 << g_i2cDataGPIO);
		POKE32(share->pvReg, g_i2cDataGPIODataDirReg, ulGPIODirection);
	}
}

/*
 *  This function read the data from the SDA GPIO pin
 *
 *  Return Value:
 *      The SDA data bit sent by the Slave
 */
static unsigned char swI2CReadSDA(struct lynx_share *share)
{
	unsigned long ulGPIODirection;
	unsigned long ulGPIOData;

	/* Make sure that the direction is input (High) */
	ulGPIODirection = PEEK32(share->pvReg, g_i2cDataGPIODataDirReg);
	if ((ulGPIODirection & (1 << g_i2cDataGPIO))
	    != (~(1 << g_i2cDataGPIO))) {
		ulGPIODirection &= ~(1 << g_i2cDataGPIO);
		POKE32(share->pvReg, g_i2cDataGPIODataDirReg, ulGPIODirection);
	}

	/* Now read the SDA line */
	ulGPIOData = PEEK32(share->pvReg, g_i2cDataGPIODataReg);
	if (ulGPIOData & (1 << g_i2cDataGPIO))
		return 1;
	else
		return 0;
}

/*
 *  This function sends ACK signal
 */
static void swI2CAck(void)
{
	return;			/* Single byte read is ok without it. */
}

/*
 *  This function sends the start command to the slave device
 */
void swI2CStart(struct lynx_share *share)
{
	/* Start I2C */
	swI2CSDA(share, 1);
	swI2CSCL(share, 1);
	swI2CSDA(share, 0);
}

/*
 *  This function sends the stop command to the slave device
 */
void swI2CStop(struct lynx_share *share)
{
	/* Stop the I2C */
	swI2CSCL(share, 1);
	swI2CSDA(share, 0);
	swI2CSDA(share, 1);
}

/*
 *  This function writes one byte to the slave device
 *
 *  Parameters:
 *      data    - Data to be write to the slave device
 *
 *  Return Value:
 *       0   - Success
 *      -1   - Fail to write byte
 */
long swI2CWriteByte(struct lynx_share *share, unsigned char data)
{
	unsigned char value = data;
	int i;

	/* Sending the data bit by bit */
	for (i = 0; i < 8; i++) {
		/* Set SCL to low */
		swI2CSCL(share, 0);

		/* Send data bit */
		if ((value & 0x80) != 0)
			swI2CSDA(share, 1);
		else
			swI2CSDA(share, 0);

		swI2CWait();

		/* Toggle clk line to one */
		swI2CSCL(share, 1);
		swI2CWait();

		/* Shift byte to be sent */
		value = value << 1;
	}

	/* Set the SCL Low and SDA High (prepare to get input) */
	swI2CSCL(share, 0);
	swI2CSDA(share, 1);

	/* Set the SCL High for ack */
	swI2CWait();
	swI2CSCL(share, 1);
	swI2CWait();

	/* Read SDA, until SDA==0 */
	for (i = 0; i < 0xff; i++) {
		if (!swI2CReadSDA(share))
			break;

		swI2CSCL(share, 0);
		swI2CWait();
		swI2CSCL(share, 1);
		swI2CWait();
	}

	/* Set the SCL Low and SDA High */
	swI2CSCL(share, 0);
	swI2CSDA(share, 1);

	if (i < 0xff)
		return 0;
	else
		return -1;
}

/*
 *  This function reads one byte from the slave device
 *
 *  Parameters:
 *      ack    - Flag to indicate either to send the acknowledge
 *            message to the slave device or not
 *
 *  Return Value:
 *      One byte data read from the Slave device
 */
unsigned char swI2CReadByte(struct lynx_share *share, unsigned char ack)
{
	int i;
	unsigned char data = 0;

	for (i = 7; i >= 0; i--) {
		/* Set the SCL to Low and SDA to High (Input) */
		swI2CSCL(share, 0);
		swI2CSDA(share, 1);
		swI2CWait();

		/* Set the SCL High */
		swI2CSCL(share, 1);
		swI2CWait();

		/* Read data bits from SDA */
		data |= (swI2CReadSDA(share) << i);
	}

	if (ack)
		swI2CAck();

	/* Set the SCL Low and SDA High */
	swI2CSCL(share, 0);
	swI2CSDA(share, 1);

	return data;
}

/*
 * This function initializes GPIO port for SW I2C communication.
 *
 * Parameters:
 *      i2cClkGPIO      - The GPIO pin to be used as i2c SCL
 *      i2cDataGPIO     - The GPIO pin to be used as i2c SDA
 *
 * Return Value:
 *      -1   - Fail to initialize the i2c
 *       0   - Success
 */
long swI2CInit_SM750LE(struct lynx_share *share,
				unsigned char i2cClkGPIO, unsigned char i2cDataGPIO)
{
	int i;

	/* Initialize the GPIO pin for the i2c Clock Register */
	g_i2cClkGPIODataReg = GPIO_DATA_SM750LE;
	g_i2cClkGPIODataDirReg = GPIO_DATA_DIRECTION_SM750LE;

	/* Initialize the Clock GPIO Offset */
	g_i2cClockGPIO = i2cClkGPIO;

	/* Initialize the GPIO pin for the i2c Data Register */
	g_i2cDataGPIODataReg = GPIO_DATA_SM750LE;
	g_i2cDataGPIODataDirReg = GPIO_DATA_DIRECTION_SM750LE;

	/* Initialize the Data GPIO Offset */
	g_i2cDataGPIO = i2cDataGPIO;

	/* Note that SM750LE don't have GPIO MUX and power is always on */

	/* Clear the i2c lines. */
	for (i = 0; i < 9; i++)
		swI2CStop(share);

	return 0;
}

/*
 * This function initializes the i2c attributes and bus
 *
 * Parameters:
 *      i2cClkGPIO      - The GPIO pin to be used as i2c SCL
 *      i2cDataGPIO     - The GPIO pin to be used as i2c SDA
 *
 * Return Value:
 *      -1   - Fail to initialize the i2c
 *       0   - Success
 */
long swI2CInit(struct lynx_share *share,
				unsigned char i2cClkGPIO, unsigned char i2cDataGPIO)
{
	int i;

	/* Return 0 if the GPIO pins to be used is out of range. The range is only from [0..63] */
	if ((i2cClkGPIO > 31) || (i2cDataGPIO > 31))
		return -1;

	if (getChipType(share) == SM750LE)
		return swI2CInit_SM750LE(share, i2cClkGPIO, i2cDataGPIO);

	/* Initialize the GPIO pin for the i2c Clock Register */
	g_i2cClkGPIOMuxReg = GPIO_MUX;
	g_i2cClkGPIODataReg = GPIO_DATA;
	g_i2cClkGPIODataDirReg = GPIO_DATA_DIRECTION;

	/* Initialize the Clock GPIO Offset */
	g_i2cClockGPIO = i2cClkGPIO;

	/* Initialize the GPIO pin for the i2c Data Register */
	g_i2cDataGPIOMuxReg = GPIO_MUX;
	g_i2cDataGPIODataReg = GPIO_DATA;
	g_i2cDataGPIODataDirReg = GPIO_DATA_DIRECTION;

	/* Initialize the Data GPIO Offset */
	g_i2cDataGPIO = i2cDataGPIO;

	/* Enable the GPIO pins for the i2c Clock and Data (GPIO MUX) */
	POKE32(share->pvReg, g_i2cClkGPIOMuxReg,
	       PEEK32(share->pvReg, g_i2cClkGPIOMuxReg) & ~(1 << g_i2cClockGPIO));
	POKE32(share->pvReg, g_i2cDataGPIOMuxReg,
	       PEEK32(share->pvReg, g_i2cDataGPIOMuxReg) & ~(1 << g_i2cDataGPIO));

	/* Enable GPIO power */
	enableGPIO(share, 1);

	/* Clear the i2c lines. */
	for (i = 0; i < 9; i++)
		swI2CStop(share);

	return 0;
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
unsigned char swI2CReadReg(struct lynx_share *share,
				unsigned char deviceAddress,
				unsigned char registerIndex)
{
	unsigned char data;

	/* Send the Start signal */
	swI2CStart(share);

	/* Send the device address */
	swI2CWriteByte(share, deviceAddress);

	/* Send the register index */
	swI2CWriteByte(share, registerIndex);

	/* Get the bus again and get the data from the device read address */
	swI2CStart(share);
	swI2CWriteByte(share, deviceAddress + 1);
	data = swI2CReadByte(share, 1);

	/* Stop swI2C and release the bus */
	swI2CStop(share);

	return data;
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
long swI2CWriteReg(struct lynx_share *share, unsigned char deviceAddress,
		   unsigned char registerIndex, unsigned char data)
{
	long returnValue = 0;

	/* Send the Start signal */
	swI2CStart(share);

	/* Send the device address and read the data. All should return success
	   in order for the writing processed to be successful
	 */
	if ((swI2CWriteByte(share, deviceAddress) != 0) ||
	    (swI2CWriteByte(share, registerIndex) != 0) ||
	    (swI2CWriteByte(share, data) != 0)) {
		returnValue = -1;
	}

	/* Stop i2c and release the bus */
	swI2CStop(share);

	return returnValue;
}
