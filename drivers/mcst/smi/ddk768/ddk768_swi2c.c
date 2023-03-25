/*******************************************************************
* 
*         Copyright (c) 2007 by Silicon Motion, Inc. (SMI)
* 
*  All rights are reserved. Reproduction or in part is prohibited
*  without the written consent of the copyright owner.
* 
*  swi2c.c --- SM750/SM718 DDK 
*  This file contains the source code for I2C using software
*  implementation.
* 
*******************************************************************/
//#include "defs.h"
#include "ddk768_reg.h"
//#include "ddk768_hardware.h"
#include "ddk768_chip.h"
#include "ddk768_power.h"
#include "ddk768_timer.h"
#include "ddk768_swi2c.h"
#include "ddk768_help.h"
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

/* GPIO pins used for this I2C. It ranges from 0 to 31. */
static unsigned char g_i2cClockGPIO = DEFAULT_I2C0_SCL;
static unsigned char g_i2cDataGPIO = DEFAULT_I2C0_SDA;

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
static void swI2CWait(struct smi_device *sdev)
{
    //SM768 has build-in timer. Use it instead of SW loop.
	timerWaitTicks(sdev, 3, 0x3ff);
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
void ddk768_swI2CSCL(struct smi_device *sdev, unsigned char value)
{
    unsigned long ulGPIOData;
    unsigned long ulGPIODirection;

	ulGPIODirection = __peekRegisterDWord(sdev->rmmio,
								g_i2cClkGPIODataDirReg);
    if (value)      /* High */
    {
        /* Set direction as input. This will automatically pull the signal up. */
        ulGPIODirection &= ~(1 << g_i2cClockGPIO);    
		__pokeRegisterDWord(sdev->rmmio,
						g_i2cClkGPIODataDirReg, ulGPIODirection);
    }
    else            /* Low */
    {
        /* Set the signal down */
		ulGPIOData = peekRegisterDWord(sdev->rmmio, g_i2cClkGPIODataReg);
        ulGPIOData &= ~(1 << g_i2cClockGPIO);
		__pokeRegisterDWord(sdev->rmmio,
						g_i2cClkGPIODataReg, ulGPIOData);

        /* Set direction as output */
        ulGPIODirection |= (1 << g_i2cClockGPIO);        
		__pokeRegisterDWord(sdev->rmmio,
						g_i2cClkGPIODataDirReg, ulGPIODirection);
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
void ddk768_swI2CSDA(struct smi_device *sdev, unsigned char value)
{
    unsigned long ulGPIOData;
    unsigned long ulGPIODirection;

	ulGPIODirection = __peekRegisterDWord(sdev->rmmio,
								g_i2cDataGPIODataDirReg);
    if (value)      /* High */
    {
        /* Set direction as input. This will automatically pull the signal up. */
        ulGPIODirection &= ~(1 << g_i2cDataGPIO);    
		__pokeRegisterDWord(sdev->rmmio,
						g_i2cDataGPIODataDirReg, ulGPIODirection);
    }
    else            /* Low */
    {
        /* Set the signal down */
		ulGPIOData = peekRegisterDWord(sdev->rmmio, g_i2cDataGPIODataReg);
        ulGPIOData &= ~(1 << g_i2cDataGPIO);
		__pokeRegisterDWord(sdev->rmmio,
						g_i2cDataGPIODataReg, ulGPIOData);

        /* Set direction as output */
        ulGPIODirection |= (1 << g_i2cDataGPIO);        
		__pokeRegisterDWord(sdev->rmmio,
						g_i2cDataGPIODataDirReg, ulGPIODirection);
    }
}

/*
 *  This function read the data from the SDA GPIO pin
 *
 *  Return Value:
 *      The SDA data bit sent by the Slave
 */
static unsigned char swI2CReadSDA(struct smi_device *sdev)
{
    unsigned long ulGPIODirection;
    unsigned long ulGPIOData;

    /* Make sure that the direction is input (High) */
	ulGPIODirection = __peekRegisterDWord(sdev->rmmio,
								g_i2cDataGPIODataDirReg);
    if ((ulGPIODirection & (1 << g_i2cDataGPIO)) != (~(1 << g_i2cDataGPIO)))
    {
        ulGPIODirection &= ~(1 << g_i2cDataGPIO);
		__pokeRegisterDWord(sdev->rmmio,
						g_i2cDataGPIODataDirReg, ulGPIODirection);
    }

    /* Now read the SDA line */
	ulGPIOData = __peekRegisterDWord(sdev->rmmio,
							g_i2cDataGPIODataReg);
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
    return;  /* Single byte read is ok without it. */
}

/*
 *  This function sends the start command to the slave device
 */
void ddk768_swI2CStart(struct smi_device *sdev)
{
    /* Start I2C */
	ddk768_swI2CSDA(sdev, 1);
	ddk768_swI2CSCL(sdev, 1);
	ddk768_swI2CSDA(sdev, 0);
}

/*
 *  This function sends the stop command to the slave device
 */
void ddk768_swI2CStop(struct smi_device *sdev)
{
    /* Stop the I2C */
	ddk768_swI2CSCL(sdev, 1);
	ddk768_swI2CSDA(sdev, 0);
	ddk768_swI2CSDA(sdev, 1);
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
long ddk768_swI2CWriteByte(struct smi_device *sdev, unsigned char data)
{
    unsigned char value = data;
    int i;

    /* Sending the data bit by bit */
    for (i=0; i<8; i++)
    {
        /* Set SCL to low */
		ddk768_swI2CSCL(sdev, 0);

        /* Send data bit */
		if ((value & 0x80) != 0)
			ddk768_swI2CSDA(sdev, 1);
        else
			ddk768_swI2CSDA(sdev, 0);

		swI2CWait(sdev);

        /* Toggle clk line to one */
		ddk768_swI2CSCL(sdev, 1);
		swI2CWait(sdev);

        /* Shift byte to be sent */
        value = value << 1;
    }

    /* Set the SCL Low and SDA High (prepare to get input) */
	ddk768_swI2CSCL(sdev, 0);
	ddk768_swI2CSDA(sdev, 1);

    /* Set the SCL High for ack */
	swI2CWait(sdev);
	ddk768_swI2CSCL(sdev, 1);
	swI2CWait(sdev);

    /* Read SDA, until SDA==0 */
    for(i=0; i<0xff; i++) 
    {
		if (!swI2CReadSDA(sdev))
            break;

		ddk768_swI2CSCL(sdev, 0);
		swI2CWait(sdev);
		ddk768_swI2CSCL(sdev, 1);
		swI2CWait(sdev);
    }

    /* Set the SCL Low and SDA High */
	ddk768_swI2CSCL(sdev, 0);
	ddk768_swI2CSDA(sdev, 1);

    if (i<0xff)
        return 0;
    else
        return (-1);
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
unsigned char ddk768_swI2CReadByte(struct smi_device *sdev,
									unsigned char ack)
{
    int i;
    unsigned char data = 0;

    for(i=7; i>=0; i--)
    {
        /* Set the SCL to Low and SDA to High (Input) */
		ddk768_swI2CSCL(sdev, 0);
		ddk768_swI2CSDA(sdev, 1);
		swI2CWait(sdev);

        /* Set the SCL High */
		ddk768_swI2CSCL(sdev, 1);
		swI2CWait(sdev);

        /* Read data bits from SDA */
		data |= (swI2CReadSDA(sdev) << i);
    }

    if (ack)
        swI2CAck();

    /* Set the SCL Low and SDA High */
	ddk768_swI2CSCL(sdev, 0);
	ddk768_swI2CSDA(sdev, 1);

    return data;
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
long ddk768_swI2CInit(
	struct smi_device *sdev,
    unsigned char i2cClkGPIO, 
    unsigned char i2cDataGPIO
)
{
    int i;
    
    /* Return 0 if the GPIO pins to be used is out of range. The range is only from [0..63] */
    if ((i2cClkGPIO > 31) || (i2cDataGPIO > 31))
        return (-1);

   
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
	__pokeRegisterDWord(sdev->rmmio, g_i2cClkGPIOMuxReg,
						__peekRegisterDWord(sdev->rmmio,
						g_i2cClkGPIOMuxReg) & ~(1 << g_i2cClockGPIO));
	__pokeRegisterDWord(sdev->rmmio, g_i2cDataGPIOMuxReg,
						__peekRegisterDWord(sdev->rmmio,
						g_i2cDataGPIOMuxReg) & ~(1 << g_i2cDataGPIO));


    /* Clear the i2c lines. */
    for(i=0; i<9; i++) 
		ddk768_swI2CStop(sdev);

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
unsigned char ddk768_swI2CReadReg(
	struct smi_device *sdev,
    unsigned char deviceAddress, 
    unsigned char registerIndex
)
{
    unsigned char data;

    /* Send the Start signal */
	ddk768_swI2CStart(sdev);

    /* Send the device address */
	ddk768_swI2CWriteByte(sdev, deviceAddress);

    /* Send the register index */
	ddk768_swI2CWriteByte(sdev, registerIndex);

    /* Get the bus again and get the data from the device read address */
	ddk768_swI2CStart(sdev);
	ddk768_swI2CWriteByte(sdev, deviceAddress + 1);
	data = ddk768_swI2CReadByte(sdev, 1);

    /* Stop swI2C and release the bus */
	ddk768_swI2CStop(sdev);

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
long ddk768_swI2CWriteReg(
	struct smi_device *sdev,
    unsigned char deviceAddress, 
    unsigned char registerIndex, 
    unsigned char data
)
{
    long returnValue = 0;
    
    /* Send the Start signal */
	ddk768_swI2CStart(sdev);

    /* Send the device address and read the data. All should return success
       in order for the writing processed to be successful
     */
	if ((ddk768_swI2CWriteByte(sdev, deviceAddress) != 0) ||
		(ddk768_swI2CWriteByte(sdev, registerIndex) != 0) ||
		(ddk768_swI2CWriteByte(sdev, data) != 0))
    {
        returnValue = -1;
    }
    
    /* Stop i2c and release the bus */
	ddk768_swI2CStop(sdev);

    return returnValue;
}
