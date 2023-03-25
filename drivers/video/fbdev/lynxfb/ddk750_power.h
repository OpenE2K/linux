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
#ifndef DDK750_POWER_H__
#define DDK750_POWER_H__

typedef enum _DPMS_t {
	crtDPMS_ON = 0x0,
	crtDPMS_STANDBY = 0x1,
	crtDPMS_SUSPEND = 0x2,
	crtDPMS_OFF = 0x3,
} DPMS_t;

#define setDAC(pvReg, off) do {	\
	unsigned __v = PEEK32(pvReg, MISC_CTRL) & ~(1 << MISC_CTRL_DAC_POWER_LSB);\
	POKE32(pvReg, MISC_CTRL, __v | (off << MISC_CTRL_DAC_POWER_LSB));	\
} while (0)

void ddk750_setDPMS(struct lynx_share *share, DPMS_t);

unsigned int getPowerMode(struct lynx_share *share);

/*
 * This function sets the current power mode
 */
void setPowerMode(struct lynx_share *share, unsigned int powerMode);

/*
 * This function sets current gate
 */
void setCurrentGate(struct lynx_share *share, unsigned int gate);

/*
 * This function enable/disable the 2D engine.
 */
void enable2DEngine(struct lynx_share *share, unsigned int enable);

/*
 * This function enable/disable the ZV Port
 */
void enableZVPort(struct lynx_share *share, unsigned int enable);

/*
 * This function enable/disable the DMA Engine
 */
void enableDMA(struct lynx_share *share, unsigned int enable);

/*
 * This function enable/disable the GPIO Engine
 */
void enableGPIO(struct lynx_share *share, unsigned int enable);

/*
 * This function enable/disable the PWM Engine
 */
void enablePWM(struct lynx_share *share, unsigned int enable);

/*
 * This function enable/disable the I2C Engine
 */
void enableI2C(struct lynx_share *share, unsigned int enable);

/*
 * This function enable/disable the SSP.
 */
void enableSSP(struct lynx_share *share, unsigned int enable);


#endif
