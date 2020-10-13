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


#ifdef CONFIG_FB_LYNXFB_DOMAINS
#define setDAC(off, domain) \
{	\
	POKE32(MISC_CTRL, PEEK32(MISC_CTRL, domain)|(off << MISC_CTRL_DAC_POWER_LSB), domain);	\
}
#else
#define setDAC(off) \
{	\
	POKE32(MISC_CTRL, PEEK32(MISC_CTRL)|(off << MISC_CTRL_DAC_POWER_LSB));	\
}
#endif /* CONFIG_FB_LYNXFB_DOMAINS */

#ifdef CONFIG_FB_LYNXFB_DOMAINS

void ddk750_setDPMS(DPMS_t, int);

unsigned int getPowerMode(int);

/*
 * This function sets the current power mode
 */
void setPowerMode(unsigned int powerMode, int domain);

/*
 * This function sets current gate
 */
void setCurrentGate(unsigned int gate, int domain);

/*
 * This function enable/disable the 2D engine.
 */
void enable2DEngine(unsigned int enable, int domain);

/*
 * This function enable/disable the ZV Port
 */
void enableZVPort(unsigned int enable, int domain);

/*
 * This function enable/disable the DMA Engine
 */
void enableDMA(unsigned int enable, int domain);

/*
 * This function enable/disable the GPIO Engine
 */
void enableGPIO(unsigned int enable, int domain);

/*
 * This function enable/disable the PWM Engine
 */
void enablePWM(unsigned int enable, int domain);

/*
 * This function enable/disable the I2C Engine
 */
void enableI2C(unsigned int enable, int domain);

/*
 * This function enable/disable the SSP.
 */
void enableSSP(unsigned int enable, int domain);

#else /* !CONFIG_FB_LYNXFB_DOMAINS: */

void ddk750_setDPMS(DPMS_t);

unsigned int getPowerMode(void);

/*
 * This function sets the current power mode
 */
void setPowerMode(unsigned int powerMode);

/*
 * This function sets current gate
 */
void setCurrentGate(unsigned int gate);

/*
 * This function enable/disable the 2D engine.
 */
void enable2DEngine(unsigned int enable);

/*
 * This function enable/disable the ZV Port
 */
void enableZVPort(unsigned int enable);

/*
 * This function enable/disable the DMA Engine
 */
void enableDMA(unsigned int enable);

/*
 * This function enable/disable the GPIO Engine
 */
void enableGPIO(unsigned int enable);

/*
 * This function enable/disable the PWM Engine
 */
void enablePWM(unsigned int enable);

/*
 * This function enable/disable the I2C Engine
 */
void enableI2C(unsigned int enable);

/*
 * This function enable/disable the SSP.
 */
void enableSSP(unsigned int enable);

#endif /* !CONFIG_FB_LYNXFB_DOMAINS */

#endif
