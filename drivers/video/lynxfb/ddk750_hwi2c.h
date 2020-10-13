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
#ifndef DDK750_HWI2C_H__
#define DDK750_HWI2C_H__

/* hwi2c functions */

#ifdef CONFIG_FB_LYNXFB_DOMAINS
int hwI2CInit(unsigned char busSpeedMode, int domain);
void hwI2CClose(int domain);

unsigned char hwI2CReadReg(unsigned char deviceAddress,
			   unsigned char registerIndex, int domain);
int hwI2CWriteReg(unsigned char deviceAddress, unsigned char registerIndex,
		  unsigned char data, int domain);

#else /* !CONFIG_FB_LYNXFB_DOMAINS:  */
int hwI2CInit(unsigned char busSpeedMode);
void hwI2CClose(void);

unsigned char hwI2CReadReg(unsigned char deviceAddress,
			   unsigned char registerIndex);
int hwI2CWriteReg(unsigned char deviceAddress, unsigned char registerIndex,
		  unsigned char data);

#endif /* CONFIG_FB_LYNXFB_DOMAINS */

#endif
