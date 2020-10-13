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
#ifndef DDK750_CHIP_H__
#define DDK750_CHIP_H__
#define DEFAULT_INPUT_CLOCK 14318181	/* Default reference clock */
#ifndef SM750LE_REVISION_ID
#define SM750LE_REVISION_ID ((unsigned char)0xfe)
#endif

/* This is all the chips recognized by this library */
typedef enum _logical_chip_type_t {
	SM_UNKNOWN,
	SM718,
	SM750,
	SM750LE,
} logical_chip_type_t;


typedef enum _clock_type_t {
	MXCLK_PLL,
	PRIMARY_PLL,
	SECONDARY_PLL,
	VGA0_PLL,
	VGA1_PLL,
} clock_type_t;

typedef struct _pll_value_t {
	clock_type_t clockType;
	unsigned long inputFreq;	/* Input clock frequency to the PLL */

	/* Use this when clockType = PANEL_PLL */
	unsigned long M;
	unsigned long N;
	unsigned long OD;
	unsigned long POD;
} pll_value_t;

/* input struct to initChipParam() function */
typedef struct _initchip_param_t {
	unsigned short powerMode;	/* Use power mode 0 or 1 */
	unsigned short chipClock;	/* Speed of main chip clock in MHz unit
					   0 = keep the current clock setting
					   Others = the new main chip clock
					 */
	unsigned short memClock;	/* Speed of memory clock in MHz unit
					   0 = keep the current clock setting
					   Others = the new memory clock
					 */
	unsigned short masterClock;	/* Speed of master clock in MHz unit
					   0 = keep the current clock setting
					   Others = the new master clock
					 */
	unsigned short setAllEngOff;	/* 0 = leave all engine state untouched.
					   1 = make sure they are off: 2D, Overlay,
					   video alpha, alpha, hardware cursors
					 */
	unsigned char resetMemory;	/* 0 = Do not reset the memory controller
					   1 = Reset the memory controller
					 */

	/* More initialization parameter can be added if needed */
} initchip_param_t;


unsigned int formatPllReg(pll_value_t * pPLL);
unsigned int calcPllValue2(unsigned int, pll_value_t *);

#ifdef CONFIG_FB_LYNXFB_DOMAINS
logical_chip_type_t getChipType(int);
unsigned int calcPllValue(unsigned int request, pll_value_t * pll, int);
void ddk750_set_mmio(volatile unsigned char *, unsigned short, unsigned char,
									 int);
unsigned int ddk750_getVMSize(int);
int ddk750_initHw(initchip_param_t *, int);
unsigned int getPllValue(clock_type_t clockType, pll_value_t * pPLL,
							int domain);
unsigned int getChipClock(int);
void setChipClock(unsigned int, int);
void setMemoryClock(unsigned int frequency, int);
void setMasterClock(unsigned int frequency, int);
#else
logical_chip_type_t getChipType(void);
unsigned int calcPllValue(unsigned int request, pll_value_t * pll);
void ddk750_set_mmio(volatile unsigned char *, unsigned short, unsigned char);
unsigned int ddk750_getVMSize(void);
int ddk750_initHw(initchip_param_t *);
unsigned int getPllValue(clock_type_t clockType, pll_value_t * pPLL);
unsigned int getChipClock(void);
void setChipClock(unsigned int);
void setMemoryClock(unsigned int frequency);
void setMasterClock(unsigned int frequency);
#endif /* CONFIG_FB_LYNXFB_DOMAINS */

#endif
