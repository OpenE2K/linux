
#include <linux/string.h>
#include "ddk768_reg.h"
#include "ddk768_help.h"
#include "ddk768_swi2c.h"
#include "ddk768_hwi2c.h"
#include "wm8978.h"

static unsigned short WM8978_REGVAL[58]=
{
	0X0000,0X0000,0X0000,0X0000,0X0050,0X0000,0X0140,0X0000,
	0X0000,0X0000,0X0000,0X00FF,0X00FF,0X0000,0X0100,0X00FF,
	0X00FF,0X0000,0X012C,0X002C,0X002C,0X002C,0X002C,0X0000,
	0X0032,0X0000,0X0000,0X0000,0X0000,0X0000,0X0000,0X0000,
	0X0038,0X000B,0X0032,0X0000,0X0008,0X000C,0X0093,0X00E9,
	0X0000,0X0000,0X0000,0X0000,0X0003,0X0010,0X0010,0X0100,
	0X0100,0X0002,0X0001,0X0001,0X0039,0X0039,0X0039,0X0039,
	0X0001,0X0001
};

unsigned char WM8978_Write_Reg(unsigned char reg, unsigned short val)
{
	unsigned char res;
	unsigned char RegAddr;
	unsigned char RegValue;
	RegAddr = (reg<<1)|((unsigned char)((val>>8)&0x01));
	RegValue = (unsigned char)val;
	if(!hwi2c_en)
		res = ddk768_swI2CWriteReg(WM8978_ADDR, RegAddr, RegValue);
	else
		res = ddk768_hwI2CWriteReg(0, WM8978_ADDR, RegAddr, RegValue);

	if(res == 0)
		WM8978_REGVAL[reg]=val;
	return res;
}

unsigned short WM8978_Read_Reg(unsigned char reg)
{
	return WM8978_REGVAL[reg];
}

unsigned char WM8978_Init(void)
{
	unsigned char Res;

	if(hwi2c_en)
		ddk768_hwI2CInit(0);
	else
		ddk768_swI2CInit(30, 31);


	Res = WM8978_Write_Reg(0, 0);	// Soft reset WM8978
	if(Res)
		return 1;					// Failed to send the command, WM8978 is abnormal
	/* Set volume to 0 can improve the noise when init codec */
	WM8978_HPvol_Set(0, 0);			// Headphone volume 0-63 (left and right are set separately)
	WM8978_SPKvol_Set(0);			// Speaker volume 0-63
	WM8978_Write_Reg(1, 0x1B);		// R1, MICEN is set to 1 (MIC enabled), BIASEN is set to 1 (simulator working), VMIDSEL [1:0] is set to:11 (5K)
	WM8978_Write_Reg(2, 0x1B0);		// R2,ROUT1,LOUT1 Output is enabled (the headset can work), BOOSTENR,BOOSTENL Enable
	WM8978_Write_Reg(3, 0x6C);		// R3,LOUT2,ROUT2 Output is enabled (speaker work), RMIX,LMIX Enable
	WM8978_Write_Reg(6, 0);			// R6, MCLK Provided by the outside
	WM8978_Write_Reg(43, 1<<4);		// R43,INVROUT2 Reverse, drive the horn
	WM8978_Write_Reg(47, 1<<8);		// R47 Set up, PGABOOSTL, Left channel MIC gets 20 times the benefit
	WM8978_Write_Reg(48, 1<<8);		// R48 Set up, PGABOOSTR, Right channel MIC gets 20 times the benefit
	WM8978_Write_Reg(49, 1<<1);		// R49. TSDEN, Turn on overheating protection
	WM8978_Write_Reg(10, 1<<3);		// R10, SOFTMUTE off, 128x sampling, best SNR
	WM8978_Write_Reg(14, 1<<3);		// R14, ADC 128x sampling rate

	/* Playback and record setup */

	WM8978_I2S_Cfg(2, 0);		// Set the I2S interface mode, the number of data bits does not need to be set, and the playback slave device is not used
	WM8978_ADDA_Cfg(1, 1);		// Turn on DAC and ADC
	WM8978_Input_Cfg(1, 1, 1);	// Turn on Line in input channel, MIC and AUX
	WM8978_MIC_Gain(20);		// MIC Gain setting, MIC can be turned on when recording
	WM8978_Output_Cfg(1, 0);	// Turn on DAC output, turn off BYPASS output

	/* Make sure the IIC is idle when do this operation */
	WM8978_HPvol_Set(50, 50);
	WM8978_SPKvol_Set(50);

	return 0;
}

void WM8978_DeInit(void)
{
	if(hwi2c_en)
		ddk768_hwI2CClose(0);
	else
		ddk768_swI2CInit(30, 31);

	/* To Do: Here should be read device register not globle array.*/
	WM8978_Write_Reg(0, 0);
}

/*
 * WM8978 DAC/ADC configuration
 * adcen: adc enable(1)/disable(0)
 * dacen: dac enable(1)/disable(0)
 */
void WM8978_ADDA_Cfg(unsigned char dacen, unsigned char adcen)
{
	unsigned short regval;
	regval = WM8978_Read_Reg(3);	// Read R3
	if(dacen)
		regval |= 3<<0;				// The lower 2 bits of R3 are set to 1, Turn on DACR&DACL
	else
		regval &= ~(3<<0);			// The lowest 2 bits of R3 are set to 0, Turn off DACR&DACL
	WM8978_Write_Reg(3, regval);	// Set R3
	regval = WM8978_Read_Reg(2);	// Read R2
	if(adcen)
		regval |= 3<<0;				// The lowest 2 bits of R2 are set to 1, Turn on ADCR&ADCL
	else
		regval &= ~(3<<0);			// The lowest 2 bits of R2 are set to 0, Turn off ADCR&ADCL
	WM8978_Write_Reg(2, regval);	// Set R2
}

/*
 * WM8978 Input channel configuration
 * micen:MIC on(1)/off(0)
 * lineinen: Line In enable(1)/disable(0)
 * auxen: aux enable(1)/disable(0)
 */
void WM8978_Input_Cfg(unsigned char micen, unsigned char lineinen, unsigned char auxen)
{
	unsigned short regval;
	regval = WM8978_Read_Reg(2);	// Read R2
	if(micen)
		regval |= 3<<2;				// Turn on INPPGAENR,INPPFAENL(increase MIC PGA)
	else
		regval &= ~(3<<2);			// Turn off INPPGAENR, INPPFAENL.
	WM8978_Write_Reg(2, regval);	// Set R2
	regval = WM8978_Read_Reg(44);	// Read R44
	if(micen)
		regval |= 3<<4|3<<0;		// Turn on LIN2INPPGA,LIP2INPGA,RIN2INPPGA,RIP2INPGA
	else
		regval &= ~(3<<4|3<<0);		// Turn off LIN2INPPGA,LIP2INPGA,RIN2INPPGA,RIP2INPGA
	WM8978_Write_Reg(44, regval);	// Set up R44
	if(lineinen)
		WM8978_LINEIN_Gain(5);		// LINE IN 0dB gain
	else
		WM8978_LINEIN_Gain(0);		// Turn off LINE IN
	if(auxen)
		WM8978_AUX_Gain(7);			// AUX 6bB gain
	else
		WM8978_AUX_Gain(0);			// Turn off AUX input
}

/*
 * WM8978 MIC Gain settings(Does not include 20dB of BOOST, MIC-->ADC Gain of input part)
 * gain:0~63, from -12dB to 35.25dB with 0.75dB step
 */
void WM8978_MIC_Gain(unsigned char gain)
{
	gain &= 0x3F;
	WM8978_Write_Reg(45, gain);			// R45, Left channel PGA settings
	WM8978_Write_Reg(46, gain|1<<8);	// R46, Right channel PGA settings
}

/*
 * WM8978 L2/R2(Line In) Gain settings(L2/R2-->ADC Gain of input part)
 * gain:0~7, 0 - Indicates that the channel is prohibited,
 *			 1~7 - From -12dB to 6dB with 3dB step
 */
void WM8978_LINEIN_Gain(unsigned char gain)
{
	unsigned short regval;
	gain &= 0x07;
	regval = WM8978_Read_Reg(47);			// Read R47
	regval &= ~(7<<4);						// Clear the original settings
	WM8978_Write_Reg(47, regval|gain<<4);	// Set R47
	regval = WM8978_Read_Reg(48);			// Read R48
	regval &= ~(7<<4);						// Clear the original settings
	WM8978_Write_Reg(48,regval|gain<<4);	// Set R48
}

/*
 * WM8978 AUXR,AUXL(PWM Audio part) Gain settings (AUXR/L-->ADC Gain of input part)
 * gain: 0~7, 0 - Indicates that channel is prohibited,
 *			  1~7 - From -12dB to 6 dB with 3dB step
 */
void WM8978_AUX_Gain(unsigned char gain)
{
	unsigned short regval;
	gain &= 0x07;
	regval = WM8978_Read_Reg(47);			// Read R47
	regval &= ~(7<<0);						// Clear the original settings
	WM8978_Write_Reg(47, regval|gain<<0);	// Set R47
	regval = WM8978_Read_Reg(48);			// Read R48
	regval &= ~(7<<0);						// Clear the original settings
	WM8978_Write_Reg(48, regval|gain<<0);	// Set R48
}

/*
 * WM8978 Output configuration
 * bpsen: Bypass output(Recording, including MIC,LINE IN,AUX,etc.) on(1)/off(0)
 */
void WM8978_Output_Cfg(unsigned char dacen, unsigned char bpsen)
{
	unsigned short regval = 0;
	if(dacen)
		regval |= 1<<0;			// DAC output enable
	if(bpsen)
	{
		regval |= 1<<1;			// BYPASS enable
		regval |= 5<<2;			// 0dB gain
	}
	WM8978_Write_Reg(50,regval); // Set R50
	WM8978_Write_Reg(51,regval); // Set R51
}

/*
 * Set the volume of the left and right channels of the headset
 * voll: Left channel volume (0~63)
 * volr: Right channel volume (0~63)
 */
void WM8978_HPvol_Set(unsigned char voll, unsigned char volr)
{
	voll &= 0x3F;
	volr &= 0x3F;						// Limited scope
	if(voll == 0)voll |= 1<<6;			// When volume is 0, mute directly
	if(volr == 0)volr |= 1<<6;			// When volume is 0, mute directly
	WM8978_Write_Reg(52, voll);			// R52, headphone left channel volume setting
	WM8978_Write_Reg(53, volr|(1<<8));	// R53, headphone right channel volume setting, synchronous update (HPVU=1)
}

/*
 * Set the speaker volume
 * voll: Left channel volume (0~63)
 */
void WM8978_SPKvol_Set(unsigned char volx)
{
	volx &= 0x3F;						// Limited scope
	if(volx == 0)volx |= 1<<6;			// When the volume is 0, mute directly
	WM8978_Write_Reg(54, volx);			// R54, speaker left channel volume setting
	WM8978_Write_Reg(55, volx|(1<<8));	// R55, speaker right channel volume setting, synchronous update (SPKVU=1)
}

/*
 * Set the I2S operating mode
 * fmt: 0 - LSB(Right alignment);
 *		1 - MSB(Align to the left);
 *		2 - Philips standard I2S;
 *		3 - PCM/DSP;
 * len: 0 - 16 bits;
 *		1 - 20 bits;
 *		2 - 24 bits;
 *		3 - 32 bits;
 */
void WM8978_I2S_Cfg(unsigned char fmt, unsigned char len)
{
	fmt &= 0x03;
	len &= 0x03;							// Limited scope
	WM8978_Write_Reg(4, (fmt<<3)|(len<<5));	// R4, WM8978 operating mode setting
}
