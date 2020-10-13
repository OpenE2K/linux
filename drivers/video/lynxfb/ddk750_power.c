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
*NONINFRINGEMENT.  IN NO EVENT SHALLMill.Chen and Monk.Liu OR COPYRIGHT
*HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
*WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
*FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
*OTHER DEALINGS IN THE SOFTWARE.
*******************************************************************/
#include "ddk750_help.h"
#include "ddk750_reg.h"
#include "ddk750_power.h"

#ifdef CONFIG_FB_LYNXFB_DOMAINS

void ddk750_setDPMS(DPMS_t state, int domain)
{
	unsigned int value;
	if (getChipType(domain) == SM750LE) {
		value = PEEK32(CRT_DISPLAY_CTRL, domain);
		value &= (~(3 << CRT_DISPLAY_CTRL_DPMS_LSB));
		POKE32(CRT_DISPLAY_CTRL,
		       value | (state << CRT_DISPLAY_CTRL_DPMS_LSB), domain);
	} else {
		value = PEEK32(SYSTEM_CTRL, domain);
		value &= (~(3 << SYSTEM_CTRL_DPMS_LSB));
		value |= state << SYSTEM_CTRL_DPMS_LSB;
		POKE32(SYSTEM_CTRL, value, domain);
	}
}

unsigned int getPowerMode(int domain)
{
	if (getChipType(domain) == SM750LE)
		return 0;
	return 2 & (PEEK32(POWER_MODE_CTRL, domain) >> POWER_MODE_CTRL_MODE_LSB);
}


/*
 * SM50x can operate in one of three modes: 0, 1 or Sleep.
 * On hardware reset, power mode 0 is default.
 */
void setPowerMode(unsigned int powerMode, int domain)
{
	unsigned int control_value = 0;

	control_value = PEEK32(POWER_MODE_CTRL, domain);
	control_value &= (~(3 << POWER_MODE_CTRL_MODE_LSB));
	if (getChipType(domain) == SM750LE)
		return;

	switch (powerMode) {
	case POWER_MODE_CTRL_MODE_MODE0:
		control_value &= (~(3 << POWER_MODE_CTRL_MODE_LSB));
		break;
	case POWER_MODE_CTRL_MODE_MODE1:
		control_value |= 1 << POWER_MODE_CTRL_MODE_LSB;
		break;

	case POWER_MODE_CTRL_MODE_SLEEP:
		control_value |= 2 << POWER_MODE_CTRL_MODE_LSB;
		break;

	default:
		break;
	}

	/* Set up other fields in Power Control Register */
	if (powerMode == POWER_MODE_CTRL_MODE_SLEEP) {
		control_value &=
#ifdef VALIDATION_CHIP
		    (~(1 << POWER_MODE_CTRL_336CLK_LSB)) |
#endif
		    (~(1 << POWER_MODE_CTRL_OSC_INPUT_LSB));
	} else {
		control_value |=
#ifdef VALIDATION_CHIP
		    (1 << POWER_MODE_CTRL_336CLK_LSB) |
#endif
		    (1 << POWER_MODE_CTRL_OSC_INPUT_LSB);
	}

	/* Program new power mode. */
	POKE32(POWER_MODE_CTRL, control_value, domain);
}

void setCurrentGate(unsigned int gate, int domain)
{
	unsigned int gate_reg;
	unsigned int mode;

	/* Get current power mode. */
	mode = getPowerMode(domain);

	switch (mode) {
	case POWER_MODE_CTRL_MODE_MODE0:
		gate_reg = MODE0_GATE;
		break;

	case POWER_MODE_CTRL_MODE_MODE1:
		gate_reg = MODE1_GATE;
		break;

	default:
		gate_reg = MODE0_GATE;
		break;
	}
	POKE32(gate_reg, gate, domain);
}



/*
 * This function enable/disable the 2D engine.
 */
void enable2DEngine(unsigned int enable, int domain)
{
	uint32_t gate;

	gate = PEEK32(CURRENT_GATE, domain);
	if (enable) {
		gate |= 1 << CURRENT_GATE_DE_LSB;
		gate |= 1 << CURRENT_GATE_CSC_LSB;
	} else {
		gate &= (~(1 << CURRENT_GATE_DE_LSB));
		gate &= (~(1 << CURRENT_GATE_CSC_LSB));
	}
	setCurrentGate(gate, domain);
}


/*
 * This function enable/disable the ZV Port.
 */
void enableZVPort(unsigned int enable, int domain)
{
	uint32_t gate;

	/* Enable ZV Port Gate */
	gate = PEEK32(CURRENT_GATE, domain);
	if (enable) {
		gate |= 1 << CURRENT_GATE_ZVPORT_LSB;

		/* Using Software I2C */
		gate |= 1 << CURRENT_GATE_GPIO_LSB;

	} else {
		/* Disable ZV Port Gate. There is no way to know whether the GPIO pins are being used
		   or not. Therefore, do not disable the GPIO gate. */
		gate &= (~(1 << CURRENT_GATE_ZVPORT_LSB));
	}

	setCurrentGate(gate, domain);
}


void enableSSP(unsigned int enable, int domain)
{
	uint32_t gate;

	/* Enable SSP Gate */
	gate = PEEK32(CURRENT_GATE, domain);
	if (enable)
		gate |= 1 << CURRENT_GATE_SSP_LSB;
	else
		gate &= (~(1 << CURRENT_GATE_SSP_LSB));

	setCurrentGate(gate, domain);
}

void enableDMA(unsigned int enable, int domain)
{
	uint32_t gate;

	/* Enable DMA Gate */
	gate = PEEK32(CURRENT_GATE, domain);
	if (enable)
		gate |= 1 << CURRENT_GATE_DMA_LSB;
	else
		gate &= (~(1 << CURRENT_GATE_DMA_LSB));

	setCurrentGate(gate, domain);
}

/*
 * This function enable/disable the GPIO Engine
 */
void enableGPIO(unsigned int enable, int domain)
{
	uint32_t gate;

	/* Enable GPIO Gate */
	gate = PEEK32(CURRENT_GATE, domain);
	if (enable)
		gate |= 1 << CURRENT_GATE_GPIO_LSB;
	else
		gate &= (~(1 << CURRENT_GATE_GPIO_LSB));

	setCurrentGate(gate, domain);
}

/*
 * This function enable/disable the PWM Engine
 */
void enablePWM(unsigned int enable, int domain)
{
	uint32_t gate;

	/* Enable PWM Gate */
	gate = PEEK32(CURRENT_GATE, domain);
	if (enable)
		gate |= 1 << CURRENT_GATE_PWM_LSB;
	else
		gate &= (~(1 << CURRENT_GATE_PWM_LSB));

	setCurrentGate(gate, domain);
}

/*
 * This function enable/disable the I2C Engine
 */
void enableI2C(unsigned int enable, int domain)
{
	uint32_t gate;

	/* Enable I2C Gate */
	gate = PEEK32(CURRENT_GATE, domain);
	if (enable)
		gate |= 1 << CURRENT_GATE_I2C_LSB;
	else
		gate &= (~(1 << CURRENT_GATE_I2C_LSB));

	setCurrentGate(gate, domain);
}

#else /* !CONFIG_FB_LYNXFB_DOMAINS */


void ddk750_setDPMS(DPMS_t state)
{
	unsigned int value;
	if (getChipType() == SM750LE) {
		value = PEEK32(CRT_DISPLAY_CTRL);
		value &= (~(3 << CRT_DISPLAY_CTRL_DPMS_LSB));
		POKE32(CRT_DISPLAY_CTRL,
		       value | (state << CRT_DISPLAY_CTRL_DPMS_LSB));
	} else {
		value = PEEK32(SYSTEM_CTRL);
		value &= (~(3 << SYSTEM_CTRL_DPMS_LSB));
		value |= state << SYSTEM_CTRL_DPMS_LSB;
		POKE32(SYSTEM_CTRL, value);
	}
}

unsigned int getPowerMode()
{
	if (getChipType() == SM750LE)
		return 0;
	return 2 & (PEEK32(POWER_MODE_CTRL) >> POWER_MODE_CTRL_MODE_LSB);
}


/*
 * SM50x can operate in one of three modes: 0, 1 or Sleep.
 * On hardware reset, power mode 0 is default.
 */
void setPowerMode(unsigned int powerMode)
{
	unsigned int control_value = 0;

	control_value = PEEK32(POWER_MODE_CTRL);
	control_value &= (~(3 << POWER_MODE_CTRL_MODE_LSB));
	if (getChipType() == SM750LE)
		return;

	switch (powerMode) {
	case POWER_MODE_CTRL_MODE_MODE0:
		control_value &= (~(3 << POWER_MODE_CTRL_MODE_LSB));
		break;
	case POWER_MODE_CTRL_MODE_MODE1:
		control_value |= 1 << POWER_MODE_CTRL_MODE_LSB;
		break;

	case POWER_MODE_CTRL_MODE_SLEEP:
		control_value |= 2 << POWER_MODE_CTRL_MODE_LSB;
		break;

	default:
		break;
	}

	/* Set up other fields in Power Control Register */
	if (powerMode == POWER_MODE_CTRL_MODE_SLEEP) {
		control_value &=
#ifdef VALIDATION_CHIP
		    (~(1 << POWER_MODE_CTRL_336CLK_LSB)) |
#endif
		    (~(1 << POWER_MODE_CTRL_OSC_INPUT_LSB));
	} else {
		control_value |=
#ifdef VALIDATION_CHIP
		    (1 << POWER_MODE_CTRL_336CLK_LSB) |
#endif
		    (1 << POWER_MODE_CTRL_OSC_INPUT_LSB);
	}

	/* Program new power mode. */
	POKE32(POWER_MODE_CTRL, control_value);
}

void setCurrentGate(unsigned int gate)
{
	unsigned int gate_reg;
	unsigned int mode;

	/* Get current power mode. */
	mode = getPowerMode();

	switch (mode) {
	case POWER_MODE_CTRL_MODE_MODE0:
		gate_reg = MODE0_GATE;
		break;

	case POWER_MODE_CTRL_MODE_MODE1:
		gate_reg = MODE1_GATE;
		break;

	default:
		gate_reg = MODE0_GATE;
		break;
	}
	POKE32(gate_reg, gate);
}



/*
 * This function enable/disable the 2D engine.
 */
void enable2DEngine(unsigned int enable)
{
	uint32_t gate;

	gate = PEEK32(CURRENT_GATE);
	if (enable) {
		gate |= 1 << CURRENT_GATE_DE_LSB;
		gate |= 1 << CURRENT_GATE_CSC_LSB;
	} else {
		gate &= (~(1 << CURRENT_GATE_DE_LSB));
		gate &= (~(1 << CURRENT_GATE_CSC_LSB));
	}
	setCurrentGate(gate);
}


/*
 * This function enable/disable the ZV Port.
 */
void enableZVPort(unsigned int enable)
{
	uint32_t gate;

	/* Enable ZV Port Gate */
	gate = PEEK32(CURRENT_GATE);
	if (enable) {
		gate |= 1 << CURRENT_GATE_ZVPORT_LSB;

		/* Using Software I2C */
		gate |= 1 << CURRENT_GATE_GPIO_LSB;

	} else {
		/* Disable ZV Port Gate. There is no way to know whether the GPIO pins are being used
		   or not. Therefore, do not disable the GPIO gate. */
		gate &= (~(1 << CURRENT_GATE_ZVPORT_LSB));
	}

	setCurrentGate(gate);
}


void enableSSP(unsigned int enable)
{
	uint32_t gate;

	/* Enable SSP Gate */
	gate = PEEK32(CURRENT_GATE);
	if (enable)
		gate |= 1 << CURRENT_GATE_SSP_LSB;
	else
		gate &= (~(1 << CURRENT_GATE_SSP_LSB));

	setCurrentGate(gate);
}

void enableDMA(unsigned int enable)
{
	uint32_t gate;

	/* Enable DMA Gate */
	gate = PEEK32(CURRENT_GATE);
	if (enable)
		gate |= 1 << CURRENT_GATE_DMA_LSB;
	else
		gate &= (~(1 << CURRENT_GATE_DMA_LSB));

	setCurrentGate(gate);
}

/*
 * This function enable/disable the GPIO Engine
 */
void enableGPIO(unsigned int enable)
{
	uint32_t gate;

	/* Enable GPIO Gate */
	gate = PEEK32(CURRENT_GATE);
	if (enable)
		gate |= 1 << CURRENT_GATE_GPIO_LSB;
	else
		gate &= (~(1 << CURRENT_GATE_GPIO_LSB));

	setCurrentGate(gate);
}

/*
 * This function enable/disable the PWM Engine
 */
void enablePWM(unsigned int enable)
{
	uint32_t gate;

	/* Enable PWM Gate */
	gate = PEEK32(CURRENT_GATE);
	if (enable)
		gate |= 1 << CURRENT_GATE_PWM_LSB;
	else
		gate &= (~(1 << CURRENT_GATE_PWM_LSB));

	setCurrentGate(gate);
}

/*
 * This function enable/disable the I2C Engine
 */
void enableI2C(unsigned int enable)
{
	uint32_t gate;

	/* Enable I2C Gate */
	gate = PEEK32(CURRENT_GATE);
	if (enable)
		gate |= 1 << CURRENT_GATE_I2C_LSB;
	else
		gate &= (~(1 << CURRENT_GATE_I2C_LSB));

	setCurrentGate(gate);
}
#endif /* !CONFIG_FB_LYNXFB_DOMAINS */

