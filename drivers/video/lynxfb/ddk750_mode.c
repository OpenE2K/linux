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
#include "ddk750_mode.h"
#include "ddk750_chip.h"

#ifdef CONFIG_FB_LYNXFB_DOMAINS
/*
   SM750LE only:
   This function takes care extra registers and bit fields required to set
   up a mode in SM750LE

   Explanation about Display Control register:
   HW only supports 7 predefined pixel clocks, and clock select is
   in bit 29:27 of	Display Control register.
   */
static unsigned long displayControlAdjust_SM750LE(mode_parameter_t *
						  pModeParam,
						  unsigned long
						  dispControl,
						  int domain)
{
	unsigned long x, y;

	x = pModeParam->horizontal_display_end;
	y = pModeParam->vertical_display_end;

	/* SM750LE has to set up the top-left and bottom-right
	   registers as well.
	   Note that normal SM750/SM718 only use those two register for
	   auto-centering mode.
	 */
	POKE32(CRT_AUTO_CENTERING_TL,
	       (~(0x7FF << CRT_AUTO_CENTERING_TL_TOP_LSB)) &
	       (~(0x7FF << CRT_AUTO_CENTERING_TL_LEFT_LSB)), domain);

	/*clear */
	POKE32(CRT_AUTO_CENTERING_BR,
	       (~(0x7FF << CRT_AUTO_CENTERING_BR_BOTTOM_LSB)) |
	       (~(0x7FF << CRT_AUTO_CENTERING_BR_RIGHT_LSB)), domain);
	POKE32(CRT_AUTO_CENTERING_BR,
	       ((y - 1) << CRT_AUTO_CENTERING_BR_BOTTOM_LSB) |
	       ((x - 1) << CRT_AUTO_CENTERING_BR_RIGHT_LSB), domain);
	/* Clear bit 29:27 of display control register */
	dispControl &= ~(7 << CRT_DISPLAY_CTRL_CLK_LSB);
	/* Assume common fields in dispControl have been properly set before
	   calling this function.
	   This function only sets the extra fields in dispControl.
	 */


	/* Set bit 29:27 of display control register for the right clock */
	/* Note that SM750LE only need to supported 7 resoluitons. */
	dispControl &= (~(7 << CRT_DISPLAY_CTRL_CLK_LSB));
	if (x == 800 && y == 600)
		dispControl |= 1 << CRT_DISPLAY_CTRL_CLK_LSB;
	else if (x == 1024 && y == 768)
		dispControl |= 3 << CRT_DISPLAY_CTRL_CLK_LSB;
	else if (x == 1152 && y == 864)
		dispControl |= 5 << CRT_DISPLAY_CTRL_CLK_LSB;
	else if (x == 1280 && y == 768)
		dispControl |= 5 << CRT_DISPLAY_CTRL_CLK_LSB;
	else if (x == 1280 && y == 720)
		dispControl |= 4 << CRT_DISPLAY_CTRL_CLK_LSB;
	else if (x == 1280 && y == 960)
		dispControl |= 6 << CRT_DISPLAY_CTRL_CLK_LSB;
	else if (x == 1280 && y == 1024)
		dispControl |= 6 << CRT_DISPLAY_CTRL_CLK_LSB;
	else			/* default to VGA clock */
		dispControl &= ~(7 << CRT_DISPLAY_CTRL_CLK_LSB);

	/* Set bit 25:24 of display controller */
	dispControl |= 1 << CRT_DISPLAY_CTRL_CRTSELECT_LSB;
	dispControl &= ~(1 << CRT_DISPLAY_CTRL_RGBBIT_LSB);

	/* Set bit 14 of display controller */
	dispControl |= 1 << CRT_DISPLAY_CTRL_CLOCK_PHASE_LSB;
	POKE32(CRT_DISPLAY_CTRL, dispControl, domain);

	return dispControl;

}

/* only timing related registers will be  programed */
static int programModeRegisters(mode_parameter_t * pModeParam,
				pll_value_t * pll, int domain)
{
	int ret = 0;
	int cnt = 0;
	unsigned int ulTmpValue, ulReg;
	if (pll->clockType == SECONDARY_PLL) {
		/* programe secondary pixel clock */
		POKE32(CRT_PLL_CTRL, formatPllReg(pll), domain);
		POKE32(CRT_HORIZONTAL_TOTAL,
		       ((pModeParam->horizontal_total -
			 1) << CRT_HORIZONTAL_TOTAL_TOTAL_LSB)
		       | ((pModeParam->horizontal_display_end - 1) <<
			  CRT_HORIZONTAL_TOTAL_DISPLAY_END_LSB), domain);

		POKE32(CRT_HORIZONTAL_SYNC,
		       (pModeParam->
			horizontal_sync_width <<
			CRT_HORIZONTAL_SYNC_WIDTH_LSB)
		       | ((pModeParam->horizontal_sync_start - 1) <<
			  CRT_HORIZONTAL_SYNC_START_LSB), domain);

		POKE32(CRT_VERTICAL_TOTAL,
		       ((pModeParam->vertical_total -
			 1) << CRT_VERTICAL_TOTAL_TOTAL_LSB)
		       | ((pModeParam->vertical_display_end - 1) <<
			  CRT_VERTICAL_TOTAL_DISPLAY_END_LSB), domain);
		POKE32(CRT_VERTICAL_SYNC,
		       (pModeParam->
			vertical_sync_height <<
			CRT_VERTICAL_SYNC_HEIGHT_LSB)
		       | ((pModeParam->vertical_sync_start - 1) <<
			  CRT_VERTICAL_SYNC_START_LSB), domain);


		ulTmpValue =
		    (pModeParam->
		     vertical_sync_polarity <<
		     CRT_DISPLAY_CTRL_VSYNC_PHASE_LSB) | (pModeParam->
							  horizontal_sync_polarity
							  <<
							  CRT_DISPLAY_CTRL_HSYNC_PHASE_LSB)
		    | (1 << CRT_DISPLAY_CTRL_TIMING_LSB) | (1 <<
							    CRT_DISPLAY_CTRL_PLANE_LSB);

		if (getChipType(domain) == SM750LE) {
			displayControlAdjust_SM750LE(pModeParam,
						     ulTmpValue, domain);
		} else {
			ulReg = PEEK32(CRT_DISPLAY_CTRL, domain)
			    & (~(1 << CRT_DISPLAY_CTRL_VSYNC_PHASE_LSB))
			    & (~(1 << CRT_DISPLAY_CTRL_HSYNC_PHASE_LSB))
			    & (~(1 << CRT_DISPLAY_CTRL_TIMING_LSB))
			    & (~(1 << CRT_DISPLAY_CTRL_PLANE_LSB));
			POKE32(CRT_DISPLAY_CTRL, ulTmpValue | ulReg, domain);
		}

	} else if (pll->clockType == PRIMARY_PLL) {
		unsigned int ulReservedBits;
		POKE32(PANEL_PLL_CTRL, formatPllReg(pll), domain);
		POKE32(PANEL_HORIZONTAL_TOTAL,
		       ((pModeParam->horizontal_total -
			 1) << PANEL_HORIZONTAL_TOTAL_TOTAL_LSB)
		       | ((pModeParam->horizontal_display_end - 1) <<
			  PANEL_HORIZONTAL_TOTAL_DISPLAY_END_LSB), domain);

		POKE32(PANEL_HORIZONTAL_SYNC,
		       (pModeParam->
			horizontal_sync_width <<
			PANEL_HORIZONTAL_SYNC_WIDTH_LSB)
		       | ((pModeParam->horizontal_sync_start - 1) <<
			  PANEL_HORIZONTAL_SYNC_START_LSB), domain);

		POKE32(PANEL_VERTICAL_TOTAL,
		       ((pModeParam->vertical_total - 1)
				       << PANEL_VERTICAL_TOTAL_TOTAL_LSB)
		       | ((pModeParam->vertical_display_end - 1) <<
			  PANEL_VERTICAL_TOTAL_DISPLAY_END_LSB), domain);

		POKE32(PANEL_VERTICAL_SYNC,
		       (pModeParam->vertical_sync_height <<
			PANEL_VERTICAL_SYNC_HEIGHT_LSB)
		       | ((pModeParam->vertical_sync_start - 1) <<
			  PANEL_VERTICAL_SYNC_START_LSB), domain);
		ulTmpValue =
		    (pModeParam->vertical_sync_polarity <<
		     PANEL_DISPLAY_CTRL_VSYNC_PHASE_LSB)
		    | (pModeParam->horizontal_sync_polarity <<
		       PANEL_DISPLAY_CTRL_HSYNC_PHASE_LSB)
		    | (pModeParam->clock_phase_polarity <<
		       PANEL_DISPLAY_CTRL_CLOCK_PHASE_LSB)
		    | (1 << PANEL_DISPLAY_CTRL_TIMING_LSB)
		    | (1 << PANEL_DISPLAY_CTRL_PLANE_LSB);
		ulReservedBits =
		    (3 << PANEL_DISPLAY_CTRL_RESERVED_1_MASK_LSB) | (15 <<
								     PANEL_DISPLAY_CTRL_RESERVED_2_MASK_LSB)
		    | (1 << PANEL_DISPLAY_CTRL_RESERVED_3_MASK_LSB) | (1 <<
								       PANEL_DISPLAY_CTRL_VSYNC_LSB);
		ulReg = (PEEK32(PANEL_DISPLAY_CTRL, domain) & ~ulReservedBits)
		    & (~(1 << PANEL_DISPLAY_CTRL_CLOCK_PHASE_LSB))
		    & (~(1 << PANEL_DISPLAY_CTRL_VSYNC_PHASE_LSB))
		    & (~(1 << PANEL_DISPLAY_CTRL_HSYNC_PHASE_LSB))
		    & (~(1 << PANEL_DISPLAY_CTRL_TIMING_LSB))
		    & (~(1 << PANEL_DISPLAY_CTRL_PLANE_LSB));

		/* May a hardware bug or just my test chip (not confirmed).
		 * PANEL_DISPLAY_CTRL register seems requiring few writes
		 * before a value can be succesfully written in.
		 * Added some masks to mask out the reserved bits.
		 * Note: This problem happens by design. The hardware will wait for the
		 *       next vertical sync to turn on/off the plane.
		 */

		POKE32(PANEL_DISPLAY_CTRL, ulTmpValue | ulReg, domain);

		while ((PEEK32(PANEL_DISPLAY_CTRL, domain) & ~ulReservedBits) !=
		       (ulTmpValue | ulReg)) {
			cnt++;
			if (cnt > 1000)
				break;
			POKE32(PANEL_DISPLAY_CTRL, ulTmpValue | ulReg, domain);
		}

	} else {
		ret = -1;
	}
	return ret;
}

int ddk750_setModeTiming(mode_parameter_t * parm, clock_type_t clock, int domain)
{
	pll_value_t pll;
	unsigned int uiActualPixelClk;
	pll.inputFreq = DEFAULT_INPUT_CLOCK;
	pll.clockType = clock;

	uiActualPixelClk = calcPllValue(parm->pixel_clock, &pll, domain);
	if (getChipType(domain) == SM750LE) {
		/* set graphic mode via IO method */
		outb_p(0x88, 0x3d4);
		outb_p(0x06, 0x3d5);
	}
	programModeRegisters(parm, &pll, domain);
	return 0;
}

#else /* !CONFIG_FB_LYNXFB_DOMAINS: */
/*
   SM750LE only:
   This function takes care extra registers and bit fields required to set
   up a mode in SM750LE

   Explanation about Display Control register:
   HW only supports 7 predefined pixel clocks, and clock select is
   in bit 29:27 of	Display Control register.
   */
static unsigned long displayControlAdjust_SM750LE(mode_parameter_t *
						  pModeParam,
						  unsigned long
						  dispControl)
{
	unsigned long x, y;

	x = pModeParam->horizontal_display_end;
	y = pModeParam->vertical_display_end;

	/* SM750LE has to set up the top-left and bottom-right
	   registers as well.
	   Note that normal SM750/SM718 only use those two register for
	   auto-centering mode.
	 */
	POKE32(CRT_AUTO_CENTERING_TL,
	       (~(0x7FF << CRT_AUTO_CENTERING_TL_TOP_LSB)) &
	       (~(0x7FF << CRT_AUTO_CENTERING_TL_LEFT_LSB)));

	/*clear */
	POKE32(CRT_AUTO_CENTERING_BR,
	       (~(0x7FF << CRT_AUTO_CENTERING_BR_BOTTOM_LSB)) |
	       (~(0x7FF << CRT_AUTO_CENTERING_BR_RIGHT_LSB)));
	POKE32(CRT_AUTO_CENTERING_BR,
	       ((y - 1) << CRT_AUTO_CENTERING_BR_BOTTOM_LSB) |
	       ((x - 1) << CRT_AUTO_CENTERING_BR_RIGHT_LSB));
	/* Clear bit 29:27 of display control register */
	dispControl &= ~(7 << CRT_DISPLAY_CTRL_CLK_LSB);
	/* Assume common fields in dispControl have been properly set before
	   calling this function.
	   This function only sets the extra fields in dispControl.
	 */


	/* Set bit 29:27 of display control register for the right clock */
	/* Note that SM750LE only need to supported 7 resoluitons. */
	dispControl &= (~(7 << CRT_DISPLAY_CTRL_CLK_LSB));
	if (x == 800 && y == 600)
		dispControl |= 1 << CRT_DISPLAY_CTRL_CLK_LSB;
	else if (x == 1024 && y == 768)
		dispControl |= 3 << CRT_DISPLAY_CTRL_CLK_LSB;
	else if (x == 1152 && y == 864)
		dispControl |= 5 << CRT_DISPLAY_CTRL_CLK_LSB;
	else if (x == 1280 && y == 768)
		dispControl |= 5 << CRT_DISPLAY_CTRL_CLK_LSB;
	else if (x == 1280 && y == 720)
		dispControl |= 4 << CRT_DISPLAY_CTRL_CLK_LSB;
	else if (x == 1280 && y == 960)
		dispControl |= 6 << CRT_DISPLAY_CTRL_CLK_LSB;
	else if (x == 1280 && y == 1024)
		dispControl |= 6 << CRT_DISPLAY_CTRL_CLK_LSB;
	else			/* default to VGA clock */
		dispControl &= ~(7 << CRT_DISPLAY_CTRL_CLK_LSB);

	/* Set bit 25:24 of display controller */
	dispControl |= 1 << CRT_DISPLAY_CTRL_CRTSELECT_LSB;
	dispControl &= ~(1 << CRT_DISPLAY_CTRL_RGBBIT_LSB);

	/* Set bit 14 of display controller */
	dispControl |= 1 << CRT_DISPLAY_CTRL_CLOCK_PHASE_LSB;
	POKE32(CRT_DISPLAY_CTRL, dispControl);

	return dispControl;

}



/* only timing related registers will be  programed */
static int programModeRegisters(mode_parameter_t * pModeParam,
				pll_value_t * pll)
{
	int ret = 0;
	int cnt = 0;
	unsigned int ulTmpValue, ulReg;
	if (pll->clockType == SECONDARY_PLL) {
		/* programe secondary pixel clock */
		POKE32(CRT_PLL_CTRL, formatPllReg(pll));
		POKE32(CRT_HORIZONTAL_TOTAL,
		       ((pModeParam->horizontal_total -
			 1) << CRT_HORIZONTAL_TOTAL_TOTAL_LSB)
		       | ((pModeParam->horizontal_display_end - 1) <<
			  CRT_HORIZONTAL_TOTAL_DISPLAY_END_LSB));

		POKE32(CRT_HORIZONTAL_SYNC,
		       (pModeParam->
			horizontal_sync_width <<
			CRT_HORIZONTAL_SYNC_WIDTH_LSB)
		       | ((pModeParam->horizontal_sync_start - 1) <<
			  CRT_HORIZONTAL_SYNC_START_LSB));

		POKE32(CRT_VERTICAL_TOTAL,
		       ((pModeParam->vertical_total -
			 1) << CRT_VERTICAL_TOTAL_TOTAL_LSB)
		       | ((pModeParam->vertical_display_end - 1) <<
			  CRT_VERTICAL_TOTAL_DISPLAY_END_LSB));
		POKE32(CRT_VERTICAL_SYNC,
		       (pModeParam->
			vertical_sync_height <<
			CRT_VERTICAL_SYNC_HEIGHT_LSB)
		       | ((pModeParam->vertical_sync_start - 1) <<
			  CRT_VERTICAL_SYNC_START_LSB));


		ulTmpValue =
		    (pModeParam->
		     vertical_sync_polarity <<
		     CRT_DISPLAY_CTRL_VSYNC_PHASE_LSB) | (pModeParam->
							  horizontal_sync_polarity
							  <<
							  CRT_DISPLAY_CTRL_HSYNC_PHASE_LSB)
		    | (1 << CRT_DISPLAY_CTRL_TIMING_LSB) | (1 <<
							    CRT_DISPLAY_CTRL_PLANE_LSB);

		if (getChipType() == SM750LE) {
			displayControlAdjust_SM750LE(pModeParam,
						     ulTmpValue);
		} else {
			ulReg = PEEK32(CRT_DISPLAY_CTRL)
			    & (~(1 << CRT_DISPLAY_CTRL_VSYNC_PHASE_LSB))
			    & (~(1 << CRT_DISPLAY_CTRL_HSYNC_PHASE_LSB))
			    & (~(1 << CRT_DISPLAY_CTRL_TIMING_LSB))
			    & (~(1 << CRT_DISPLAY_CTRL_PLANE_LSB));
			POKE32(CRT_DISPLAY_CTRL, ulTmpValue | ulReg);
		}

	} else if (pll->clockType == PRIMARY_PLL) {
		unsigned int ulReservedBits;
		POKE32(PANEL_PLL_CTRL, formatPllReg(pll));
		POKE32(PANEL_HORIZONTAL_TOTAL,
		       ((pModeParam->horizontal_total -
			 1) << PANEL_HORIZONTAL_TOTAL_TOTAL_LSB)
		       | ((pModeParam->horizontal_display_end - 1) <<
			  PANEL_HORIZONTAL_TOTAL_DISPLAY_END_LSB));

		POKE32(PANEL_HORIZONTAL_SYNC,
		       (pModeParam->
			horizontal_sync_width <<
			PANEL_HORIZONTAL_SYNC_WIDTH_LSB)
		       | ((pModeParam->horizontal_sync_start - 1) <<
			  PANEL_HORIZONTAL_SYNC_START_LSB));

		POKE32(PANEL_VERTICAL_TOTAL,
		       ((pModeParam->vertical_total - 1)
				       << PANEL_VERTICAL_TOTAL_TOTAL_LSB)
		       | ((pModeParam->vertical_display_end - 1) <<
			  PANEL_VERTICAL_TOTAL_DISPLAY_END_LSB));

		POKE32(PANEL_VERTICAL_SYNC,
		       (pModeParam->vertical_sync_height <<
			PANEL_VERTICAL_SYNC_HEIGHT_LSB)
		       | ((pModeParam->vertical_sync_start - 1) <<
			  PANEL_VERTICAL_SYNC_START_LSB));
		ulTmpValue =
		    (pModeParam->vertical_sync_polarity <<
		     PANEL_DISPLAY_CTRL_VSYNC_PHASE_LSB)
		    | (pModeParam->horizontal_sync_polarity <<
		       PANEL_DISPLAY_CTRL_HSYNC_PHASE_LSB)
		    | (pModeParam->clock_phase_polarity <<
		       PANEL_DISPLAY_CTRL_CLOCK_PHASE_LSB)
		    | (1 << PANEL_DISPLAY_CTRL_TIMING_LSB)
		    | (1 << PANEL_DISPLAY_CTRL_PLANE_LSB);
		ulReservedBits =
		    (3 << PANEL_DISPLAY_CTRL_RESERVED_1_MASK_LSB) | (15 <<
								     PANEL_DISPLAY_CTRL_RESERVED_2_MASK_LSB)
		    | (1 << PANEL_DISPLAY_CTRL_RESERVED_3_MASK_LSB) | (1 <<
								       PANEL_DISPLAY_CTRL_VSYNC_LSB);
		ulReg = (PEEK32(PANEL_DISPLAY_CTRL) & ~ulReservedBits)
		    & (~(1 << PANEL_DISPLAY_CTRL_CLOCK_PHASE_LSB))
		    & (~(1 << PANEL_DISPLAY_CTRL_VSYNC_PHASE_LSB))
		    & (~(1 << PANEL_DISPLAY_CTRL_HSYNC_PHASE_LSB))
		    & (~(1 << PANEL_DISPLAY_CTRL_TIMING_LSB))
		    & (~(1 << PANEL_DISPLAY_CTRL_PLANE_LSB));

		/* May a hardware bug or just my test chip (not confirmed).
		 * PANEL_DISPLAY_CTRL register seems requiring few writes
		 * before a value can be succesfully written in.
		 * Added some masks to mask out the reserved bits.
		 * Note: This problem happens by design. The hardware will wait for the
		 *       next vertical sync to turn on/off the plane.
		 */

		POKE32(PANEL_DISPLAY_CTRL, ulTmpValue | ulReg);

		while ((PEEK32(PANEL_DISPLAY_CTRL) & ~ulReservedBits) !=
		       (ulTmpValue | ulReg)) {
			cnt++;
			if (cnt > 1000)
				break;
			POKE32(PANEL_DISPLAY_CTRL, ulTmpValue | ulReg);
		}

	} else {
		ret = -1;
	}
	return ret;
}

int ddk750_setModeTiming(mode_parameter_t * parm, clock_type_t clock)
{
	pll_value_t pll;
	unsigned int uiActualPixelClk;
	pll.inputFreq = DEFAULT_INPUT_CLOCK;
	pll.clockType = clock;

	uiActualPixelClk = calcPllValue(parm->pixel_clock, &pll);
	if (getChipType() == SM750LE) {
		/* set graphic mode via IO method */
		outb_p(0x88, 0x3d4);
		outb_p(0x06, 0x3d5);
	}
	programModeRegisters(parm, &pll);
	return 0;
}
#endif /* !CONFIG_FB_LYNXFB_DOMAINS */

