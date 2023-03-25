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
#include "ddk750_reg.h"
#include "ddk750_help.h"
#include "ddk750_display.h"
#include "ddk750_power.h"
#include "ddk750_dvi.h"
#include "lynx_drv.h"

#define primaryWaitVerticalSync(share, delay) \
	   waitNextVerticalSync(share, 0, delay)

static void setDisplayControl(struct lynx_share *share,
				int ctrl, int dispState)
{
	/* state != 0 means turn on both timing & plane en_bit */
	unsigned long ulDisplayCtrlReg, ulReservedBits = 0;
	int cnt;

	cnt = 0;

	/* Set the primary display control */
	if (!ctrl) {
		ulDisplayCtrlReg = PEEK32(share->pvReg, PANEL_DISPLAY_CTRL);
		/* Turn on/off the Panel display control */
		if (dispState) {
			/* Timing should be enabled first before enabling the plane
			 * because changing at the same time does not guarantee that
			 * the plane will also enabled or disabled.
			 */
			ulDisplayCtrlReg =
			    ulDisplayCtrlReg | (1 <<
						PANEL_DISPLAY_CTRL_TIMING_LSB);
			POKE32(share->pvReg, PANEL_DISPLAY_CTRL, ulDisplayCtrlReg);

			ulDisplayCtrlReg =
			    ulDisplayCtrlReg | (1 <<
						PANEL_DISPLAY_CTRL_PLANE_LSB);
			/* Added some masks to mask out the reserved bits.
			 * Sometimes, the reserved bits are set/reset randomly when
			 * writing to the PRIMARY_DISPLAY_CTRL, therefore, the register
			 * reserved bits are needed to be masked out.
			 */
			ulReservedBits =
			    (3 << PANEL_DISPLAY_CTRL_RESERVED_1_MASK_LSB) |
			    (15 << PANEL_DISPLAY_CTRL_RESERVED_2_MASK_LSB)
			    | (1 <<
			       PANEL_DISPLAY_CTRL_RESERVED_3_MASK_LSB);

			/* Somehow the register value on the plane is not set
			 * until a few delay. Need to write
			 * and read it a couple times
			 */
			do {
				cnt++;
				POKE32(share->pvReg, PANEL_DISPLAY_CTRL, ulDisplayCtrlReg);
			} while ((PEEK32(share->pvReg, PANEL_DISPLAY_CTRL) &
				  ~ulReservedBits) !=
				 (ulDisplayCtrlReg & ~ulReservedBits));
			pr_debug("Set Panel Plane enbit:after tried %d times\n",
					cnt);
		} else {
			/* When turning off, there is no rule on the programming
			 * sequence since whenever the clock is off, then it does not
			 * matter whether the plane is enabled or disabled.
			 * Note: Modifying the plane bit will take effect on the
			 * next vertical sync. Need to find out if it is necessary to
			 * wait for 1 vsync before modifying the timing enable bit.
			 * */
			ulDisplayCtrlReg =
			    ulDisplayCtrlReg &
			    (~(1 << PANEL_DISPLAY_CTRL_PLANE_LSB));
			POKE32(share->pvReg, PANEL_DISPLAY_CTRL, ulDisplayCtrlReg);

			ulDisplayCtrlReg =
			    ulDisplayCtrlReg &
			    (~(1 << PANEL_DISPLAY_CTRL_TIMING_LSB));
			POKE32(share->pvReg, PANEL_DISPLAY_CTRL, ulDisplayCtrlReg);
		}

	} else {
		/* Set the secondary display control */
		ulDisplayCtrlReg = PEEK32(share->pvReg, CRT_DISPLAY_CTRL);

		if (dispState) {
			/* Timing should be enabled first before enabling the plane because changing at the
			   same time does not guarantee that the plane will also enabled or disabled.
			 */
			ulDisplayCtrlReg =
			    ulDisplayCtrlReg | (1 <<
						CRT_DISPLAY_CTRL_TIMING_LSB);
			POKE32(share->pvReg, CRT_DISPLAY_CTRL, ulDisplayCtrlReg);

			ulDisplayCtrlReg =
			    ulDisplayCtrlReg | (1 <<
						CRT_DISPLAY_CTRL_PLANE_LSB);

			/* Added some masks to mask out the reserved bits.
			 * Sometimes, the reserved bits are set/reset randomly when
			 * writing to the PRIMARY_DISPLAY_CTRL, therefore, the register
			 * reserved bits are needed to be masked out.
			 */

			ulReservedBits =
			    (0X1F << CRT_DISPLAY_CTRL_RESERVED_1_MASK_LSB)
			    | (3 << CRT_DISPLAY_CTRL_RESERVED_2_MASK_LSB) |
			    (1 << CRT_DISPLAY_CTRL_RESERVED_3_MASK_LSB) |
			    (1 << CRT_DISPLAY_CTRL_RESERVED_4_MASK_LSB);
			do {
				cnt++;
				POKE32(share->pvReg, CRT_DISPLAY_CTRL, ulDisplayCtrlReg);
			} while ((PEEK32(share->pvReg, CRT_DISPLAY_CTRL) &
				  ~ulReservedBits) !=
				 (ulDisplayCtrlReg & ~ulReservedBits));
			pr_debug("Set Crt Plane enbit:after tried %d times\n",
					cnt);
		} else {
			/* When turning off, there is no rule on the programming
			 * sequence since whenever the clock is off, then it does not
			 * matter whether the plane is enabled or disabled.
			 * Note: Modifying the plane bit will take effect on the next
			 * vertical sync. Need to find out if it is necessary to
			 * wait for 1 vsync before modifying the timing enable bit.
			 */
			ulDisplayCtrlReg =
			    ulDisplayCtrlReg &
			    (~(1 << CRT_DISPLAY_CTRL_PLANE_LSB));
			POKE32(share->pvReg, CRT_DISPLAY_CTRL, ulDisplayCtrlReg);

			ulDisplayCtrlReg =
			    ulDisplayCtrlReg &
			    (~(1 << CRT_DISPLAY_CTRL_TIMING_LSB));
			POKE32(share->pvReg, CRT_DISPLAY_CTRL, ulDisplayCtrlReg);
		}
	}
}


static void waitNextVerticalSync(struct lynx_share *share, int ctrl, int delay)
{
	unsigned int status;
	if (!ctrl) {
		/* primary controller */

		/* Do not wait when the Primary PLL is off or display control is already off.
		   This will prevent the software to wait forever. */
		if (((1 &
		      (PEEK32(share->pvReg, PANEL_PLL_CTRL) >>
			   PANEL_PLL_CTRL_POWER_LSB)) == PANEL_PLL_CTRL_POWER_OFF)
		    ||
		    ((1 &
		      (PEEK32(share->pvReg, PANEL_DISPLAY_CTRL) >>
		       PANEL_DISPLAY_CTRL_TIMING_LSB)) ==
		     PANEL_DISPLAY_CTRL_TIMING_DISABLE)) {
			return;
		}
		while (delay-- > 0) {
			/* Wait for end of vsync. */
			do {
				status =
				    1 & (PEEK32(share->pvReg, SYSTEM_CTRL) >>
					 SYSTEM_CTRL_PANEL_VSYNC_LSB);
			} while (status == SYSTEM_CTRL_PANEL_VSYNC_ACTIVE);

			/* Wait for start of vsync. */
			do {
				status =
				    1 & (PEEK32(share->pvReg, SYSTEM_CTRL) >>
					 SYSTEM_CTRL_PANEL_VSYNC_LSB);
			} while (status ==
				 SYSTEM_CTRL_PANEL_VSYNC_INACTIVE);
		}

	} else {

		/* Do not wait when the Primary PLL is off or display control is already off.
		   This will prevent the software to wait forever. */
		if (((1 & (PEEK32(share->pvReg, CRT_PLL_CTRL) >>
			CRT_PLL_CTRL_POWER_LSB)) == CRT_PLL_CTRL_POWER_OFF)
		    || ((1 & (PEEK32(share->pvReg, CRT_DISPLAY_CTRL) >>
			 CRT_DISPLAY_CTRL_TIMING_LSB)) ==
			CRT_DISPLAY_CTRL_TIMING_DISABLE)) {
			return;
		}

		while (delay-- > 0) {
			/* Wait for end of vsync. */
			do {
				status =
				    1 & (PEEK32(share->pvReg, SYSTEM_CTRL) >>
					 SYSTEM_CTRL_CRT_VSYNC_LSB);
			} while (status == SYSTEM_CTRL_CRT_VSYNC_ACTIVE);

			/* Wait for start of vsync. */
			do {
				status =
				    1 & (PEEK32(share->pvReg, SYSTEM_CTRL) >>
					 SYSTEM_CTRL_CRT_VSYNC_LSB);
			} while (status == SYSTEM_CTRL_CRT_VSYNC_INACTIVE);
		}
	}
}

static inline void swPanelPowerSequence_sm750le(struct lynx_share *share,
				int disp, int delay)
{
	unsigned int reg;
	reg = PEEK32(share->pvReg, DISPLAY_CONTROL_750LE);
	if (disp)
		reg |= 0xf;
	else
		reg &= ~0xf;
	POKE32(share->pvReg, DISPLAY_CONTROL_750LE, reg);
}

static void swPanelPowerSequence(struct lynx_share *share,
				int disp, int delay)
{
	unsigned int reg;

	/* disp should be 1 to open sequence */
	reg = PEEK32(share->pvReg, PANEL_DISPLAY_CTRL);
	reg &= ~(1 << PANEL_DISPLAY_CTRL_FPEN_LSB);
	reg = reg | (disp << PANEL_DISPLAY_CTRL_FPEN_LSB);
	POKE32(share->pvReg, PANEL_DISPLAY_CTRL, reg);
	primaryWaitVerticalSync(share, delay);

	reg = PEEK32(share->pvReg, PANEL_DISPLAY_CTRL);
	reg &= ~(1 << PANEL_DISPLAY_CTRL_DATA_LSB);
	reg = reg | (disp << PANEL_DISPLAY_CTRL_DATA_LSB);
	POKE32(share->pvReg, PANEL_DISPLAY_CTRL, reg);
	primaryWaitVerticalSync(share, delay);

	reg = PEEK32(share->pvReg, PANEL_DISPLAY_CTRL);
	reg &= ~(1 << PANEL_DISPLAY_CTRL_VBIASEN_LSB);
	reg = reg | (disp << PANEL_DISPLAY_CTRL_VBIASEN_LSB);
	POKE32(share->pvReg, PANEL_DISPLAY_CTRL, reg);
	primaryWaitVerticalSync(share, delay);

	reg = PEEK32(share->pvReg, PANEL_DISPLAY_CTRL);
	reg &= ~(1 << PANEL_DISPLAY_CTRL_FPEN_LSB);
	reg = reg | (disp << PANEL_DISPLAY_CTRL_FPEN_LSB);
	POKE32(share->pvReg, PANEL_DISPLAY_CTRL, reg);
	primaryWaitVerticalSync(share, delay);

}

void ddk750_setLogicalDispOut(struct lynx_share *share,
				disp_output_t output)
{
	unsigned int reg;
	if (output & PNL_2_USAGE) {
		/* set panel path controller select */
		reg = PEEK32(share->pvReg, PANEL_DISPLAY_CTRL);
		reg &= ~(3 << PANEL_DISPLAY_CTRL_SELECT_LSB);
		reg =
		    reg | ((output & PNL_2_MASK) >> PNL_2_OFFSET) <<
		    PANEL_DISPLAY_CTRL_SELECT_LSB;
		POKE32(share->pvReg, PANEL_DISPLAY_CTRL, reg);
	}

	if (output & CRT_2_USAGE) {
		/* set crt path controller select */
		reg = PEEK32(share->pvReg, CRT_DISPLAY_CTRL);
		reg &= ~(3 << CRT_DISPLAY_CTRL_SELECT_LSB);
		reg =
		    reg | ((output & CRT_2_MASK) >> CRT_2_OFFSET) <<
		    CRT_DISPLAY_CTRL_SELECT_LSB;
		/*se blank off */
		reg = reg & (~(1 << CRT_DISPLAY_CTRL_BLANK_LSB));
		POKE32(share->pvReg, CRT_DISPLAY_CTRL, reg);
	}
	if (output & PRI_TP_USAGE) {
		/* set primary timing and plane en_bit */
		setDisplayControl(share, 0,
				  (output & PRI_TP_MASK) >> PRI_TP_OFFSET);
	}

	if (output & SEC_TP_USAGE) {
		/* set secondary timing and plane en_bit */
		setDisplayControl(share, 1,
				  (output & SEC_TP_MASK) >> SEC_TP_OFFSET);
	}

	if (output & PNL_SEQ_USAGE) {
		/* set  panel sequence */
		swPanelPowerSequence(share, (output & PNL_SEQ_MASK) >>
				     PNL_SEQ_OFFSET, 4);
	}

	if (output & DAC_USAGE)
		setDAC(share->pvReg, ((output & DAC_MASK) >> DAC_OFFSET));

	if (output & DPMS_USAGE)
		ddk750_setDPMS(share, ((output & DPMS_MASK) >> DPMS_OFFSET));
}


int ddk750_initDVIDisp(struct lynx_share *share)
{
	/* Initialize DVI. If the dviInit fail and the VendorID or the DeviceID are
	   not zeroed, then set the failure flag. If it is zeroe, it might mean
	   that the system is in Dual CRT Monitor configuration. */

	/* De-skew enabled with default 111b value.
	   This will fix some artifacts problem in some mode on board 2.2.
	   Somehow this fix does not affect board 2.1.
	 */
	if ((dviInit(share,
			1,		/* Select Rising Edge */
		     1,		/* Select 24-bit bus */
		     0,		/* Select Single Edge clock */
		     1,		/* Enable HSync as is */
		     1,		/* Enable VSync as is */
		     1,		/* Enable De-skew */
		     7,		/* Set the de-skew setting to maximum setup */
		     1,		/* Enable continuous Sync */
		     1,		/* Enable PLL Filter */
		     4		/* Use the recommended value for PLL Filter value */
	     ) != 0) && (dviGetVendorID(share) != 0x0000)
	    && (dviGetDeviceID(share) != 0x0000)) {
		return -1;
	}

	/* TODO: Initialize other display component */

	/* Success */
	return 0;

}
