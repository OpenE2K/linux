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
#ifdef USE_DVICHIP
#include "ddk750_help.h"
#include "ddk750_reg.h"
#include "ddk750_dvi.h"
#include "ddk750_sii164.h"


/* This global variable contains all the supported driver and its corresponding
   function API. Please set the function pointer to NULL whenever the function
   is not supported. */
static dvi_ctrl_device_t g_dcftSupportedDviController[] = {
#ifdef DVI_CTRL_SII164
	{
	 .pfnInit = sii164InitChip,
	 .pfnGetVendorId = sii164GetVendorID,
	 .pfnGetDeviceId = sii164GetDeviceID,
#ifdef SII164_FULL_FUNCTIONS
	 .pfnResetChip = sii164ResetChip,
	 .pfnGetChipString = sii164GetChipString,
	 .pfnSetPower = sii164SetPower,
	 .pfnEnableHotPlugDetection = sii164EnableHotPlugDetection,
	 .pfnIsConnected = sii164IsConnected,
	 .pfnCheckInterrupt = sii164CheckInterrupt,
	 .pfnClearInterrupt = sii164ClearInterrupt,
#endif
	 },
#endif
};

#ifdef CONFIG_FB_LYNXFB_DOMAINS

int dviInit(unsigned char edgeSelect,
	    unsigned char busSelect,
	    unsigned char dualEdgeClkSelect,
	    unsigned char hsyncEnable,
	    unsigned char vsyncEnable,
	    unsigned char deskewEnable,
	    unsigned char deskewSetting,
	    unsigned char continuousSyncEnable,
	    unsigned char pllFilterEnable, unsigned char pllFilterValue,
	    int domain)
{
	dvi_ctrl_device_t *pCurrentDviCtrl;
	pCurrentDviCtrl = g_dcftSupportedDviController;
	if (pCurrentDviCtrl->pfnInit != NULL) {
		return pCurrentDviCtrl->pfnInit(edgeSelect, busSelect,
						dualEdgeClkSelect,
						hsyncEnable, vsyncEnable,
						deskewEnable,
						deskewSetting,
						continuousSyncEnable,
						pllFilterEnable,
						pllFilterValue,
						domain);
	}
	return -1;		/* error */
}


/*
 *  dviGetVendorID
 *      This function gets the vendor ID of the DVI controller chip.
 *
 *  Output:
 *      Vendor ID
 */
unsigned short dviGetVendorID(int domain)
{
	dvi_ctrl_device_t *pCurrentDviCtrl;

	/*pCurrentDviCtrl = getDviCtrl(); */
	pCurrentDviCtrl = g_dcftSupportedDviController;
	if (pCurrentDviCtrl != (dvi_ctrl_device_t *) 0)
		return pCurrentDviCtrl->pfnGetVendorId(domain);

	return 0x0000;
}


/*
 *  dviGetDeviceID
 *      This function gets the device ID of the DVI controller chip.
 *
 *  Output:
 *      Device ID
 */
unsigned short dviGetDeviceID(int domain)
{
	dvi_ctrl_device_t *pCurrentDviCtrl;

	/*    pCurrentDviCtrl = getDviCtrl(); */
	pCurrentDviCtrl = g_dcftSupportedDviController;
	if (pCurrentDviCtrl != (dvi_ctrl_device_t *) 0)
		return pCurrentDviCtrl->pfnGetDeviceId(domain);

	return 0x0000;
}


#else /* !CONFIG_FB_LYNXFB_DOMAINS: */


int dviInit(unsigned char edgeSelect,
	    unsigned char busSelect,
	    unsigned char dualEdgeClkSelect,
	    unsigned char hsyncEnable,
	    unsigned char vsyncEnable,
	    unsigned char deskewEnable,
	    unsigned char deskewSetting,
	    unsigned char continuousSyncEnable,
	    unsigned char pllFilterEnable, unsigned char pllFilterValue)
{
	dvi_ctrl_device_t *pCurrentDviCtrl;
	pCurrentDviCtrl = g_dcftSupportedDviController;
	if (pCurrentDviCtrl->pfnInit != NULL) {
		return pCurrentDviCtrl->pfnInit(edgeSelect, busSelect,
						dualEdgeClkSelect,
						hsyncEnable, vsyncEnable,
						deskewEnable,
						deskewSetting,
						continuousSyncEnable,
						pllFilterEnable,
						pllFilterValue);
	}
	return -1;		/* error */
}


/*
 *  dviGetVendorID
 *      This function gets the vendor ID of the DVI controller chip.
 *
 *  Output:
 *      Vendor ID
 */
unsigned short dviGetVendorID()
{
	dvi_ctrl_device_t *pCurrentDviCtrl;

	/*pCurrentDviCtrl = getDviCtrl(); */
	pCurrentDviCtrl = g_dcftSupportedDviController;
	if (pCurrentDviCtrl != (dvi_ctrl_device_t *) 0)
		return pCurrentDviCtrl->pfnGetVendorId();

	return 0x0000;
}


/*
 *  dviGetDeviceID
 *      This function gets the device ID of the DVI controller chip.
 *
 *  Output:
 *      Device ID
 */
unsigned short dviGetDeviceID()
{
	dvi_ctrl_device_t *pCurrentDviCtrl;

	/*    pCurrentDviCtrl = getDviCtrl(); */
	pCurrentDviCtrl = g_dcftSupportedDviController;
	if (pCurrentDviCtrl != (dvi_ctrl_device_t *) 0)
		return pCurrentDviCtrl->pfnGetDeviceId();

	return 0x0000;
}

#endif /* CONFIG_FB_LYNXFB_DOMAINS */


#endif
