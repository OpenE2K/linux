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
#ifndef DDK750_DVI_H__
#define DDK750_DVI_H__

#ifdef CONFIG_FB_LYNXFB_DOMAINS
/* dvi chip stuffs structros */
typedef long (*PFN_DVICTRL_INIT) (unsigned char edgeSelect,
				  unsigned char busSelect,
				  unsigned char dualEdgeClkSelect,
				  unsigned char hsyncEnable,
				  unsigned char vsyncEnable,
				  unsigned char deskewEnable,
				  unsigned char deskewSetting,
				  unsigned char continuousSyncEnable,
				  unsigned char pllFilterEnable,
				  unsigned char pllFilterValue,
				  int domain);
typedef void (*PFN_DVICTRL_RESETCHIP) (int domain);
typedef char *(*PFN_DVICTRL_GETCHIPSTRING) (int domain);
typedef unsigned short (*PFN_DVICTRL_GETVENDORID) (int domain);
typedef unsigned short (*PFN_DVICTRL_GETDEVICEID) (int domain);
typedef void (*PFN_DVICTRL_SETPOWER) (unsigned char powerUp, int domain);
typedef void (*PFN_DVICTRL_HOTPLUGDETECTION) (unsigned char enableHotPlug, int domain);
typedef unsigned char (*PFN_DVICTRL_ISCONNECTED) (int domain);
typedef unsigned char (*PFN_DVICTRL_CHECKINTERRUPT) (int domain);
typedef void (*PFN_DVICTRL_CLEARINTERRUPT) (int domain);
#else
/* dvi chip stuffs structros */
typedef long (*PFN_DVICTRL_INIT) (unsigned char edgeSelect,
				  unsigned char busSelect,
				  unsigned char dualEdgeClkSelect,
				  unsigned char hsyncEnable,
				  unsigned char vsyncEnable,
				  unsigned char deskewEnable,
				  unsigned char deskewSetting,
				  unsigned char continuousSyncEnable,
				  unsigned char pllFilterEnable,
				  unsigned char pllFilterValue);
typedef void (*PFN_DVICTRL_RESETCHIP) (void);
typedef char *(*PFN_DVICTRL_GETCHIPSTRING) (void);
typedef unsigned short (*PFN_DVICTRL_GETVENDORID) (void);
typedef unsigned short (*PFN_DVICTRL_GETDEVICEID) (void);
typedef void (*PFN_DVICTRL_SETPOWER) (unsigned char powerUp);
typedef void (*PFN_DVICTRL_HOTPLUGDETECTION) (unsigned char enableHotPlug);
typedef unsigned char (*PFN_DVICTRL_ISCONNECTED) (void);
typedef unsigned char (*PFN_DVICTRL_CHECKINTERRUPT) (void);
typedef void (*PFN_DVICTRL_CLEARINTERRUPT) (void);
#endif /* CONFIG_FB_LYNXFB_DOMAINS */


/* Structure to hold all the function pointer to the DVI Controller. */
typedef struct _dvi_ctrl_device_t {
	PFN_DVICTRL_INIT pfnInit;
	PFN_DVICTRL_RESETCHIP pfnResetChip;
	PFN_DVICTRL_GETCHIPSTRING pfnGetChipString;
	PFN_DVICTRL_GETVENDORID pfnGetVendorId;
	PFN_DVICTRL_GETDEVICEID pfnGetDeviceId;
	PFN_DVICTRL_SETPOWER pfnSetPower;
	PFN_DVICTRL_HOTPLUGDETECTION pfnEnableHotPlugDetection;
	PFN_DVICTRL_ISCONNECTED pfnIsConnected;
	PFN_DVICTRL_CHECKINTERRUPT pfnCheckInterrupt;
	PFN_DVICTRL_CLEARINTERRUPT pfnClearInterrupt;
} dvi_ctrl_device_t;
#define DVI_CTRL_SII164


#ifdef CONFIG_FB_LYNXFB_DOMAINS

/* dvi functions prototype */
int dviInit(unsigned char edgeSelect,
	    unsigned char busSelect,
	    unsigned char dualEdgeClkSelect,
	    unsigned char hsyncEnable,
	    unsigned char vsyncEnable,
	    unsigned char deskewEnable,
	    unsigned char deskewSetting,
	    unsigned char continuousSyncEnable,
	    unsigned char pllFilterEnable, unsigned char pllFilterValue,
	    int domain);

unsigned short dviGetVendorID(int domain);
unsigned short dviGetDeviceID(int domain);

#else

/* dvi functions prototype */
int dviInit(unsigned char edgeSelect,
	    unsigned char busSelect,
	    unsigned char dualEdgeClkSelect,
	    unsigned char hsyncEnable,
	    unsigned char vsyncEnable,
	    unsigned char deskewEnable,
	    unsigned char deskewSetting,
	    unsigned char continuousSyncEnable,
	    unsigned char pllFilterEnable, unsigned char pllFilterValue);

unsigned short dviGetVendorID(void);
unsigned short dviGetDeviceID(void);

#endif /* CONFIG_FB_LYNXFB_DOMAINS */



#endif
