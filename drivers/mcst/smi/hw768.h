/*
 * Copyright 2016 SiliconMotion Inc.
 *
 * This file is subject to the terms and conditions of the GNU General
 * Public License version 2. See the file COPYING in the main
 * directory of this archive for more details.
 *
 */


#ifndef LYNX_HW768_H__
#define LYNX_HW768_H__
#include "hw_com.h"
#include "smi_drv.h"

void hw768_enable_lvds(struct smi_device *sdev, int channels);

void ddk768_set_mmio(volatile unsigned char * addr,unsigned short devId,char revId);
unsigned long ddk768_getFrameBufSize(struct smi_device *sdev);
long ddk768_initChip(struct smi_device *sdev);
void ddk768_deInit(struct smi_device *sdev);

void ddk768_swPanelPowerSequence(struct smi_device *sdev,
						disp_control_t dispControl,
						disp_state_t dispState,
						unsigned long vSyncDelay);


long ddk768_edidHeaderReadMonitorEx(
	struct smi_device *sdev,
    unsigned char sclGpio,
    unsigned char sdaGpio
);

long ddk768_edidHeaderReadMonitorExHwI2C(
	struct smi_device *sdev,
    unsigned char i2cNumber
);


long ddk768_detectCRTMonitor(struct smi_device *sdev,
	disp_control_t dispControl, unsigned char redValue,
	unsigned char greenValue, unsigned char blueValue);

long ddk768_edidReadMonitor(
	struct smi_device *sdev,
    unsigned char *pEDIDBuffer,
    unsigned long bufferSize,
    unsigned char edidExtNo,
    unsigned char i2cNumber
);



long ddk768_edidReadMonitorEx(
	struct smi_device *sdev,
    unsigned char *pEDIDBuffer,
    unsigned long bufferSize,
    unsigned char edidExtNo,
    unsigned char sclGpio,
    unsigned char sdaGpio
);


int hw768_get_hdmi_edid(struct smi_device *sdev, unsigned char *pEDIDBuffer);


long ddk768_edidReadMonitorExHwI2C(
	struct smi_device *sdev,
    unsigned char *pEDIDBuffer,
    unsigned long bufferSize,
    unsigned char edidExtNo,
    unsigned char i2cNumber
);

/*
 * Disable double pixel clock. 
 * This is a teporary function, used to patch for the random fuzzy font problem. 
 */
void EnableDoublePixel(struct smi_device *sdev, disp_control_t dispControl);
void DisableDoublePixel(struct smi_device *sdev, disp_control_t dispControl);

/*
 * This function initializes the cursor attributes.
 */
void ddk768_initCursor(
	struct smi_device *sdev,
    disp_control_t dispControl,     /* Display control (CHANNEL0_CTRL or CHANNEL1_CTRL) */
    unsigned long base,             /* Base Address */ 
    unsigned long color1,           /* Cursor color 1 in RGB 5:6:5 format */
    unsigned long color2,           /* Cursor color 2 in RGB 5:6:5 format */
    unsigned long color3            /* Cursor color 3 in RGB 5:6:5 format */
);

/*
 * This function sets the cursor position.
 */
void ddk768_setCursorPosition(
	struct smi_device *sdev,
    disp_control_t dispControl,     /* Display control (CHANNEL0_CTRL or CHANNEL1_CTRL) */
    unsigned long dx,               /* X Coordinate of the cursor */
    unsigned long dy,               /* Y Coordinate of the cursor */
    unsigned char topOutside,       /* Top Boundary Select: either partially outside (= 1) 
                                       or within the screen top boundary (= 0) */
    unsigned char leftOutside       /* Left Boundary Select: either partially outside (= 1) 
                                       or within the screen left boundary (= 0) */
);
 
void hw768_set_base(struct smi_device *sdev,
				int display, int pitch, int base_addr);
 
/*
 * This function enables/disables the cursor.
 */
void ddk768_enableCursor(
	struct smi_device *sdev,
    disp_control_t dispControl,     /* Display control (CHANNEL0_CTRL or CHANNEL1_CTRL) */
    unsigned long enable
);

void hw768_HDMI_Enable_Output(struct smi_device *sdev);

void hw768_HDMI_Disable_Output(struct smi_device *sdev);

 
long ddk768_setMode(
	struct smi_device *sdev,
    logicalMode_t *pLogicalMode
);
long setSingleViewOn(struct smi_device *sdev,
				disp_control_t dispOutput, disp_format_t dispFormat);

void setDisplayDPMS(
	struct smi_device *sdev,
   disp_control_t dispControl, /* Channel 0 or Channel 1) */
   DISP_DPMS_t state, /* DPMS state */
   int lvds /* configure LVDS channel */
   );

void hw768_init_hdmi(struct smi_device *sdev);
int hw768_set_hdmi_mode(struct smi_device *sdev,
				logicalMode_t *pLogicalMode, bool isHDMI);

void ddk768_setDisplayEnable(struct smi_device *sdev,
disp_control_t dispControl, /* Channel 0 or Channel 1) */
disp_state_t dispState /* ON or OFF */);

int hw768_check_iis_interrupt(volatile unsigned char __iomem *rmmio);

int hw768_check_vsync_interrupt(struct smi_device *sdev, int path);
void hw768_clear_vsync_interrupt(struct smi_device *sdev, int path);


int hw768_en_dis_interrupt(struct smi_device *sdev,
								int status, int pipe);

int hdmi_detect(struct smi_device *sdev);

inline int hdmi_hotplug_detect(struct smi_device *sdev);

void HDMI_Audio_Mute(volatile unsigned char __iomem *rmmio);

void HDMI_Audio_Unmute(volatile unsigned char __iomem *rmmio);

void ddk768_disable_IntMask(struct smi_device *sdev);

void hw768_suspend(struct smi_768_register * pSave);
void hw768_resume(struct smi_768_register * pSave);

#endif
