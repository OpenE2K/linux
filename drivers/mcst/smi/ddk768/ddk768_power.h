/*******************************************************************
* 
*         Copyright (c) 2007 by Silicon Motion, Inc. (SMI)
* 
*  All rights are reserved. Reproduction or in part is prohibited
*  without the written consent of the copyright owner.
* 
*  power.h --- Voyager GX SDK 
*  This file contains the definitions for the power functions.
* 
*******************************************************************/
#ifndef _DDK768_POWER_H_
#define _DDK768_POWER_H_

struct smi_device;

/*
 *  Enable/disable jpeg decoder 1.
 */
void ddk768_enableJPU1(struct smi_device *sdev, unsigned long enable);


/* 
 * This function enable/disable the 2D engine.
 */
void ddk768_enable2DEngine(struct smi_device *sdev, unsigned long enable);

/* 
 * This function enable/disable the ZV Port 
 */
void ddk768_enableZVPort(struct smi_device *sdev, unsigned long enable);

/* 
 * This function enable/disable the DMA Engine
 */
void ddk768_enableDMA(struct smi_device *sdev, unsigned long enable);



/* 
 * This function enable/disable the PWM Engine
 */
void ddk768_enablePWM(unsigned long enable);

/* 
 * This function enable/disable the SSP.
 */
void ddk768_enableSSP(struct smi_device *sdev, unsigned long enable);

/*
 * This function enable/disable the HDMI Clock. 
 */
void ddk768_enableHDMI(struct smi_device *sdev, unsigned long enable);


void ddk768_enableI2S(struct smi_device *sdev, unsigned long enable);



#endif /* _POWER_H_ */
