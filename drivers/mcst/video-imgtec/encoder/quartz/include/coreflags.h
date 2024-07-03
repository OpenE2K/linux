/*!
 *****************************************************************************
 *
 * @File       coreflags.h
 * @Title      VXE Firmware Features support
 * @Description    Definitions used by the VXE encoder host-firmware interface to know what
 *  can be done with the firmware
 * ---------------------------------------------------------------------------
 *
 * Copyright (c) Imagination Technologies Ltd.
 * 
 * The contents of this file are subject to the MIT license as set out below.
 * 
 * Permission is hereby granted, free of charge, to any person obtaining a 
 * copy of this software and associated documentation files (the "Software"), 
 * to deal in the Software without restriction, including without limitation 
 * the rights to use, copy, modify, merge, publish, distribute, sublicense, 
 * and/or sell copies of the Software, and to permit persons to whom the 
 * Software is furnished to do so, subject to the following conditions:
 * 
 * The above copyright notice and this permission notice shall be included in 
 * all copies or substantial portions of the Software.
 * 
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR 
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, 
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE 
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER 
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, 
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN 
 * THE SOFTWARE.
 * 
 * Alternatively, the contents of this file may be used under the terms of the 
 * GNU General Public License Version 2 ("GPL")in which case the provisions of
 * GPL are applicable instead of those above. 
 * 
 * If you wish to allow use of your version of this file only under the terms 
 * of GPL, and not to allow others to use your version of this file under the 
 * terms of the MIT license, indicate your decision by deleting the provisions 
 * above and replace them with the notice and other provisions required by GPL 
 * as set out in the file called "GPLHEADER" included in this distribution. If 
 * you do not delete the provisions above, a recipient may use your version of 
 * this file under the terms of either the MIT license or GPL.
 * 
 * This License is also included in this distribution in the file called 
 * "MIT_COPYING".
 *
 *****************************************************************************/

#if !defined (_COREFLAGS_H_)
#define _COREFLAGS_H_

#ifdef __cplusplus
extern "C" {
#endif

//  This will ensure the drivers/FW will work will both the old and the new environmental variables (should eventually be able to remove this)



/* Trace memory usage */
//#define TRACE_MEMORY_USAGE

/* Write outputs from the firmware like printf() statements */
//#define FW_LOGGING (1)

/* Light weight event logging intended to be always enabled */
#define FW_TRACE 1

/* Verbose logging of events within firmware */
#define FW_TRACE_VERBOSE 0

/* This define controls whether the fw trace is actually used in the driver*/
#define USE_FW_TRACE 

//#if defined(ENCFMT_H264MVC) || !defined(QUARTZ_LTP_HW)
//#	define ENCFMT_H264
//#	define _ENABLE_MVC_        /* Defined for enabling MVC specific code */
//#	define _MVC_RC_  1         /* Defined for enabling MVC rate control code, later on it will be replaced by _ENABLE_MVC_ */
//#endif

#if defined(RCMODE_ALL) || !defined(QUARTZ_LTP_HW)
#	define RCMODE_CBR
#	define RCMODE_VBR
#	define RCMODE_VCM
#	define RCMODE_SRC
#endif


#if defined(RCMODE_NONE)
#	define __COREFLAGS_RC_ALLOWED__	0
#else
#	define __COREFLAGS_RC_ALLOWED__ 1
#endif

/* Check if user defined GOPs fit in Predefined GOPs */
#define FIT_RC_GOP_TYPE		1

#define QUARTZ_MAX_BU_SUPPORT	128
/* 
	Determine possible rate control modes.
*/
#if !defined(QUARTZ_LTP_HW)
#	define	CBR_RC_MODE_POSSIBLE	__COREFLAGS_RC_ALLOWED__
#	define  VCM_RC_MODE_POSSIBLE	__COREFLAGS_RC_ALLOWED__
#	define  VBR_RC_MODE_POSSIBLE	__COREFLAGS_RC_ALLOWED__
#else
#	if defined(RCMODE_CBR)
#		define	CBR_RC_MODE_POSSIBLE	__COREFLAGS_RC_ALLOWED__
#	else
#		define	CBR_RC_MODE_POSSIBLE	FALSE
#	endif
#	if defined(RCMODE_SRC)
#		define	SRC_RC_MODE_POSSIBLE	__COREFLAGS_RC_ALLOWED__
#	else
#		define	SRC_RC_MODE_POSSIBLE	FALSE
#	endif
#	if defined(RCMODE_VCM) 
		/* VCM is possible only for H264 and VP8*/
#		define  VCM_RC_MODE_POSSIBLE	__COREFLAGS_RC_ALLOWED__
#	else
#		define	VCM_RC_MODE_POSSIBLE	FALSE
#	endif
#	if defined(RCMODE_VBR)
#		define  VBR_RC_MODE_POSSIBLE	__COREFLAGS_RC_ALLOWED__
#	else
#		define	VBR_RC_MODE_POSSIBLE	FALSE
#	endif
#	if defined(RCMODE_ERC)
#		define  ERC_RC_MODE_POSSIBLE	__COREFLAGS_RC_ALLOWED__
#	else
#		define	ERC_RC_MODE_POSSIBLE	FALSE
#	endif
#endif

#define	INCLUDE_HIER_SUPPORT	1
#define MULTI_REF_P				1
	
#if INCLUDE_HIER_SUPPORT
#	define MAX_REF_B_LEVELS_FW	3
#else
#	define MAX_REF_B_LEVELS_FW	0
#endif /* INCLUDE_HIER_SUPPORT */

#ifdef MULTI_REF_P
#	define MAX_REF_I_OR_P_LEVELS_FW	(MAX_REF_I_OR_P_LEVELS)
#else
#	define MAX_REF_I_OR_P_LEVELS_FW	2
#endif


#define RATE_CONTROL_AVAILABLE (\
		CBR_RC_MODE_POSSIBLE || VCM_RC_MODE_POSSIBLE || \
		VBR_RC_MODE_POSSIBLE || SRC_RC_MODE_POSSIBLE \
	)
#define RC_MODE_POSSIBLE(MODE) (MODE ## _RC_MODE_POSSIBLE)

#define RC_MODES_POSSIBLE2(M1, M2) \
	(RC_MODE_POSSIBLE(M1) || RC_MODE_POSSIBLE(M2))

#define RC_MODES_POSSIBLE3(M1, M2, M3) \
	(RC_MODES_POSSIBLE2(M1, M2) || RC_MODE_POSSIBLE(M3))

/*
	Declare `CUR_ENCODE_RC_MODE` as proper function only in USE_FAKE_FW.
	Alternatively, declare it as constant.
*/
#if  defined(RCMODE_ALL)
#	define	CUR_ENCODE_RC_MODE (psFWCurrentContext->sRateCtrlVariables.sRCParams.eRCMode)
#elif defined(RCMODE_NONE)
#	define CUR_ENCODE_RC_MODE (VXE_RC_MODE_NONE)
#elif defined(RCMODE_CBR)
#	define CUR_ENCODE_RC_MODE (VXE_RC_MODE_CBR)
#elif defined(RCMODE_VBR)
#	define CUR_ENCODE_RC_MODE (VXE_RC_MODE_VBR)
#elif defined(RCMODE_VCM)
#	define CUR_ENCODE_RC_MODE (VXE_RC_MODE_VCM)
#elif defined(RCMODE_SRC)
#	define CUR_ENCODE_RC_MODE (VXE_RC_MODE_SRC)
#endif

#define FIRMWARE_SUPPORT_VCM_HW (1)


// Note: 
// We currently use MAX_SLICES_PER_SLICEMAP so we can have a static array aui8SliceMap in the VXE_SLICE_MAP driver structure
// This value currently needs to be capable of being stored in an unsigned integer (we could increase this if we turned all slice count storage types to 16 bit, including the slicemap entry itself)
#define MAX_SLICES_PER_SLICEMAP 255



// Note:
//					[NUM TILES THIS PIPE]
//					[NUM SLICES THIS PIPE]
//					[XPOS START IN CTU][YPOS START IN CTU]	- Start of region this tile is going to work on (In H264 these are used for slice group start and XPOS START must always be 0)
//					[XPOS END IN CTU][YPOS END IN CTU]		- End of region this tile is going to work on (In H264 these are used for slice group end and XPOS END must always be size of a row in CTUs)
//						[KICK SIZE THIS TILE]				- Tiles may be different in size and we want to avoid kicks to wrap over several lines
//						[CONTROL INFORMATION THIS TILE]		- Any BU_FORCE_MODE operations that should be applied to this tile
//						[NUM SLICES THIS TILE] 
//						[FRAME SLICENUM] [CTU COUNT] [ ..]
//						[FRAME SLICENUM] [CTU COUNT] [ ..]
// NOTE: We no longer support dependent slices
// etc.
#define MAX_SLICEMAP_SIZE	( \
								(1 /*[NUM TILES THIS PIPE]*/) + \
								(1 /*[NUM SLICES THIS PIPE]*/) + \
								(MAX_SLICES_PER_SLICEMAP /*[MAX NUMBER OF SLICES (slices >= tiles)]*/ * \
									( \
										(4 /*[XPOS START IN CTU][YPOS START IN CTU][XPOS END IN CTU][YPOS END IN CTU]*/) + \
										(2 /*[KICK SIZE THIS TILE]*/) + \
										(1 /*[CONTROL INFORMATION THIS TILE]*/) + \
										(1 /*[NUM SLICES THIS TILE]*/) + \
										(1 /*[FRAME SLICENUM]*/) + \
										(4 /*[CTU COUNT]*/) \
									) \
								) \
							)

/* Define a maximum to have one but it can be increased when needed */
#define FW_TOTAL_CONTEXT_SUPPORT (16)

#define MIN_CTU_COUNT_PER_KICK (10)
#define MAX_BU_SUPPORT (128)

/* Quartz added a quarter-pixel crop precision, these defines are used for readability in the parsing/setting of the crop */
#define FRACT_CROP_TOP		(0)
#define FRACT_CROP_BOTTOM	(1)
#define FRACT_CROP_LEFT		(2)
#define FRACT_CROP_RIGHT	(3)
/* Each direction has an optional added precision, there are four of them */
#define FRACTIONAL_CROPS	(4)



#ifdef __cplusplus
} /* extern "C"  */
#endif
#endif // !defined (_COREFLAGS_H_)
