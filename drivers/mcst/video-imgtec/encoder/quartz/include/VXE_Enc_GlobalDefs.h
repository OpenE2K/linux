/*!
 *****************************************************************************
 *
 * @File       VXE_Enc_GlobalDefs.h
 * @Title      VXE Encoder global definitions
 * @Description    Definitions used by the entire VXE encoder (eg. diagnostic mode defines)
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

#ifndef _VXE_ENC_GLOBALDEFS_H_
#define _VXE_ENC_GLOBALDEFS_H_

#include "coreflags.h"

// Activate below if you want to disable H264 10 bit max slice size profile constraints
// #define IGNORE_H264_SLICE_PROFILE_CONSTRAINTS 1



//#define TRACEFILE


#define		CODED_DATA_HDR_UNDEFINED	0	// Undefined - shouldn't be used
//#define 	CODED_DATA_HDR_RETURN_EOS	1	// End of slice - NO LONGER USED (see definition for EODS)
#define 	CODED_DATA_HDR_RETURN_EON	2	// End of node - used mostly by low latency (but can occur where multiple EOT messages span nodes), this type of header will not contain any useful stat data and should be largely ignored by any stat reliant process.
#define 	CODED_DATA_HDR_RETURN_EODS	3	// End of dynamic slice (or normal slice) - this type of header will not contain any useful stat data and should be largely ignored by any stat reliant process. The encoder is unable to distinguish between dynamic slices and predetermined commandline slices.
#define 	CODED_DATA_HDR_RETURN_EOT	4	// End of tile (may be removed)  - this header contains valid stats for the last tile (even where previous nodes within the slice may have already been output in low latency mode)


#define VXE_LEVELTIMES10_UNDEFINED	0
#define MAX_NUM_TILE_SETUPS 4



#define VXE_DEFAULT_eCodec										VXE_CODEC_H265 // was VXE_CODEC_H264, but most of the sim bringup is hevc focused
#define VXE_DEFAULT_eInputFormat								FRAME_STORE_420PL111YCbCr8 // 8-bit YUV
#define VXE_DEFAULT_eInputFormat_10								FRAME_STORE_420PL111YCbCr10 // 10-bit YUV
#define VXE_DEFAULT_ui32StartFrame								0
#define VXE_DEFAULT_ui32NumFramesToEncode						0

#define VXE_DEFAULT_bHierarchical								IMG_FALSE
#define VXE_DEFAULT_ui32BFrameCount								1
#define VXE_DEFAULT_ui32IntraLoopCnt							3
#define VXE_DEFAULT_DecRefreshType								2	//!< Default CRA, which will do an IDR for AVC.
#define VXE_DEFAULT_qpoffset_of_B_frames						0
#define VXE_DEFAULT_qpoffset_of_P_frames						0
#define VXE_DEFAULT_ui32IdrCnt									1	//!< By default, all I frames are IDR
#define VXE_DEFAULT_ui32LtrCnt									0
#define VXE_DEFAULT_bDisableVuiParams							IMG_TRUE
#define VXE_DEFAULT_bEnableHRDParams							(IMG_FALSE)
#define VXE_DEFAULT_bEnableSEI_DPH								(IMG_FALSE)
#define VXE_DEFAULT_bRepeatSequenceHeader						(IMG_FALSE)


//#define VXE_DEFAULT_i32QP_Level1								0
//#define VXE_DEFAULT_i32QP_Level2								0
//#define VXE_DEFAULT_i32QP_Level3								0
//#define VXE_DEFAULT_i32QP_Level4								0
//#define VXE_DEFAULT_i32QP_Level5								0
//#define VXE_DEFAULT_i32QP_OffsetI								0
//#define VXE_DEFAULT_i32QP_OffsetB								0
//#define VXE_DEFAULT_i32QP_OffsetP								0

#define VXE_DEFAULT_ui32Framerate								30

#define VXE_DEFAULT_bUseCol1									1
#define VXE_DEFAULT_uiSpeedup									1

#define VXE_DEFAULT_bVCMEnable									IMG_TRUE
#define VXE_DEFAULT_ui32VcmHwUMaxLevel							7
#define VXE_DEFAULT_b8VcmHwUpdatebyBU							IMG_FALSE

#define VXE_DEFAULT_bCFSonIFrames								IMG_TRUE


#define VXE_DEFAULT_ui32CABACBitLimit_AVC_8						4500
#define VXE_DEFAULT_ui32CABACBitLimit_HEVC_8					5000
#define VXE_DEFAULT_ui32CABACBitLimit_AVC_10					5625
#define VXE_DEFAULT_ui32CABACBitLimit_HEVC_10					6250
#define VXE_DEFAULT_ui32CABACDBMargin							768


#define VXE_DEFAULT_bCarcEnabled								IMG_FALSE
#define VXE_DEFAULT_ui8CarcNegScale								0
#define VXE_DEFAULT_ui8CarcNegRange								10
#define VXE_DEFAULT_ui8CarcPosScale								0
#define VXE_DEFAULT_ui8CarcPosRange								10
#define VXE_DEFAULT_ui8CarcShift								2
#define VXE_DEFAULT_ui8CarcCutoff								15
#define VXE_DEFAULT_ui16CarcThreshold							2
#define VXE_DEFAULT_ui16CarcBaseline							0

#define VXE_DEFAULT_ui32SlicesPerFrame							1
#define VXE_DEFAULT_ui32QP_Luma									26
#define VXE_DEFAULT_iQP_Chroma_Offset							0

#define VXE_DEFAULT_ui8POC_Type									0

#define VXE_DEFAULT_ui32MaxInterruptPeriod						1 // generate an interrupt per frame by default

#define VXE_DEFAULT_motion_search_on_I_frames					IMG_FALSE
#define VXE_DEFAULT_bCBufferUpdateOnSliceMode					IMG_FALSE
#define VXE_DEFAULT_ui32CBPerEncode								1
#define VXE_DEFAULT_ui32CBPartitions							1
#define VXE_DEFAULT_ui32CBListsPerEncode						1
#define VXE_DEFAULT_ui32CBPerList								1
#define VXE_DEFAULT_ui8MinCbSize								8 // Minimum coded block size (>= 2^3)
#define VXE_DEFAULT_eEncProfile									VXE_PROFILE_UNDEFINED

#define VXE_DEFAULT_ui8NumberOfTemporalLayers					1
#define VXE_DEFAULT_ui16LevelTimes10							VXE_LEVELTIMES10_UNDEFINED // Note: A Zero value indicates it should be calculated from the API settings
#define VXE_DEFAULT_bHighTier									0  // High tier
#define VXE_DEFAULT_ui32Log2ParallelMergeLevel					2

#define VXE_DEFAULT_ROI_QP_ui8ApplyAsOffset						IMG_TRUE
#define VXE_DEFAULT_ROI_QP_ui8Val								0x20	//Twos Compliment Default to 0x20 (-32)

#define VXE_DEFAULT_bLoopFilterAcrossSlice						0
#define VXE_DEFAULT_bLoopFilterAcrossTile						0

#define VXE_DEFAULT_bSignDataHiding								1
#define VXE_DEFAULT_bTransformSkipEnabled						1
#define VXE_DEFAULT_bLosslessMode								0
#define VXE_DEFAULT_bLosslessIntra8x8PreFilter					1 // Default is no x264 compatibility

#define VXE_DEFAULT_bDependentSliceSegments						0
#define VXE_DEFAULT_bTemporalMvp								1
#define VXE_DEFAULT_bAsymetricMotionPartition					1
#define VXE_DEFAULT_ui32SubPelResolution						(0x1) // Default to the finest granularity, quarter pixel 0.25 in floating point, 0x1 in unsigned fixed point
#define	VXE_DEFAULT_ui32ForcedKickSize							0	// Default of zero indicates the API should choose an appropriate size itself
#define VXE_DEFAULT_bDisableEncSizeCheck						IMG_FALSE;

#define VXE_DEFAULT_ui8InterTransformHierarchyDepth				8
#define VXE_DEFAULT_ui8IntraTransformHierarchyDepth				8

#define VXE_DEFAULT_ui8TransformBlockSize						16
#define VXE_DEFAULT_ui8MinTransformBlockSize					4

#define VXE_DEFAULT_bAPMEachFrame								(IMG_FALSE)  /* off by default */

#define VXE_DEFAULT_bInterScaleUpdateByQp						(IMG_FALSE)  /* off by default */

 //!< Fixed Qp Mode (ie no rate control)
#define VXE_DEFAULT_eRcMode										VXE_RC_MODE_FIXED_QP

/* Used by the RC to check for variable overflows */
#define MAX_INT32			0X7FFFFFFF
#define MAX_INT32_DIV_BY_10	0X0CCCCCCC

/* General video related defines */
#define MIN_QP_10BIT		(-12)
#define QP_OFFSET_10BITS	(12)
#define MAX_QP_10BIT		(51)

#define MIN_QP_8BIT			(0)
#define MAX_QP_8BIT			(51)

#define VXE_DEFAULT_ui32CbrBufferTenths							10
#define VXE_DEFAULT_bDisableStuffing							IMG_FALSE
#define VXE_DEFAULT_bDisableFrameSkipping						IMG_FALSE
#define VXE_DEFAULT_bSceneDetectDisable							IMG_FALSE
#define VXE_DEFAULT_uRCCfsMaxMarginPerc							9

#define VXE_DEFAULT_bLowLatency									(IMG_FALSE)
#define VXE_DEFAULT_ui8PictureParameterSetCnt					1
#define VXE_DEFAULT_bSAO										(IMG_FALSE)
#define VXE_DEFAULT_i8CBQpOffset								(0)
#define VXE_DEFAULT_i8CRQpOffset								(0)
#define VXE_DEFAULT_i32ChromaQpOffset							(0)

#define VXE_DEFAULT_bDisableLL									0 // Linked-list stays on (redundant with below)

#define VXE_DEFAULT_ui8VideoFormat								1 // 1: PAL 2: NTSC ...
#define VXE_DEFAULT_b8Overscan									1
#define VXE_DEFAULT_b8UseConformanceWindow						1
#define VXE_DEFAULT_b8UsePCM									1
#define VXE_DEFAULT_ui8PCMLumaDepth								0 // 0 default will tell the API to set it
//#define VXE_DEFAULT_ui8PCMChromaDepth							8
#define VXE_DEFAULT_ui8PCMMaxCBSize								16
#define VXE_DEFAULT_ui8PCMMinCBSize								8
#define VXE_DEFAULT_b8PCMLoopFilter								1
#define VXE_DEFAULT_ui8CuQpDeltaDepth							1
#define VXE_DEFAULT_eDeblockMode								(VXE_DEBLOCK_ENABLED)
#define VXE_DEFAULT_eColumnStoreMode							(VXE_COLSTORE_DEFAULT)
#define VXE_DEFAULT_i8DeblockingBetaOffset						0
#define VXE_DEFAULT_i8DeblockingTcOffset						0
#define VXE_DEFAULT_eCSCMode									VXE_CSC_NONE
#define VXE_DEFAULT_bHwFifoOutput								IMG_FALSE
#define VXE_DEFAULT_b8NoMemO									IMG_FALSE

#define VXE_DEFAULT_bSecureMem									0 // no secure mem
#define VXE_DEFAULT_bWeightedPrediction							0 // Desactivated for first version of Quartz
#define VXE_DEFAULT_bCABAC										1 // always use CABAC
#define VXE_DEFAULT_ui32CABACBinLimit							1440 
#define VXE_DEFAULT_ui32CABACBinFlex							14500
#define VXE_DEFAULT_bDisableIntraResSkip						(IMG_FALSE)
#define VXE_DEFAULT_ui16PrefetchMVLimitX_AVC					2048
#define VXE_DEFAULT_ui16PrefetchMVLimitY_AVC					511
#define VXE_DEFAULT_ui16PrefetchMVLimitX_HEVC					4095
#define VXE_DEFAULT_ui16PrefetchMVLimitY_HEVC					4095
#define VXE_DEFAULT_ui32MaxSliceSize							0 // no limit

#define VXE_DEFAULT_bDirectSpatial								IMG_TRUE // Use spatial Direct as the default

#define VXE_DEFAULT_bHostHeaders								IMG_FALSE

#define VXE_DEFAULT_eIntraRefreshMode							INTRA_REFRESH_OFF
#define VXE_DEFAULT_ui16CTUsToForce								2
#define VXE_DEFAULT_ui16CTUIncrement							1
#define VXE_DEFAULT_ui32IntraRefreshPeriod                      0
#define VXE_DEFAULT_ui16IntraRefreshSizeIncrease				30 // 30% increase
#define VXE_DEFAULT_i16IntraRefreshQpDelta						2

#define VXE_DEFAULT_TILE_STRIDE									512

#define VXE_DEFAULT_bCheckCRCs									(0) // for HW verification, CRCs are enabled by default is not specified otherwise, this will change later on

#define VXE_DEFAULT_bRefFBCEnabled								(0)
#define VXE_DEFAULT_bSrcFBCEnabled								(0)
#define VXE_DEFAULT_bFBCByPassEnabled							(1)

#define VXE_DEFAULT_ui32LineStoreSize							(0) // 0 means line-store disabled
#define VXE_DEFAULT_ui32LineStoreOffset                         (0)

#define VXE_DEFAULT_num_bits_poc								5

#define NUM_SLICE_TYPES			5
#define MAX_COMMANDS			10
#define MAX_FILE_NAME_LENGTH	256
#define NUM_ELEMENTS_RPS_ARRAYS 8
#define MAX_LTR_BUFFERS					2
/*Maximum number of frames that can be queued for encoding at a later time*/
	#define MAX_SOURCE_BUFFER_COUNT	10

#define CACHE_NONE				0
#define CACHE_PIC0				1
#define CACHE_BOTH				2
#define CACHE_SAME				3

#define MAX_DYNAMIC_PARAMS_DATA_LENGTH		256				//!< maximum structure size for a dynamic parameter (set using -qptable)
#define MAX_LINE_LENGTH						512				//<! max length of the line for reading the static qp values
#define NUM_VALUES_ON_EACH_LINE				4				//<!default number of values expected in each line


// THESE DEFINES ARE PRIMARILY USED TO SET COMMON HEADER ELEMENTS TO KNOWN VALUES. SOME ARE ALSO BE USED FOR OTHER API OR PROFILE-LEVEL DECISIONS.
// HEVC/H265 HEADER KNOWN VALUE DEFINES
#define AVC_SEQ_PARAMETER_ID_VAL 0


#define HEVC_SPS_SEQ_PARAMETER_ID_VAL 0
#define HEVC_BP_SEQ_PARAMETER_SET_ID_VAL HEVC_SPS_SEQ_PARAMETER_ID_VAL
#define HEVC_VCL_HRD_PARAMETERS_PRESENT_FLAG_VAL 0
#define HEVC_SUB_PIC_CPB_PARAMS_IN_PIC_TIMING_SEI_FLAG_VAL 1 //equal to 1 specifies that sub-picture level CPB removal delay parameters are present in picture timing SEI messages and no decoding unit information SEI message is available (in the CVS or Rec.ITU - T H.265 (10 / 2014) Prepublished version 376 provided through external means not specified in this Specification)
#define IRAP_CPB_PARAMS_PRESENT_FLAG 0

#define HEVC_SUB_PIC_HRD_PARAMS_PRESENT_FLAG_VAL 0	// Probably zero for Quartz???
#define HEVC_IRAP_CPB_PARAMS_PRESENT_FLAG 0
#define HEVC_PAYLOAD_EXTENSION_PRESENT_VAL 0 	//reserved_payload_extension_data shall not be present in bitstreams conforming to this version of T-REC-H.265-201410

#define HEVC_AU_CPB_REMOVAL_DELAY_LENGTH
// AVC/H264 HEADER KNOWN VALUE DEFINES

// VALUES COMMON TO BOTH AVC and HEVC
#define HEVC_AVC_VUI_HRD_PARAMETERS_PRESENT_FLAG_VAL		1
#define HEVC_AVC_NAL_HRD_PARAMETERS_PRESENT_FLAG_VAL		HEVC_AVC_VUI_HRD_PARAMETERS_PRESENT_FLAG_VAL
#define HEVC_AVC_INITIAL_CPB_REMOVAL_DELAY_LENGTH			23	// 23 in H264 Onyx
#define HEVC_AVC_INITIAL_CPB_REMOVAL_OFFSET_LENGTH			HEVC_AVC_INITIAL_CPB_REMOVAL_DELAY_LENGTH
//#define HEVC_AVC_INITIAL_ALT_CPB_REMOVAL_DELAY_LENGTH		HEVC_AVC_INITIAL_CPB_REMOVAL_DELAY_LENGTH
//#define HEVC_AVC_INITIAL_ALT_CPB_REMOVAL_OFFSET_LENGTH	HEVC_AVC_INITIAL_CPB_REMOVAL_DELAY_LENGTH
#define HEVC_AVC_VCL_INITIAL_CPB_REMOVAL_DELAY_LENGTH		HEVC_AVC_INITIAL_CPB_REMOVAL_DELAY_LENGTH
#define HEVC_AVC_VCL_INITIAL_CPB_REMOVAL_OFFSET_LENGTH		HEVC_AVC_INITIAL_CPB_REMOVAL_DELAY_LENGTH
#define HEVC_AVC_CPB_REMOVAL_DELAY_LENGTH					HEVC_AVC_INITIAL_CPB_REMOVAL_DELAY_LENGTH
#define HEVC_AVC_DPB_OUTPUT_DELAY_LENGTH					7	// 7 in H264 Onyx
#define HEVC_AVC_AU_CPB_REMOVAL_DELAY_MINUS1_LENGTH			HEVC_AVC_INITIAL_CPB_REMOVAL_DELAY_LENGTH
#define HEVC_AVC_PIC_DPB_OUTPUT_DELAY_LENGTH				HEVC_AVC_DPB_OUTPUT_DELAY_LENGTH
#define HEVC_AVC_AU_CPB_REMOVAL_DELAY_LENGTH				23	// 23 in H264 Onyx
#define HEVC_AVC_DPB_OUTPUT_DELAY_DU_LENGTH					HEVC_AVC_DPB_OUTPUT_DELAY_LENGTH
#define HEVC_AVC_PIC_DPB_OUTPUT_DU_DELAY_LENGTH				HEVC_AVC_DPB_OUTPUT_DELAY_LENGTH
#define HEVC_AVC_CPB_CNT									1

#define GOP_DEFINITION_UNIFIED_INTERFACE	0

#define MAX_NUM_USER_DEFINED_REGIONS_OF_INTEREST 8
#define MAX_NUM_TILE_COLS 20
#define MAX_NUM_TILE_ROWS 22
#define MAX_FORCE_TILE_COL_VALS (MAX_NUM_TILE_COLS)


#define MAX_ENCODES_QUEUED_PER_CONTEXT 12

// Print errors in a way we see them
void VXE_ERROR(char *fmt, ...);

// Print warnings in a way we see them
void VXE_WARNING(char *fmt, ...);

// Common standard output routine
void VXE_OUTPUT(char *fmt, ...);

// Debug output routine (for output that we will eventually want to strip out or deactivate)
void VXE_DEBUG(char *fmt, ...);


#endif // _VXE_ENC_GLOBALDEFS_H_
