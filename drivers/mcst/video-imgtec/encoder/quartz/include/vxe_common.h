/*!
 *****************************************************************************
 *
 * @File       vxe_common.h
 * @Title      VXE common definitions
 * @Description    VXE common definitions
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

#ifndef _VXECOMMON_H_
#define _VXECOMMON_H_

#include "img_types.h"
#include "img_defs.h"
#include "coreflags.h"
#include "VXE_Enc_GlobalDefs.h"

/* Pragma warning */
#define PRINT_DEF(x) #x
#define CONCAT(x) PRINT_DEF(x)
// Use this as #pragma message(__LOC__":WARNING: something) to display a clickable custom warning
#define __LOC__ __FILE__ "(" CONCAT(__LINE__) ")"

#if ! defined (__llvm__) && ! defined (__clang__)
#if defined (WIN32)
#define CUSTOM_WARNING(msg) __pragma(message(__LOC__ ":WARNING: " msg))
#else
#define DO_CUSTOM_WARNING(x) _Pragma (#x)
#define CUSTOM_WARNING(msg) DO_CUSTOM_WARNING(message(__LOC__ ":WARNING: " msg))
#endif /* defined (WIN32) */
#else
/* Clang does not want us to use our own pragmas, so we have this to keep them with other compiler */
#define CUSTOM_WARNING(msg)
#endif /* ! defined (__llvm__) && ! defined (__clang__) */


#define VXE_ALIGN_2(X)  (((X)+1) &~1)
#define VXE_ALIGN_16(X)  (((X)+15) &~15)
#define VXE_ALIGN_32(X)  (((X)+31) &~31)
#define VXE_ALIGN_64(X)  (((X)+63) &~63)
#define VXE_ALIGN_128(X)  (((X)+127) &~127)
#define VXE_ALIGN_1024(X)  (((X)+1023) &~1023)

#define VXE_ALIGN(v,align) (((v) + (align-1)) &~(align-1))

#define VXE_MIN_BUF_ALIGNMENT	64

#define MAX_POSSIBLE_REFERENCE_FRAMES	2
#define QUARTZ_MAX_PIPES				4
#define MAX_CODED_LISTS_PER_ENCODE QUARTZ_MAX_PIPES

/*!
*****************************************************************************
*
* @details    Used to indentify the plane index  that the luma/chroma component will be stored in
*
* @brief      Enum referencing source plane types
*
****************************************************************************/
typedef enum _VXE_PLANE_INDEX_
{
	DIAGNOSTIC_PLANE_INDEX = 0,
	LUMA_PLANE_INDEX = 0,				//!< Used to index the luma plane in most formats
	Y_PLANE_INDEX = 0,					//!< Used to index the luma plane in YUV formats
	SINGLE_PLANE_INDEX = 0,				//!< Used to index single plane formats
	CHROMA_PLANE_INDEX = 1,				//!< Used to index the beginning of the chroma plane in most formats
	U_PLANE_INDEX = 1,					//!< Used to index the U chroma plane in planer formats
	UV_PLANE_INDEX = 1,					//!< Used to index an interleaved UV chroma plane
	VU_PLANE_INDEX = 1,					//!< Used to index an interleaved VU chroma plane
	V_PLANE_INDEX = 2,					//!< Used to index the V chroma plane in planar formats
	MAX_PLANE_INDEX
} VXE_PLANE_INDEX;

/*!
*****************************************************************************
*
* @details    Enum describing encoding standard (codec)
*
* @brief      Encoding standard
*
****************************************************************************/
typedef enum _VXE_CODEC_
{
	VXE_CODEC_NONE = 0,	//!< There is no codec selected
	VXE_CODEC_H264 = 1,		//!< Encode using the AVC (Advanced Video Coding) H264 standard
	VXE_CODEC_AVC = 1,		//!< Encode using the AVC (Advanced Video Coding) H264 standard
	VXE_CODEC_H265 = 2,		//!< Encode using the HEVC (High Efficiency Coding) H265 standard
	VXE_CODEC_HEVC = 2,		//!< Encode using the HEVC (High Efficiency Coding) H265 standard
	VXE_CODEC_COUNT,	//!< Total number of supported codec, should be last element
} VXE_CODEC;

/*!
*****************************************************************************
*
* @details    Enum describing encoded frame types
*
* @brief      Frame Encoding Type
*
****************************************************************************/
typedef enum _VXE_FRAME_TYPE_
{
	VXE_FRAME_TYPE_IDR,			//!< IDR frame type
	VXE_FRAME_TYPE_I,			//!< I frame type
	VXE_FRAME_TYPE_P,			//!< P frame type
	VXE_FRAME_TYPE_B,			//!< B frame type
	VXE_FRAME_TYPE_AUTO			//!< Automatic selection of frame type
} VXE_FRAME_TYPE;

/*!
*****************************************************************************
*
* @details    Enum describing encoder rate control modes
*
* @brief      Rate Control Mode
*
****************************************************************************/
typedef enum _VXE_RC_MODE_
{
	VXE_RC_MODE_UNSPECIFIED = 0,//!< No rate control mode selected
	VXE_RC_MODE_FIXED_QP,		//!< Fixed Qp Mode (ie no rate control)
	VXE_RC_MODE_SRC,			//!< Simple Mode
	VXE_RC_MODE_CBR,			//!< Constant Bitrate Mode
	VXE_RC_MODE_VBR,			//!< Variable Bitrate Mode
	VXE_RC_MODE_VCM,			//!< Video Conference Mode
	VXE_RC_MODE_SVBR,			//!< Streaming VBR Mode (also known as Peak Constrained VBR Mode)
	VXE_RC_MODE_CFS,			//!< Constant Frame Size Mode
} VXE_RC_MODE;

/*!
*****************************************************************************
*
* @details    Enumerated type used to provide hint to rate control about what type of GOP is being used
*
* @brief      GOP Rate Control Type 
*
****************************************************************************/
typedef enum _VXE_RC_GOP_TYPE_
{
	VXE_RC_GOP_TYPE_UNKNOWN = 0,		//!< GOP is of unknown type
	VXE_RC_GOP_TYPE_LOWDELAY = 1,		//!< GOP matches the parameters of the Low Delay predefined GOPs
	VXE_RC_GOP_TYPE_RANDOMACCESS = 2,	//!< GOP matches the parameters of the Random Access predefined GOP
	VXE_RC_GOP_TYPE_OTHER_SUPPORTED		//!< GOP should be handled as a generic supported GOP
} VXE_RC_GOP_TYPE;

/*!
*****************************************************************************
*
* @details    Contains information relating to and accumulated for the current coded message since the last one (regardless of whether coded messages are sent back on a node-full, slice or tile complete granularity)
*
* @brief      Structure describing coded header data returned by the firmware.
*
****************************************************************************/
typedef struct _FW_CODED_DATA_HDR_
{
	IMG_UINT8	eCBReturnType;				//!< This needs to actually be defines rather than enums due to data packing issues (enum will take 1 more byte)
	
	IMG_BOOL8	ui8StuffingBytes;			//!< Stuffing bytes after coded buffer data
	IMG_UINT16	ui16TilesInThisHeader;		//!< How many tiles in this coded buffer
	IMG_UINT32	ui32SliceCnt;				//!< How many slices in this coded buffer

	IMG_UINT32	ui32NumListNodesFilled;

	IMG_UINT32	ui32CBBytesWritten;			//!< Bytes in this coded buffer excluding this header


	///////////////// We may want to remove the following four fields (present for validation only)
	IMG_UINT32	ui32CTUStartColIdx;
	IMG_UINT32	ui32CTUCurColIdx;

	IMG_UINT32	ui32CTUStartRowIdx;
	IMG_UINT32	ui32CTUCurRowIdx;
	//////////////////////////////////////////////////////////////////

	IMG_UINT32	ui32_Intra_BlockCnt;		//!< Number of 8x8 blocks coded as Intra (excluding IPCM blocks)
	IMG_UINT32	ui32_IPCM_BlockCnt;			//!< Number of 8x8 blocks coded as PCM mode Intra

	IMG_UINT32	ui32_Inter_BlockCnt;		//!< Number of 8x8 blocks coded as Inter

	// Note: The following info can be used to determine the number of P or B coded blocks
	IMG_UINT32	ui32_Inter_Ref0_BlockCnt;	//!< Number of 8x8 Inter blocks using Reference Picture 0
	IMG_UINT32	ui32_Inter_Ref1_BlockCnt;	//!< Number of 8x8 Inter blocks using Reference Picture 1

	IMG_UINT32	ui32_Skip_BlockCnt;			//!< Number of 8x8 blocks marked as skipped Inter

	// Inter/Inra SADT values
	IMG_UINT32 ui32_Pred_Dist_Intra;		//!< Sum of the Intra mode transformed error in prediction for all Intra blocks (exluding Intra PCM, else add0)
	IMG_UINT32 ui32_Pred_Dist_Inter;		//!< Sum of the Intra mode transformed error in prediction for all Intra blocks (exluding Intra PCM, else add0)

	IMG_UINT32	ui32_QpyIntra;		//!< Sum of QPy/Qscale for all Intra-MBs since last coded output (ie. in this slice, node or tile - depending upon cB output mode)
	IMG_UINT32	ui32_QpyInter;		//!< Sum of QPy/Qscale for all Inter-MBs since last coded output (ie. in this slice, node or tile - depending upon cB output mode)

	IMG_UINT32	ui32QuantGroupCount;		//!< Number of Quantization Groups encoded by VCM HW

	IMG_BOOL	bBufferCorrupted;			//!< Signals that this buffer has been corrupted (eg. linked list overflow) - the contents of the buffer should not be used.

	VXE_FRAME_TYPE 	eCBFrameType;				//!< Stores the frame type that generated the coded buffer

	IMG_UINT32 ui32ReservedForInternalUse;
} FW_CODED_DATA_HDR;

/*!
*****************************************************************************
*
* @details    Enum describing (adaptive) intra refresh mode
*
* @brief      Use cases
*
****************************************************************************/
typedef enum _VXE_INTRA_REFRESH_MODE_
{
	INTRA_REFRESH_OFF = 0,				//!< Switch Intra Refresh Off
	INTRA_REFRESH_CYCLIC,				//!< Cyclic Intra Refresh (refresh N CTUs CTUs each frame, advancing postion by N each frame and wrapping around rows until the final row has been refreshed and the CTU refresh postion is reset to the top left position)
	INTRA_REFRESH_CYCLIC_COLUMN,		//!< Cyclic Column Intra Refresh (refresh N columns of CTUs each frame, advancing position by N each frame, cycling the column left to right)
} VXE_INTRA_REFRESH_MODE;

/*!
* @enum _IMG_RC_VCM_MODE_
* @brief Video Conferencing Mode (VCM) rate control method's sub modes
*/
typedef enum _IMG_RC_VCM_MODE_
{
	IMG_RC_VCM_MODE_DEFAULT = 0,
	IMG_RC_VCM_MODE_CFS_NONIFRAMES,
	IMG_RC_VCM_MODE_CFS_ALLFRAMES,
} IMG_RC_VCM_MODE;


// Header definitions used in both low level and Helper API (vxe_api_internal_headers_h265.c and vxe_api_helper_profiles.c)
// H265 Extended profile definitions:
// Profile for which the bitstream indicates conformance - uncomment definitions when/if they are implemented
#define H265_TABLE_A2_IDX_GENERAL_MAX_12BIT_CONSTRAINT_FLAG			0
#define H265_TABLE_A2_IDX_GENERAL_MAX_10BIT_CONSTRAINT_FLAG			1
#define H265_TABLE_A2_IDX_GENERAL_MAX_8BIT_CONSTRAINT_FLAG			2
#define H265_TABLE_A2_IDX_GENERAL_MAX_422CHROMA_CONSTRAINT_FLAG		3
#define H265_TABLE_A2_IDX_GENERAL_MAX_420CHROMA_CONSTRAINT_FLAG		4
#define H265_TABLE_A2_IDX_GENERAL_MAX_MONOCHROME_CONSTRAINT_FLAG	5
#define H265_TABLE_A2_IDX_GENERAL_INTRA_CONSTRAINT_FLAG				6
#define H265_TABLE_A2_IDX_GENERAL_ONE_PICTURE_ONLY_CONSTRAINT_FLAG	7
#define H265_TABLE_A2_IDX_GENERAL_LOWER_BIT_RATE_CONSTRAINT_FLAG	8

// Header definitions used in both low level and Helper API  (vxe_api_internal_headers_h265.c and vxe_api_helper_profiles.c)
// NOTE: We could turn the following into single ui8 bitfields if we're not using (or otherwise handling) the 'either 0 or 1' extension descriptors
// The following 2 don't natively use the extensions, but we're defining them to enable a common interface:
#define H265_TABLE_A2_MAIN						"111110001"
#define H265_TABLE_A2_MAIN_10					"110110001"
// The following are real extension profiles:
//#ifdef SUPPORT_12BIT - This profile can still be used without 12 bit encoding, so don't disallow it
#define H265_TABLE_A2_MAIN_12					"100110001"
//#endif
#define H265_TABLE_A2_MAIN_422_10				"110100001"
//#ifdef SUPPORT_12BIT - This profile can still be used without 12 bit encoding, so don't disallow it
#define H265_TABLE_A2_MAIN_422_12				"100100001"
//#endif
//#ifdef SUPPORT_444 - This profile can be used without 444 encoding, so don't disallow it
#define H265_TABLE_A2_MAIN_444					"111000001"
#define H265_TABLE_A2_MAIN_444_10				"110000001"
//#ifdef SUPPORT_12BIT - This profile can still be used without 12 bit encoding, so don't disallow it
#define H265_TABLE_A2_MAIN_444_12				"100000001"
//#endif
//#endif
#ifdef SUPPORT_MAIN_INTRA
#define H265_TABLE_A2_MAIN_INTRA				"11111010-" //- = either 0 or 1
#define H265_TABLE_A2_MAIN_10_INTRA				"11011010-" //- = either 0 or 1
#define H265_TABLE_A2_MAIN_422_10_INTRA			"11010010-" //- = either 0 or 1
#endif
#define H265_TABLE_A2_UNSUPPORTED				"--------"

/*
* When requesting the hardware caps, the caller may not know about the device
* connection id and needs the API to find the correct device, this will happen when:
* - the context has not openned a stream connection to the kernel module
* - function is called outside of the API
*/
#define VXE_API_UNKNOWN_CONNECTION_ID (0xbaadf00d)

/**
* \defgroup vxe_dim_limits VXE API limits for dimensions
* \details
* VXE drivers imposes its own limit on dimensions in order
* to classify use cases. They might not follow completely
* what the standard(s) dictate so they are held by these
* specific defines.
* @{
*/
#define VXE_LIMIT_WIDTH_4K		(3040) /*!< How wide the output needs to be in order to classify as >= 4K */
#define VXE_LIMIT_HEIGTH_4K		(2048) /*!< How high the output needs to be in order to classify as >= 4K (2160 would be an expected value here) */
/** @}*/


/*
* Defines relating to the limits of linked list coded buffer mode
*/

#define MASK_LINKEDLISTINFO_NUMNODESPERLIST 0xFFFFF000
#define SHIFT_LINKEDLISTINFO_NUMNODESPERLIST 12
#define MASK_LINKEDLISTINFO_LLISTNODESIZEDIV1024 0x00000FFF
#define SHIFT_LINKEDLISTINFO_LLISTNODESIZEDIV1024 0


#define MAX_NUM_LINKED_LIST_NODES_LOW_LATENCY	0x20		// (Based on the maximum FW -> API FIFO size - Low latency returns messages for every full list node during encode so we don't want the FIFO overflowing and requiring flushing (which would create irregularly timed buffer return messages) within a frame.
#define MAX_NUM_LINKED_LIST_NODES_NORMAL		0x3FFFF		// (Based on LINK_LIST_BUF_COUNT field (17:0 = 18 bits) (note: this is CBs in list * partitions per CB)
#define MAX_LIST_LIST_BUFFER_SIZE_DIV1024		0x3FF		// (Based on LINK_LIST_BUFFER_SIZE field in VLC_STRBUFMAN_CONTROL (19:10 = 10 bits = 0x3FF)

#if (0xFFFFF > (MAX_LIST_LIST_BUFFER_SIZE_DIV1024 * 1024))
#define MAX_LINK_LIST_BUFFER_SIZE				(MAX_LIST_LIST_BUFFER_SIZE_DIV1024 * 1024)	// (Based on LINK_LIST_BUFFER_SIZE field = 10 bits * 1024 = 0x3FF * 0x400) 
#else
#define MAX_LINK_LIST_BUFFER_SIZE				0xFFFFF		// (Based on LAST_MEM_COUNT (19:0 = 20 bits) - however, actual amount is limited by the LINK_LIST_BUFFER_SIZE field max in VLC_STRBUFMAN_CONTROL (see below)
#endif

#define MAX_NON_LINK_LIST_BUFFER_SIZE			0xFFFFFFFF	// (32 bits?)



/*!
*****************************************************************************

 @details    Enum describing buffer lock status

 @brief          Buffer lock status

****************************************************************************/
typedef enum _LOCK_STATUS_
{
	BUFFER_FREE	= 1,  //!< Buffer is not locked
	HW_LOCK,          //!< Buffer is locked by hardware
	SW_LOCK,          //!< Buffer is locked by software
	NOTDEVICEMEMORY,  //!< Buffer is not a device memory buffer
} LOCK_STATUS;



typedef struct _VXE_SLICE_MAP_
{
	IMG_UINT32 ui32SliceMapSize;
	IMG_UINT8 aui8SliceMap[MAX_SLICEMAP_SIZE];

#if (VXE_ALIGN(MAX_SLICEMAP_SIZE, 4) - MAX_SLICEMAP_SIZE)
	IMG_BYTE	aPad[VXE_ALIGN(MAX_SLICEMAP_SIZE, 4) - MAX_SLICEMAP_SIZE];
#endif

} VXE_SLICE_MAP;


/*!
*****************************************************************************
*
* @details
*
* @brief      Enum describing the bit depth of a source format
*
****************************************************************************/
typedef enum _IMG_VXE_BITDEPTH_
{
	BD_8BITS = 8,			//!< 8 bits
	BD_VARIABLE = 9,		//!< Variable bit depth
	BD_10BITS = 10,			//!< 10 bits packed together (3 entries per UINT32 with the final two bits disgarded)
	BD_10MSBITS = 16,		//!< 10 bits stored in the most significant bits
	BD_10LSBITS,			//!< 10 bits stored in the least significant bits
} IMG_VXE_BITDEPTH;

// NOTE: Actual calculation based upon this structure is:
//			Widthbytes = (SrcWidth + (ui8HDiv - 1))/ui8HDiv) * (ui8HMult)
//			Heightbytes = (SrcHeight + (ui8VDiv - 1)/ui8VDiv)
// We could simplify this by calculating chroma stride first and then basing luma stride on this value and assumptions (reducing calculations and required lookup values for luma) - but keeping this method as it is more future-proof
/*!
*****************************************************************************
*
* @details		Structure containing information relating to a given format (subsampling and 10 bit) to be used in calculating width and height size requirements. Used in conjunction with the source format lookup table.
*
* @brief		Components used to calculate buffer sizes based upon format attributes.
*
****************************************************************************/
typedef struct _IMG_VXPLAINSURFCALC_
{
	IMG_UINT8 ui8VDiv;
	IMG_UINT8 ui8HDiv;
	IMG_UINT8 ui8HMult;
} IMG_VX_PLAINSURFCALC;


/*!
*****************************************************************************
*
* @details    Enum containing the different image component resolution types, each representing a different sampling of luma and chroma data.
*
* @brief      Image component resolution enum
*
****************************************************************************/
typedef enum _IMG_VXE_RES_
{
	RES_UNDEFINED = 0,
	RES_SRC = 0,				//!< Use the same encode resolution as defined in the source frame format
	RES_400 = 400,				//!< Single plane, luma only
	RES_420 = 420,				//!< The two chroma components are sampled at a quarter the sample rate of the luma: the horizontal and vertical chroma encode resolution is halved
	RES_422 = 422,				//!< The two chroma components are sampled at half the sample rate of the luma: the horizontal chroma encode resolution is halved
	RES_444 = 444				//!< Luma and chroma encode resolutions are the same, no chroma subsampling
} IMG_VXE_RES;

/*!
*****************************************************************************
*
* @details	  Structure used in the source format lookup table to describe the properties of a given source format
*
* @brief      Source format information
*
****************************************************************************/
typedef struct _SOURCEFORMATLOOKUP_ {
	// NOTE: Formats with separate U and V planes (ui8NSrcPlanes == 3) will have unique U and V pointers to those planes
	// sent to registers so will not require the colour planes to be swapped in HW (ui8Seq_IFSF_RegVal).
	// eg. ui8Seq_IFSF_RegVal should be the same (0x20) for both YUV and YVU.
	IMG_UINT8				ui8Seq_IFSF_RegVal;					//!< Register value 
	IMG_UINT8				ui8NSrcPlanes;						//!< Number of source planes used by this format
	IMG_VXE_BITDEPTH		eBitDepth;							//!< Bit depth of this format
	IMG_VXE_RES				eResolution;						//!< (Chroma) resolution of this format
	IMG_VX_PLAINSURFCALC	sPlaneCalc[CHROMA_PLANE_INDEX + 1];	//!< Used to calculate plane memory width/stride in bytes
	IMG_UINT8				ui8IsUVOrder;						//!< Specify whether the chroma is in UV or VU order
	IMG_UINT8				ui8LumaLineAlignment;				//!< Alignment value of each luma line (eg. 444 = 64, 420 and 422 = 128)
	IMG_CHAR				*pcFmtName;							//!< Format name
	IMG_CHAR				*pcFmtDesc;							//!< Format description
} IMG_VXE_SOURCEFORMATLOOKUP;


// LOOKUP_ table entries of type SOURCEFORMATLOOKUP
// NOTE: Formats with separate U and V planes (ui8NSrcPlanes == 3) will have unique U and V pointers to those planes sent to registers so will not require the colour planes to be swapped in HW (colour interleaved formats will still need to use this).
// eg. ui8Seq_IFSF_RegVal should be the same (0x20) for both YUV and YVU.
#define LOOKUP_420PL111YCbCr8		{ 0x20, 3, BD_8BITS, RES_420, { { 1, 1, 1 }, { 2, 2, 1 } }, 1, 128,	"420PL111YCbCr8", "4 : 2 : 0, Y Cb Cr in 3 separate planes, 8 - bit components" }
#define LOOKUP_420PL111YCrCb8		{ 0x20, 3, BD_8BITS, RES_420, { { 1, 1, 1 }, { 2, 2, 1 } }, 0, 128, "420PL111YCrCb8", "4 : 2 : 0, Y Cr Cb in 3 separate planes, 8 - bit components" }
#define LOOKUP_422PL111YCbCr8		{ 0x40, 3, BD_8BITS, RES_422, { { 1, 1, 1 }, { 1, 2, 1 } }, 1, 128, "422PL111YCbCr8", "4 : 2 : 2, Y Cb Cr in 3 separate planes, 8 - bit components" }
#define LOOKUP_422PL111YCrCb8		{ 0x40, 3, BD_8BITS, RES_422, { { 1, 1, 1 }, { 1, 2, 1 } }, 0, 128, "422PL111YCrCb8", "4 : 2 : 2, Y Cr Cb in 3 separate planes, 8 - bit components" }
#define LOOKUP_444PL111YCbCr8		{ 0x60, 3, BD_8BITS, RES_444, { { 1, 1, 1 }, { 1, 1, 1 } }, 1, 64, "444PL111YCbCr8", "4 : 4 : 4, Y Cb Cr in 3 separate planes, 8 - bit components(could also be ABC, but colour space conversion is not supported by input scaler)" }
#define LOOKUP_444PL111YCrCb8		{ 0x60, 3, BD_8BITS, RES_444, { { 1, 1, 1 }, { 1, 1, 1 } }, 0, 64, "444PL111YCrCb8", "4 : 4 : 4, Y Cr Cb in 3 separate planes, 8 - bit components(could also be ABC, but colour space conversion is not supported by input scaler)" }

// 8-bit chroma byte-interleaved formats
#define LOOKUP_420PL12YCbCr8		{ 0x28, 2, BD_8BITS, RES_420, { { 1, 1, 1 }, { 2, 2, 2 } }, 1, 64, "420PL12YCbCr8", "4 : 2 : 0, Y in 1 plane, CbCr interleaved in 2nd plane, 8 - bit components" }
#define LOOKUP_420PL12YCrCb8		{ 0x2A, 2, BD_8BITS, RES_420, { { 1, 1, 1 }, { 2, 2, 2 } }, 0, 64, "420PL12YCrCb8", "4 : 2 : 0, Y in 1 plane, CrCb interleaved in 2nd plane, 8 - bit components" }
#define LOOKUP_422PL12YCbCr8		{ 0x48, 2, BD_8BITS, RES_422, { { 1, 1, 1 }, { 1, 2, 2 } }, 1, 64, "422PL12YCbCr8", "4 : 2 : 2, Y in 1 plane, CbCr interleaved in 2nd plane, 8 - bit components" }
#define LOOKUP_422PL12YCrCb8		{ 0x4A, 2, BD_8BITS, RES_422, { { 1, 1, 1 }, { 1, 2, 2 } }, 0, 64, "422PL12YCrCb8", "4 : 2 : 2, Y in 1 plane, CrCb interleaved in 2nd plane, 8 - bit components" }
#define LOOKUP_444PL12YCbCr8		{ 0x68, 2, BD_8BITS, RES_444, { { 1, 1, 1 }, { 1, 1, 2 } }, 1, 64, "444PL12YCbCr8", "4 : 4 : 4, Y in 1 plane, CbCr interleaved in 2nd plane, 8 - bit components" }
#define LOOKUP_444PL12YCrCb8		{ 0x6A, 2, BD_8BITS, RES_444, { { 1, 1, 1 }, { 1, 1, 2 } }, 0, 64, "444PL12YCrCb8", "4 : 4 : 4, Y in 1 plane, CrCb interleaved in 2nd plane, 8 - bit components" }

// 8-bit Single plane interleaved
#define LOOKUP_422IL3YCbYCr8		{ 0x50, 1, BD_8BITS, RES_422, { { 1, 1, 2 }, { 1, 1, 2 } }, 1, 64, "422IL3YCbYCr8", "4 : 2 : 2, YCbYCr interleaved in a single plane, 8 - bit components" }
#define LOOKUP_422IL3YCrYCb8		{ 0x52, 1, BD_8BITS, RES_422, { { 1, 1, 2 }, { 1, 1, 2 } }, 0, 64, "422IL3YCrYCb8", "4 : 2 : 2, YCrYCb interleaved in a single plane, 8 - bit components" }
#define LOOKUP_422IL3CbYCrY8		{ 0x54, 1, BD_8BITS, RES_422, { { 1, 1, 2 }, { 1, 1, 2 } }, 1, 64, "422IL3CbYCrY8", "4 : 2 : 2, CbYCrY interleaved in a single plane, 8 - bit components" }
#define LOOKUP_422IL3CrYCbY8		{ 0x56, 1, BD_8BITS, RES_422, { { 1, 1, 2 }, { 1, 1, 2 } }, 0, 64, "422IL3CrYCbY8", "4 : 2 : 2, CrYCbY interleaved in a single plane, 8 - bit components" }

#define LOOKUP_444IL4ABCX8			{ 0x7C, 1, BD_8BITS, RES_444, { { 1, 1, 4 }, { 1, 1, 4 } }, 1, 64, "444IL4ABCX8", "4 : 4 : 4, Any 3 colour space components plus reserved byte(e.g.RGB), 8 - bit components, packed 32 - bit per pixel in a single plane, 8 MSBits not used" }
#define LOOKUP_444IL4XBCA8			{ 0x7E, 1, BD_8BITS, RES_444, { { 1, 1, 4 }, { 1, 1, 4 } }, 0, 64, "444IL4XBCA8", "4 : 4 : 4, Any 3 colour space components plus reserved byte(e.g.RGB), 8 - bit components, packed 32 - bit" }

// 10 bit packed planar formats
#define LOOKUP_420PL111YCbCr10		{ 0x21, 3, BD_10BITS, RES_420, { { 1, 3, 4 }, { 2, 6, 4 } }, 1, 128, "420PL111YCbCr10", "4 : 2 : 0, Y Cb Cr in 3 separate planes, 10 - bit components" }
#define LOOKUP_420PL111YCrCb10		{ 0x21, 3, BD_10BITS, RES_420, { { 1, 3, 4 }, { 2, 6, 4 } }, 0, 128, "420PL111YCrCb10", "4 : 2 : 0, Y Cr Cb in 3 separate planes, 10 - bit components" }
#define LOOKUP_422PL111YCbCr10		{ 0x41, 3, BD_10BITS, RES_422, { { 1, 3, 4 }, { 1, 6, 4 } }, 1, 128, "422PL111YCbCr10", "4 : 2 : 2, Y Cb Cr in 3 separate planes, 10 - bit components" }
#define LOOKUP_422PL111YCrCb10		{ 0x41, 3, BD_10BITS, RES_422, { { 1, 3, 4 }, { 1, 6, 4 } }, 0, 128, "422PL111YCrCb10", "4 : 2 : 2, Y Cr Cb in 3 separate planes, 10 - bit components" }
#define LOOKUP_444PL111YCbCr10		{ 0x61, 3, BD_10BITS, RES_444, { { 1, 3, 4 }, { 1, 3, 4 } }, 1, 64, "444PL111YCbCr10", "4 : 4 : 4, Y Cb Cr in 3 separate planes, 10 - bit components(could also be ABC, but colour space conversion is not supported by input scaler)" }
#define LOOKUP_444PL111YCrCb10		{ 0x61, 3, BD_10BITS, RES_444, { { 1, 3, 4 }, { 1, 3, 4 } }, 0, 64, "444PL111YCrCb10", "4 : 4 : 4, Y Cr Cb in 3 separate planes, 10 - bit components(could also be ABC, but colour space conversion is not supported by input scaler)" }

// 10 bit packed chroma byte-interleaved formats
#define LOOKUP_420PL12YCbCr10		{ 0x29, 2, BD_10BITS, RES_420, { { 1, 3, 4 }, { 2, 6, 8 } }, 1, 64, "420PL12YCbCr10", "4 : 2 : 0, Y in 1 plane, CbCr interleaved in 2nd plane, 10 - bit components" }
#define LOOKUP_420PL12YCrCb10		{ 0x2B, 2, BD_10BITS, RES_420, { { 1, 3, 4 }, { 2, 6, 8 } }, 0, 64, "420PL12YCrCb10", "4 : 2 : 0, Y in 1 plane, CrCb interleaved in 2nd plane, 10 - bit components" }
#define LOOKUP_422PL12YCbCr10		{ 0x49, 2, BD_10BITS, RES_422, { { 1, 3, 4 }, { 1, 6, 8 } }, 1, 64, "422PL12YCbCr10", "4 : 2 : 2, Y in 1 plane, CbCr interleaved in 2nd plane, 10 - bit components" }
#define LOOKUP_422PL12YCrCb10		{ 0x4B, 2, BD_10BITS, RES_422, { { 1, 3, 4 }, { 1, 6, 8 } }, 0, 64, "422PL12YCrCb10", "4 : 2 : 2, Y in 1 plane, CrCb interleaved in 2nd plane, 10 - bit components" }
#define LOOKUP_444PL12YCbCr10		{ 0x69, 2, BD_10BITS, RES_444, { { 1, 3, 4 }, { 1, 3, 8 } }, 1, 64, "444PL12YCbCr10", "4 : 4 : 4, Y in 1 plane, CbCr interleaved in 2nd plane, 10 - bit components" }
#define LOOKUP_444PL12YCrCb10		{ 0x6B, 2, BD_10BITS, RES_444, { { 1, 3, 4 }, { 1, 3, 8 } }, 0, 64, "444PL12YCrCb10", "4 : 4 : 4, Y in 1 plane, CrCb interleaved in 2nd plane, 10 - bit components" }

// 10-bit packed Single plane interleaved
#define LOOKUP_444IL3ABC10			{ 0x75, 1, BD_10BITS, RES_444, { { 1, 1, 4 }, { 1, 1, 4 } }, 1, 64, "444IL3ABC10", "4 : 4 : 4, Any 3 colour space components(e.g.RGB), 10 - bit components, packed 32 - bit per pixel in a single plane" }

// 16-bit (MSBits) planar formats
#define LOOKUP_444PL111YCbCr16		{ 0x64, 3, BD_10MSBITS, RES_444, { { 1, 1, 2 }, { 1, 1, 2 } }, 1, 64, "444PL111YCbCr16", "4 : 4 : 4, Y Cb Cr in 3 separate planes, 16 - bit components(could also be ABC, but colour space conversion is not supported by input scaler)" }
#define LOOKUP_444PL111YCrCb16		{ 0x64, 3, BD_10MSBITS, RES_444, { { 1, 1, 2 }, { 1, 1, 2 } }, 0, 64, "444PL111YCrCb16", "4 : 4 : 4, Y Cr Cb in 3 separate planes, 16 - bit components(could also be ABC, but colour space conversion is not supported by input scaler)" }

// 16-bit (MSBits) chroma byte-interleaved formats
#define LOOKUP_420PL12YCbCr16		{ 0x2C, 2, BD_10MSBITS, RES_420, { { 1, 1, 2 }, { 2, 2, 4 } }, 1, 64, "420PL12YCbCr16", "4 : 2 : 0, Y in 1 plane, CbCr interleaved in 2nd plane, 16 - bit components(only 10 MSBits used)" }
#define LOOKUP_420PL12YCrCb16		{ 0x2E, 2, BD_10MSBITS, RES_420, { { 1, 1, 2 }, { 2, 2, 4 } }, 0, 64, "420PL12YCrCb16", "4 : 2 : 0, Y in 1 plane, CrCb interleaved in 2nd plane, 16 - bit components(only 10 MSBits used)" }
#define LOOKUP_422PL12YCbCr16		{ 0x4C, 2, BD_10MSBITS, RES_422, { { 1, 1, 2 }, { 1, 2, 4 } }, 1, 64, "422PL12YCbCr16", "4 : 2 : 2, Y in 1 plane, CbCr interleaved in 2nd plane, 16 - bit components(only 10 MSBits used)" }
#define LOOKUP_422PL12YCrCb16		{ 0x4E, 2, BD_10MSBITS, RES_422, { { 1, 1, 2 }, { 1, 2, 4 } }, 0, 64, "422PL12YCrCb16", "4 : 2 : 2, Y in 1 plane, CrCb interleaved in 2nd plane, 16 - bit components(only 10 MSBits used)" }
#define LOOKUP_444PL12YCbCr16		{ 0x6C, 2, BD_10MSBITS, RES_444, { { 1, 1, 2 }, { 1, 1, 4 } }, 1, 64, "444PL12YCbCr16", "4 : 4 : 4, Y in 1 plane, CbCr interleaved in 2nd plane, 16 - bit components(only 10 MSBits used)" }
#define LOOKUP_444PL12YCrCb16		{ 0x6E, 2, BD_10MSBITS, RES_444, { { 1, 1, 2 }, { 1, 1, 4 } }, 0, 64, "444PL12YCrCb16", "4 : 4 : 4, Y in 1 plane, CrCb interleaved in 2nd plane, 16 - bit components(only 10 MSBits used)" }

// 16-bit (LSBits) planar formats
#define LOOKUP_420PL111YCbCr16L10	{ 0x21, 3, BD_10LSBITS, RES_420, { { 1, 1, 2 }, { 2, 2, 2 } }, 1, 64, "420PL111YCbCrL10", "4 : 2 : 0, Y Cb Cr in 3 separate planes, 16 - bit components(10LSB)" }
#define LOOKUP_420PL111YCrCb16L10	{ 0x21, 3, BD_10LSBITS, RES_420, { { 1, 1, 2 }, { 2, 2, 2 } }, 0, 64, "420PL111YCrCbL10", "4 : 2 : 0, Y Cr Cb in 3 separate planes, 16 - bit components(10LSB)" }
#define LOOKUP_420PL111YCbCr16		{ 0x21, 3, BD_16BITS, RES_420,   { { 1, 1, 2 }, { 2, 2, 2 } }, 1, 64, "420PL111YCbCr16",  "4 : 2 : 0, Y Cb Cr in 3 separate planes, 16 - bit components" }
#define LOOKUP_420PL111YCrCb16		{ 0x21, 3, BD_16BITS, RES_420,   { { 1, 1, 2 }, { 2, 2, 2 } }, 0, 64, "420PL111YCrCb16",  "4 : 2 : 0, Y Cr Cb in 3 separate planes, 16 - bit components" }
#define LOOKUP_422PL111YCbCr16L10	{ 0x41, 3, BD_10LSBITS, RES_422, { { 1, 1, 2 }, { 1, 2, 2 } }, 1, 64, "422PL111YCbCrL10", "4 : 2 : 2, Y Cb Cr in 3 separate planes, 16 - bit components(10LSB)" }
#define LOOKUP_422PL111YCrCb16L10	{ 0x41, 3, BD_10LSBITS, RES_422, { { 1, 1, 2 }, { 1, 2, 2 } }, 0, 64, "422PL111YCrCbL10", "4 : 2 : 2, Y Cr Cb in 3 separate planes, 16 - bit components(10LSB)" }
#define LOOKUP_422PL111YCbCr16		{ 0x21, 3, BD_16BITS, RES_422,   { { 1, 1, 2 }, { 2, 2, 2 } }, 1, 64, "422PL111YCbCr16",  "4 : 2 : 2, Y Cb Cr in 3 separate planes, 16 - bit components" }
#define LOOKUP_422PL111YCrCb16		{ 0x21, 3, BD_16BITS, RES_422,   { { 1, 1, 2 }, { 2, 2, 2 } }, 0, 64, "422PL111YCrCb16",  "4 : 2 : 2, Y Cr Cb in 3 separate planes, 16 - bit components" }
#define LOOKUP_444PL111YCbCr16L10	{ 0x65, 3, BD_10LSBITS, RES_444, { { 1, 1, 2 }, { 1, 1, 2 } }, 1, 64, "444PL111YCbCrL10", "4 : 4 : 4, Y Cb Cr in 3 separate planes, 16 - bit components(10LSB) (could also be ABC, but colour space conversion is not supported by input scaler)" }
#define LOOKUP_444PL111YCrCb16L10	{ 0x65, 3, BD_10LSBITS, RES_444, { { 1, 1, 2 }, { 1, 1, 2 } }, 0, 64, "444PL111YCrCbL10", "4 : 4 : 4, Y Cr Cb in 3 separate planes, 16 - bit components(10LSB) (could also be ABC, but colour space conversion is not supported by input scaler)" }

// 16-bit (MSBits) chroma byte-interleaved formats
#define LOOKUP_420PL12YCbCr16L10	{ 0x2D, 2, BD_10LSBITS, RES_420, { { 1, 1, 2 }, { 2, 2, 4 } }, 1, 64, "420PL12YCbCrL10", "4 : 2 : 0, Y in 1 plane, CbCr interleaved in 2nd plane, 16 - bit components(only 10 LSBits used)" }
#define LOOKUP_420PL12YCrCb16L10	{ 0x2F, 2, BD_10LSBITS, RES_420, { { 1, 1, 2 }, { 2, 2, 4 } }, 0, 64, "420PL12YCrCbL10", "4 : 2 : 0, Y in 1 plane, CrCb interleaved in 2nd plane, 16 - bit components(only 10 LSBits used)" }
#define LOOKUP_422PL12YCbCr16L10	{ 0x4D, 2, BD_10LSBITS, RES_422, { { 1, 1, 2 }, { 1, 2, 4 } }, 1, 64, "422PL12YCbCrL10", "4 : 2 : 2, Y in 1 plane, CbCr interleaved in 2nd plane, 16 - bit components(only 10 LSBits used)" }
#define LOOKUP_422PL12YCrCb16L10	{ 0x4F, 2, BD_10LSBITS, RES_422, { { 1, 1, 2 }, { 1, 2, 4 } }, 0, 64, "422PL12YCrCbL10", "4 : 2 : 2, Y in 1 plane, CrCb interleaved in 2nd plane, 16 - bit components(only 10 LSBits used)" }
#define LOOKUP_444PL12YCbCr16L10	{ 0x6D, 2, BD_10LSBITS, RES_444, { { 1, 1, 2 }, { 1, 1, 4 } }, 1, 64, "444PL12YCbCrL10", "4 : 4 : 4, Y in 1 plane, CbCr interleaved in 2nd plane, 16 - bit components(only 10 LSBits used)" }
#define LOOKUP_444PL12YCrCb16L10	{ 0x6F, 2, BD_10LSBITS, RES_444, { { 1, 1, 2 }, { 1, 1, 4 } }, 0, 64, "444PL12YCrCbL10", "4 : 4 : 4, Y in 1 plane, CrCb interleaved in 2nd plane, 16 - bit components(only 10 LSBits used)" }

// Single plane Variable bits
#define LOOKUP_444IL3RGB565			{ 0x70, 1, BD_VARIABLE, RES_444, { { 1, 1, 2 }, { 1, 1, 2 } }, 1, 64, "444IL3RGB565", "RGB with 5 bits for R, 6 bits for G and 5 bits for B" }


/*!
*****************************************************************************
*
* @details    Enum describing the force mode to apply when using any form of CTU Input Control
*
* @brief      Force mode enum
*
****************************************************************************/

typedef enum _VXE_CTU_FORCE_MODE_
{
	CTU_FORCE_MODE_NONE = 0,					//!< Don't force anythnig
	CTU_FORCE_MODE_INTRA = 1,					//!< Force the CTU to Intra
	CTU_FORCE_MODE_SKIP = 2,					//!< Force skip the CTU
	CTU_FORCE_MODE_SKIP_OR_INTRA = 3			//!< Force skip or Intra
} VXE_CTU_FORCE_MODE;


/*!
 *****************************************************************************
 *
 * @details    Struct describing coded buffer usage
 *
 * @brief      Struct describing coded buffer usage
 *
 ****************************************************************************/

typedef struct _VXE_CODEDBUFFER_DATA_
{
	IMG_UINT32 ui32DataStartBytes;			//!< Offset (in bytes) of the data
	IMG_UINT32 ui32DataSizeBytes;			//!< Size (in bytes) of the data
} VXE_CODEDBUFFER_DATA;


/*!
 *****************************************************************************
 *
 * @details    Maximum number of slices per field
 *
 * @brief      Maximum number of slices per field
 *
 ****************************************************************************/
#define MAX_SLICESPERPIC		(128)

/*!
*****************************************************************************
*
* @details
*
* @brief      Bit fields for ui32MmuFlags
*
****************************************************************************/
#define MMU_USE_MMU_FLAG		0x00000001
#define MMU_TILED_FLAG			0x00000002
#define MMU_EXTENDED_ADDR_FLAG	0x00000004
#define MMU_SECURE_FW_UPLOAD	0x00000008
#define MMU_TILED_INTERLEAVED	0x00000010
#define MMU_ALT_TILING			0x00000020

/*!
*****************************************************************************
*
* @details
*
* @brief      Bit fields for virtual memory mappings
*
****************************************************************************/
#define IMG_MAP_HOST_KM         0x00000001
#define IMG_MAP_HOST_UM         0x00000002
#define IMG_MAP_FIRMWARE        0x00000004


typedef IMG_UINT32 VXE_COMMAND_ID;


#endif
