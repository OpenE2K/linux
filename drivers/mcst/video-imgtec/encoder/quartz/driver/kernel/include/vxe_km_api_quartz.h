/*!
 *****************************************************************************
 *
 * @File       vxe_km_api_quartz.h
 * @Title      Exposed kernel module API
 * @Description    Expose kernel module API (these functions will have an ioctl id)
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

#if ! defined (__VXE_KM_API_H__)
#define __VXE_KM_API_H__

#include "vxe_fw_if.h"


#ifdef  __RPCCODEGEN__
#define rpc_prefix      HOSTUTILS
#define rpc_filename    vxe_km_api_quartz
#endif


/***************************************************** DEFINES *************************************************************/
/**
* \defgroup codec_mask Bit-mask of supported codecs
* @{
*/
#define CODEC_MASK_H264		0x0010  /*!< Support for H264 */
#define CODEC_MASK_H265		0x0080  /*!< Support for H265 */
/** @}*/

/**
* \defgroup features_mask Bit-mask of vxe kernel module features
* \details
* Latency-related context features have an impact on the context's 
* pipes allocation. These features are packed in a 32bit word using
* the following macros.
* @{
*/
#define SHIFT_VXEKMAPI_ENCDIM_FEATURE		(0)
#define MASK_VXEKMAPI_ENCDIM_FEATURE		(0x3 << SHIFT_VXEKMAPI_ENCDIM_FEATURE)
#define SHIFT_VXEKMAPI_ENCRES_FEATURE		(2)
#define MASK_VXEKMAPI_ENCRES_FEATURE		(0x3 << SHIFT_VXEKMAPI_ENCRES_FEATURE)
#define SHIFT_VXEKMAPI_FRAMERATE_FEATURE	(4)
#define MASK_VXEKMAPI_FRAMERATE_FEATURE		(0x7 << SHIFT_VXEKMAPI_FRAMERATE_FEATURE)
#define SHIFT_VXEKMAPI_LOWLATENCY_FEATURE	(7)
#define MASK_VXEKMAPI_LOWLATENCY_FEATURE	(0x1 << SHIFT_VXEKMAPI_LOWLATENCY_FEATURE)
#define SHIFT_VXEKMAPI_HWINPUT_FEATURE		(8)
#define MASK_VXEKMAPI_HWINPUT_FEATURE		(0x1 << SHIFT_VXEKMAPI_HWINPUT_FEATURE)
#define SHIFT_VXEKMAPI_COLUMN_STORE_ON		(9)
#define MASK_VXEKMAPI_COLUMN_STORE_ON		(0x1 << SHIFT_VXEKMAPI_COLUMN_STORE_ON)
#define SHIFT_VXEKMAPI_FBC_FEATURE			(10)
#define MASK_VXEKMAPI_FBC_FEATURE			(0x1 << SHIFT_VXEKMAPI_FBC_FEATURE)
#define SHIFT_VXEKMAPI_CORE_ID				(11)
#define MASK_VXEKMAPI_CORE_ID			    (0x7 << SHIFT_VXEKMAPI_CORE_ID)

#define INVALID_CORE_ID                        7
/** @}*/

/**
* \defgroup features_vals VXE kernel module features
* \details
* Any feature with effects on the latency will be assigned
* a value and they will be used by the kernel module to allocate pipes to a context.
* A single pipe is expected to deliver 4K 4:2:0 @ 30 fps, higher requirements imply
* multiple pipes and the following flags will help determining how many are needed
* @{
*/
#define VXEKMAPI_ENCDIM_LESS_THAN_4K	(0x0)   /*!< Output dimensions are smaller than 4096 * 2048 */
#define VXEKMAPI_ENCDIM_4K_TO_8K		(0x1)   /*!< Output dimensions are below 8k */

#define VXEKMAPI_ENCRES420				(0x0)   /*!< Chroma subsampling 4:2:0 */
#define VXEKMAPI_ENCRES422				(0x1)   /*!< Chroma subsampling 4:2:2 */
#define VXEKMAPI_ENCRES444				(0x2)   /*!< Chroma subsampling 4:4:4 */

#define VXEKMAPI_FRAMERATE_0_TO_30		(0x0)   /*!< Frame rate up to 30fps */
#define VXEKMAPI_FRAMERATE_31_TO_60		(0x1)   /*!< Frame rate up to 60fps */
#define VXEKMAPI_FRAMERATE_61_TO_90		(0x2)   /*!< Frame rate up to 90fps */
#define VXEKMAPI_FRAMERATE_91_TO_120	(0x3)   /*!< Frame rate up to 120fps */
/** @}*/

/**
* \def BUILD_VXEKMAPI_FEATURE_FLAG
* User mode will use this macro to build the kernel features' flag.
* It relies on each feature value (see \ref features_vals "Values"),
* and the kernel module will use it internally for comparison.
*/
#define BUILD_VXEKMAPI_FEATURE_FLAG(dim, res, framerate, lowlatency, hwinput, columnstore, fbc) (\
	F_ENCODE(dim, VXEKMAPI_ENCDIM_FEATURE) | \
	F_ENCODE(res, VXEKMAPI_ENCRES_FEATURE) | \
	F_ENCODE(framerate, VXEKMAPI_FRAMERATE_FEATURE) | \
	F_ENCODE(lowlatency, VXEKMAPI_LOWLATENCY_FEATURE) | \
	F_ENCODE(hwinput, VXEKMAPI_HWINPUT_FEATURE) | \
	F_ENCODE(columnstore, VXEKMAPI_COLUMN_STORE_ON) | \
	F_ENCODE(fbc, VXEKMAPI_FBC_FEATURE) \
	)


/**
* \defgroup features_weights VXE kernel module features' weight
* \details
* Any feature with effects on the latency will be assigned a weight.
* This will be used to increment/decrement the pipe's usage.
* @{
*/
#define VXEKMAPI_ENCDIM_FEATURE_WEIGHT			(0x1)       /*!< Encode dimensions is assigned a small weight */
#define VXEKMAPI_ENCRES_FEATURE_WEIGHT			(0x1)       /*!< Encode resolution is assigned a small weight */
#define VXEKMAPI_FRAMERATE_FEATURE_WEIGHT		(0x1)       /*!< Framerate resolution is assigned a small weight */
#define VXEKMAPI_LOWLATENCY_FEATURE_WEIGHT		(0x10)      /*!< Low-latency wants the pipe it is using to be less assigned */
#define VXEKMAPI_HWINPUT_FEATURE_WEIGHT			(0x7ff)     /*!< Hardware input cannot share the pipe, we virtually lock it with a much higher value */

#define VXEKMAPI_MAX_FEATURE_WEIGHT				(0xffff)    /*!< The counter used per pipe is stored in 16bit value */
/** @}*/


/** How many instance are supported at maximum by the kernel */
#define VXE_KM_MAX_DEVICE_SUPPORTED (8)

/**
* Defines which scheduling scenario are supported by our kernel module
*/
typedef enum _VXE_KM_SCHEDULING_MODEL_
{
	e_NO_SCHEDULING_SCENARIO = 0,		/*!< Kernel will try a best-effort sharing */
	e_4K422_60__1080p420_30,			/*!< One context running 4K4:2:2 @ 60fps, coupled with a context encoding 1080p 4:2:0 @ 30fps */
	e_4K422_60__1080p422_30,			/*!< One context running 4K4:2:2 @ 60fps, coupled with a context encoding 1080p 4:2:2 @ 30fps */
	e_SCHEDULING_SCENARII               /*!< Maximum number of scenario, used for checking */
} VXE_KM_SCHEDULING_MODEL;

/*!
*****************************************************************************
*
* @details    Structure containing hardware config registers
*
* @brief      Available Encoder Resources
*
****************************************************************************/
typedef struct _VXE_HW_CONFIG_
{
	IMG_UINT32	ui32CoreId;					//!< Core ID Register
	IMG_UINT32	ui32CoreRev;				//!< Core Revision Register
	IMG_UINT32  ui32CoreConfig;				//!< Core Config Register
	IMG_UINT32  ui32CoreConfig2;			//!< Core Config2 Register
	IMG_UINT32  ui32CoreConfig3;			//!< Core Config3 Register
	IMG_UINT32  ui32ProcConfig;				//!< Proc Config Register
	IMG_UINT32  ui32LineStoreConfig;		//!< Line Store Config Register
	// Clock frequency measurement code
	IMG_UINT32 ui32ClkFreqkHz;				//!< Clock frequency of MTX in kHz
} VXE_HW_CONFIG;

#if defined (SYSBRG_NO_BRIDGING)
extern IMG_CHAR *apszCmd[];

/* In non-bridging builds, we may want to test various combinations and having these backdoors allow us to do so (they would be defined at compile time when building KM modules) */
extern IMG_BOOL g_bKMPPM;
extern IMG_UINT32 g_ui32MMUFlags;
extern IMG_UINT32 g_ui32MMUTileStride;
extern VXE_KM_SCHEDULING_MODEL g_eSchedulingModel;

/* These variable are not exposed in a bridging build */
extern IMG_BOOL g_bFWUseCache;
extern IMG_BOOL g_bFWUseBootloader;
extern IMG_BOOL gbDebugOutputHidden;

/* Provide default values if not given */
#define VXE_KM_DEFAULT_PPM (0)
#define VXE_KM_DEFAULT_MMU_FLAGS (MMU_USE_MMU_FLAG/*0x00000001*/ | MMU_TILED_FLAG/*0x00000002*/ | MMU_EXTENDED_ADDR_FLAG /*0x00000004*/)
#define VXE_KM_DEFAULT_SCHED_MODEL (e_NO_SCHEDULING_SCENARIO)

/* Do we want more verbose in the out2.txt generated for pdump replays? */
#define TALPDUMP_VerboseComment(hBank, pszComment) /*don't overload the out2.txt*/
#endif


/************************************************* PUBLIC FUNCTIONS ********************************************************/

/**
*
* \brief Open the socket used for the KM <=> FW communications (linked to the device context)
* \param [in] aui32DevConnId Device connection identifiers, kernel will only read what it supports
* \param [in] eCodec Codec to be used for this socket
* \param [in] ui32FeaturesFlag Reduced set of features which state impacts latency/pipe allocation
* \param [in] ui8PipesToUse Pipes this context needs to use
* \param [out] pui32CtxtId Numeric context identifier (matches the FWCtxtId - FW_COMMAND_SOCKET_ID)
* \param [out] pui32SockId Unique socket identifier used for further access to the socket object
* \param [out] pui8FirstPipeIdx First pipe kernel allocated for this context
* \param [out] pui8LastPipeIdx Last pipe kernel allocated for this context
* \return
*   - IMG_SUCCESS if the socket has been opened
*   - IMG_ERROR_GENERIC_FAILURE if the connection id parameter is wrong
*   - IMG_ERROR_NOT_INITIALISED if the kernel device context cannot be used
*   - IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE if the device context cannot support more stream opened at the same time
*   - IMG_ERROR_VALUE_OUT_OF_RANGE if the new stream cannot be opened because it cannot fit in internal arrays
*   - IMG_ERROR_MALLOC_FAILED if the dynamic stream object allocation failed
*   - IMG_ERROR_UNEXPECTED_STATE if it was the first opened stream and the firmware could not be loaded
*   - IMG_ERROR_STORAGE_TYPE_FULL if this context cannot get hold on the pipes it requires
*
* \details
* All communications between user mode and hardware is via a socket that must be created and tracked
* After checking that the device context has been previously created, this function will try to open
* a new socket to communicate to the FW. The device context might deny it if the number of socket it
* supports has already been exceeded. If a socket can be created, it then fill the required fields
* and create the proper structure to handle the communication (FIFO, semaphores, ..) and register the
* socket in the device context.
* Afterwards, it performs several operation which initialize the socket object to make it usable:
* - Allow the socket access to the device memory pool containing all allocation
* - Specify the socket inner identifier different from the socket id passed as parameter (mirrors the context id)
*
**/
IMG_RESULT KM_OpenSocket(SYSBRG_POINTER_ARG(IMG_UINT32) aui32DevConnId, VXE_CODEC eCodec, IMG_UINT32 ui32FeaturesFlag, IMG_UINT8 ui8PipesToUse,
	SYSBRG_POINTER_ARG(IMG_UINT8) pui8CtxtId, SYSBRG_POINTER_ARG(IMG_UINT32) pui32SockId, SYSBRG_POINTER_ARG(IMG_UINT8) pui8FirstPipeIdx, SYSBRG_POINTER_ARG(IMG_UINT8) pui8LastPipeIdx);



/**
*
* \brief Close the socket identified by its unique id and free its related structures
* \param ui32SockId Unique socket identifier to be closed
* \return
*   - IMG_SUCCESS if the socket has been closed
*   - IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE if the socket id was not correct
*
* \details
* After checking that the device context has been previously created and this id corresponds to
* a previously opened socket, this function will destroy all structure that were used by the
* fetched socket object. It will also un-register the socket from the device context
*
**/
IMG_RESULT KM_CloseSocket(IMG_UINT32 ui32SockId);


/**
*
* \brief Linked a virtual address to a stream object for future use
* \param [in] ui32SockId Unique socket object identifier
* \param [in] ui32FWVirtualAddr Firmware context virtual address to link
* \return
*   - IMG_SUCCESS if the socket has been closed
*   - IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE if the socket id was not correct
*
**/
IMG_RESULT KM_LinkSocketToFW(IMG_UINT32 ui32SockId, IMG_UINT32 ui32FWVirtualAddr);


/**
*
* \brief Insert a 4 words commands in the socket command FIFO
* \param [in] ui32SockId Unique socket object identifier
* \param [in] eCommand Command to be inserted
* \param [in] ui32DevMemBlock Offset in the context device memory pool for the external device memory allocated block - can be the virtual address too in certain cases
* \param [in] ui32CommandData Useful data for the command that can fit on 32bits and directly usable without access to the external memory
* \param [out] pui32CmdSeqNum Last unique command identifier that was sent to the FW, KM can use it to keep track of what the FW has already processed
* \return
*   - IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE if the socket object cannot be fetched from RMAN layer
*	- IMG_ERROR_NOT_INITIALISED if there is a problem with the device context
*	- IMG_ERROR_INVALID_ID if the socket id is invalid
*	- IMG_ERROR_INVALID_PARAMETERS if the socket object for this id has not been created
*	- IMG_ERROR_COMM_COMMAND_NOT_QUEUED if the socket command FIFO is already full
*	- IMG_ERROR_COMM_RETRY if the socket command FIFO slot cannot be found
*	- IMG_ERROR_FATAL if a non-recognised command is being sent
*	- IMG_SUCCESS if the command has been inserted properly
*
* \details
* After performing existence check for both the device context and the socket object associate with the UM context,
* this function will try (if some space is available) to insert the command in the socket command buffer (FIFO).
* Once all four words have been placed in the socket command queue, it terminates by signalling the "work queue"
* scheduling function (either the DMAN LISR or the LISR thread when we poll for interrupts) which will actually
* performs the command insertion from the KM to the command FIFO (it might not be the last command queued but a
* command for another context)
*
**/
IMG_RESULT KM_SendCommandToFW(IMG_UINT32 ui32SockId, IMG_UINT32 eCommand, IMG_UINT32 ui32DevMemBlock, IMG_UINT32 ui32CommandData, SYSBRG_POINTER_ARG(IMG_UINT32) pui32CmdSeqNum);


/**
*
* \brief Waits for the next feedback message from Firmware for a given context
* \param [in] ui32SockId Socket unique id on which feedback should come back from FW
* \param [out] peMessage The feedback message type that came back
* \param [out] pui32Data Data associated with the message that came back
* \param [out] pui32ExtraInfo Extra information that came back with the message 
* \return
*   - IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE if the kernel object cannot be fetched
*   - IMG_ERROR_NOT_INITIALISED if the kernel device context is not initialised properly
*   - IMG_ERROR_INVALID_ID if the kernel object id is out of range
*   - IMG_ERROR_COMM_RETRY if firmware had not returned feedback for this stream
*   - IMG_SUCCESS on normal completion
*
* \details
* This function is the interface between user-mode and firmware to receive messages.
* Two words will be extracted and returned unchanged to user-space. The type of message
* will also be extracted and redundantly returned.
*
**/
IMG_RESULT KM_WaitForMessageFW(IMG_UINT32 ui32SockId, SYSBRG_POINTER_ARG(VXE_FWMESSAGE_TYPE) peMessage, SYSBRG_POINTER_ARG(IMG_UINT32) pui32Data, SYSBRG_POINTER_ARG(IMG_UINT32) pui32ExtraInfo);


/********************************************* QUARTZ SPECIFIC FUNCTIONS ***************************************************/

/**
*
* \brief Access the registers containing the features supported by the HW
* \param [in] ui32ConnId Unique identifier for the connection KM => device
* \param [out] psHwConfig Set of hardware configuration register values
* \return IMG_SUCCESS on normal completion
*
**/
IMG_RESULT QUARTZ_KM_GetCoreConfig(IMG_UINT32 ui32ConnId, SYSBRG_POINTER_ARG(VXE_HW_CONFIG) psHwConfig);


/**
*
* \brief Fetches the connection id from an already opened stream
* \param [in] ui32SockId Unique stream identifier (UM => KM) [obtained when calling #KM_OpenSocket()]
* \param [out] pui32ConnId Global device connection id to which this stream is attached (KM => device)
* \return
*   - IMG_SUCCESS on normal completion
*   - IMG_ERROR_FATAL if the socket is not connected to any device context
*
**/
IMG_RESULT QUARTZ_KM_GetConnIdFromSockId(IMG_UINT32 ui32SockId, SYSBRG_POINTER_ARG(IMG_UINT32) pui32ConnId);

/**
* \fn KM_EnableFirmwareTrace
* \brief Enables firmware debug log 
* \param [in] ui32DevConnId Unique identifier for the connection KM => device
* \param [in] ui32Size Size of trace buffer to allocate
* \return	- IMG_SUCCESS on normal completion
*			- IMG_ERROR_NOT_INITIALISED if the device is not initialised
*			- IMG_ERROR_OUT_OF_MEMORY if the memory cannot be allocated
*			- IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE if the memory cannot be mapped into the device virtual address map
**/
IMG_RESULT KM_EnableFirmwareTrace(IMG_UINT32 ui32DevConnId, IMG_UINT32 ui32Size);

/**
* \fn KM_GetFirmwareTrace
* \brief Returns details of firmware debug log previously enabled using KM_EnableFirmwareTrace
* \param [in] ui32DevConnId Unique identifier for the connection KM => device
* \param [out] pui64fwLogToken Token to allow mapping of buffer into user space
* \param [out] pui32fwLogSize Size of trace buffer
* \param [out] pui32fwLogWoff Next write offset in trace buffer 
* \return	- IMG_SUCCESS on normal completion
*			- IMG_ERROR_NOT_INITIALISED if the firmware trace is not initialised
**/
IMG_RESULT KM_GetFirmwareTrace(IMG_UINT32 ui32DevConnId, SYSBRG_POINTER_ARG(IMG_UINT64) pui64fwLogToken, SYSBRG_POINTER_ARG(IMG_UINT32) pui32fwLogSize, SYSBRG_POINTER_ARG(IMG_UINT32) pui32fwLogWoff);


#endif
