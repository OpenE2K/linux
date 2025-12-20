/*!
 *****************************************************************************
 *
 * @File       proc_FwIF.h
 * @Title      Expose embedded processor driving function to the kernel
 * @Description    Contains functions used to setup the firmware on the hardware
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

#if !defined(_PROC_FW_IF_H_)
#define _PROC_FW_IF_H_

#include "vxe_fw_if.h"
#include "img_types.h"

/***************************************************** DEFINES *************************************************************/

// From <metasim_source>/source/include/metag-local/include/metag/metac_2_1.inc
#define LTP_CORE_CODE_MEM   (0x10) // First code memory [0x10-0x17] cf TRM 4.6.21
#define LTP_CORE_DATA_MEM   (0x18) // First data memory [0x18-0x1f] cf TRM 4.6.21
#define LTP_PC              (0x05)
// This has to be MINIM compliant (same values in the makefile used with META compiler)
#define PC_START_ADDRESS    (0x80980000)
#define DATA_BASE_ADDRESS	(0x82000000)

#define MMU_SOFT_RESET_POLL_COUNT	(200)
#define MMU_SOFT_RESET_TIMEOUT		(500)

#define VXE_TIMEOUT_WAIT_FOR_FW_BOOT		(500)
#define VXE_TIMEOUT_RETRIES					(4000)


/*********************************************** STRUCTURES/TYPEDEFS *******************************************************/


/*!
* @struct _GENERAL_PURPOSE_DATA_ General purpose data the driver needs in the uncached area
* @typedef GENERAL_PURPOSE_DATA General purpose data the driver needs in the uncached area
* @brief The firmware and the kernel module communicate using this small memory region from mapped embedded processor RAM
*/
typedef struct _GENERAL_PURPOSE_DATA_
{
	IMG_UINT8 aui8FWRegisters[FW_REG_SECTION_END - PIPELOWLATENCYINFO_MEM_TOTAL_SIZE];				//!< General purpose register, FW_REG_SECTION_START is 0
	IMG_UINT8 aui8HWPipeLowLatencyusageMemory[PIPELOWLATENCYINFO_MEM_TOTAL_SIZE]; //!< Keeps count of nodes/headers in linked lists completed (per tile)
	IMG_UINT8 aui8FWStatusCounters[FW_CTXT_STATUS_COUNTERS_SIZE]; //!< Counters of feedback messages sent by each context
	IMG_UINT8 aui8HWFIFOMemory[FW_HW_FIFO_MEM_TOTAL_SIZE];		//!< Command FIFO KM => FW
	IMG_UINT8 aui8FeedbackMemory[FW_FEEDBACK_MEM_TOTAL_SIZE];	//!< Feedback FIFO FW => KM
} GENERAL_PURPOSE_DATA;
STATIC_ASSERT(sizeof(GENERAL_PURPOSE_DATA) == FW_FEEDBACK_FIFO_END);


/*!
* @struct _LOAD_METHOD_ Firmware loading method
* @typedef VXE_KM_FW_SOFT_IMAGE Firmware loading method
* @brief The firmware can be loaded using several methods or not be loaded (fake fw)
*/
typedef enum _LOAD_METHOD_
{
	LTP_LOADMETHOD_NONE = 0,
	LTP_LOADMETHOD_COPY,
	LTP_LOADMETHOD_DMA,
	LTP_LOADMETHOD_BOOTLOADER,
} LOAD_METHOD;


/*!
* @struct _VXE_KM_FW_SOFT_IMAGE_ Representation of the firmware in software
* @typedef VXE_KM_FW_SOFT_IMAGE Representation of the firmware in software
* @brief This structure contains information on how the FW code will be upload, and other important ones
*/
typedef struct _VXE_KM_FW_SOFT_IMAGE_
{
	IMG_BOOL8		bInitialized;								//!< Memory required for the firmware code has been allocated
	IMG_BOOL8		bPopulated;									//!< After being initialized, this firmware image has been set, so that it know how to load the FW code
	IMG_UINT16		ui16ActiveContextMask;						//!< Bit mask of active encode contexts in the firmware (subject to change depending on the max number of context supported)

	IMG_HANDLE		hLTPDataRam;								//!< Embedded data ram memory bank (uncached) that we will use for general purpose and FW load
	IMG_HANDLE		hLTPCodeRam;								//!< Embedded code ram memory bank (uncached) that we will use for FW load
	IMG_HANDLE		hLTPRegMemspace;							//!< Lower end of the exposed LTP registers (directly accessible from outside of the core)
	IMG_HANDLE		hMetaRegMemspace;							//!< Higher end of the exposed META registers (directly accessible from outside of the core)
	IMG_HANDLE		hQuartzMultipipeMemSpace;					//!< Some further function calls require access to it, so we grant access at init time
	IMG_HANDLE		hMMURegs;									//!< MMU register bank is accessed for APM, so we grant access at init time
	IMG_HANDLE		hDMACRegs;									//!< DMAC register bank
	LOAD_METHOD		eLoadMethod;								//!< How the firmware should be loaded on the hardware
	IMG_VOID		*pvText;									//!< Device memory location where the firmware text section will be kept
	IMG_VOID		*pvData;									//!< Device memory location where the firmware data section will be kept
	// Information relative to the selected firmware build
	struct _FIRMWARE_BUILD_
	{
		IMG_UINT32	ui32SelectedFWBuildTextSize;				//!< After electing a FW build, we know the code size it requires
		IMG_UINT32	ui32SelectedFWBuildDataSize;				//!< After electing a FW build, we know the data size it requires
		IMG_UINT32	*pui32FWText;								//!< Raw firmware binary for the text section
		IMG_UINT32	*pui32FWData;								//!< Raw firmware binary for the text section
		IMG_UINT32	ui32FWDataOrigin;							//!< Start of the data section
		IMG_UINT32	ui32FWBootStrap;							//!< Address from where the firmware code can be loaded
		IMG_UINT32	ui32NumPipes;								//!< Pipe support for the build
		IMG_UINT32	ui32FWDefinesLength;
		IMG_CHAR	**ppszFWDefineNames;
		IMG_UINT32	*pui32FWDefinesValues;
		IMG_UINT32	ui32FWSupportedCodecs;
		IMG_UINT32	ui32FWNumContexts;
	} sFirmwareBuildInfos;
	// Some information about the hardware
	IMG_UINT32		ui32QuartzCoreRev;							//!< Content of QUARTZ_CORE_REV register
	IMG_UINT32		ui32QuartzConfig;							//!< Content of QUARTZ_CONFIG register
	IMG_UINT8		ui8QuartzHwPipes;							//!< Content of QUARTZ_CONFIG[2:0] register

	IMG_BOOL8		bDriverHasProcCtrl;							//!< The interaction with core registers is done through the slave interface and it can be used only once at a time

	//IMG_BYTE		aPad2[2];

	IMG_UINT32		ui32CoreCodeRAM;							//!< Maximum core memory dedicated to FW code
	IMG_UINT32		ui32CoreDataRAM;							//!< Maximum core memory dedicated to FW data
	IMG_UINT32		ui32ProcRAMAccessControl;					//!< Content of the core memory control proc register (MCMGCTRL in LTP TRM)
	// Power management related
	IMG_UINT32*		pui32ProcRegisterCopy;						//!< When the core is turned off, we need to save some of the registers' value
	IMG_VOID*		apvProcContextCopy [FW_CORE_CONTEXTS];		//!< When the embeddded proc is turned off, we need to save the context(s) currently on core memory, the ones in external memory does not need it
} VXE_KM_FW_SOFT_IMAGE;


/*!
* @struct _VXE_KM_LOOKUP_CODEC_FORMAT_RC_ Lookup table content linked codec to bitmask and string name
* @typedef VXE_KM_LOOKUP_CODEC_FORMAT_RC Lookup table content linked codec to bitmask and string name
* @brief This structure is used to guarantee that the right information are linked to the right codec, the enum can change and the lookup table won't be impacted
*/
typedef struct _VXE_KM_LOOKUP_CODEC_FORMAT_RC_
{
	IMG_UINT16		ui16CodecMask;								//!< Same format as VXE_KM_SOFT_IMAGE::sFirmwareBuildInfos::ui32FWSupportedCodecs and compiler build
	IMG_CHAR const	*pszFormat;									//!< Name of the codec as string
	IMG_CHAR const	*pszRCModes; /* not sure about this one */
} VXE_KM_LOOKUP_CODEC_FORMAT_RC;

extern VXE_KM_LOOKUP_CODEC_FORMAT_RC g_asLookupTableCodecToMask[];

#ifdef LOAD_FW_VIA_LINUX
extern char* firmware_name; 
#endif


IMG_RESULT ltp_reset(VXE_KM_FW_SOFT_IMAGE * psFWSoftImage);


/************************************************* PUBLIC FUNCTIONS ********************************************************/


/*!
* @fn LTP_Initialize
* @brief Initialize the firmware image to prepare its load on the LTP embedded processor
* @param psFWSoftImage Pointer to the context of the target LTP
* @return
*	- IMG_SUCCESS on normal completion
*	- IMG_ERROR_ALREADY_INITIALISED if psFWSoftImage->bInitialized is set
*	- IMG_ERROR_MALLOC_FAILED if the dynamic allocation failed
*/
IMG_RESULT LTP_Initialize(VXE_KM_FW_SOFT_IMAGE * psFWSoftImage);


/*!
* @fn LTP_Deinitialize
* @brief Deinitialize the FW loaded on the LTP embedded processor
* @param psFWSoftImage Pointer to the context of the target LTP
*/
IMG_VOID LTP_Deinitialize(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage);


/*!
* @fn LTP_Start
* @brief Turn on the LTP embedded processor
* @param psFWSoftImage Pointer to the context of the target LTP
* @return
*	- IMG_SUCCESS on normal completion
*/
IMG_RESULT LTP_Start(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage);


/*!
* @fn LTP_Stop
* @brief Stop the LTP embedded processor
* @param psFWSoftImage Pointer to the context of the target LTP
* @return
*	- IMG_SUCCESS on normal completion
*/
IMG_RESULT LTP_Stop(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage);


/*!
* @fn LTP_EnableDisable
* @brief Abstracts real/fake firmware behaviour for enabling/disabling LTP (fake does nothing)
* @param psFWSoftImage Pointer to the context of the target LTP
* @param bEnable Should the LTP be enabled (1) or disabled (0)
* @return
*	- IMG_SUCCESS on normal completion
*/
IMG_RESULT LTP_EnableDisable(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage, IMG_BOOL bEnable);


/*!
* @fn LTP_WriteSoftReset
* @brief Wraps the LTP soft reset register write(s)
* @param psFWSoftImage Pointer to the context of the target LTP
*/
IMG_RESULT LTP_WriteSoftReset(VXE_KM_FW_SOFT_IMAGE * psFWSoftImage);


/*!
* @fn LTP_Kick
* @brief Issue <ui32KickCount> kick(s) to the LTP core through its dedicated register (background kick)
* @param psFWSoftImage Pointer to the context of the target LTP
* @param ui32KickCount Number of kick to issue
* @return
*	IMG_SUCCESS on normal completion
*/
IMG_RESULT LTP_Kick(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage, IMG_UINT32 ui32KickCount);


/*!
* @fn LTP_Deinitialize
* @brief Deinitialize the FW loaded on the LTP embedded processor
* @param psFWSoftImage Pointer to the context of the target LTP
* @return
*	- IMG_SUCCESS on normal completion
*/
IMG_RESULT LTP_WaitForCompletion(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage);


/*!
* @fn LTP_PopulateFirmwareContext
* @brief Set a number of required information to upload the firmware on device memory
* @param psFWSoftImage Pointer to the context of the target LTP
* @param eCodec Codec to be used for this firmware (comes from the codec selected when openning the socket)
* @return IMG_SUCCESS if the firmware context has been populated and a firmware build matches the requirement
*/
IMG_RESULT LTP_PopulateFirmwareContext(IMG_HANDLE pvDevContext, VXE_CODEC eCodec);


/*!
* @fn LTP_LoadFirmware
* @brief After all information required have been set, this will perform the code copy where (and how) it has been defined on device memory
* @param hDevContext Handle on the device context (used for allocation mainly)
* @param psFWSoftImage Pointer to the context of the target LTP
* @param eLoadMethod How do we want to load the firmware
* @return	- IMG_ERROR_OUT_OF_MEMORY if one allocation failed
*			- IMG_ERROR_GENERIC_FAILURE if eLoadMethod is 'NONE'
*			- IMG_ERROR_DISABLED if the device initialisation failed
*			- IMG_ERROR_TIMEOUT on poll timeout
*			- IMG_SUCCESS on normal completion
*/
IMG_RESULT LTP_LoadFirmware(IMG_HANDLE hDevContext, VXE_KM_FW_SOFT_IMAGE * psFWSoftImage, LOAD_METHOD eLoadMethod);


/*!
* @fn LTP_GetFWConfigIntValue
* @brief Get the value of #define pszDefineName for the firmware represented by $psFWSoftImage
* @param psFWSoftImage Pointer to the context of the target LTP
* @param pszDefineName Name of the define to be found
* @return The value of the define on success, -1 if not found (all constants are expected positive)
*/
IMG_INT32 LTP_GetFWConfigIntValue(const VXE_KM_FW_SOFT_IMAGE * const psFWSotfImage, const IMG_CHAR * const pszDefineName);




/************************************************* POWER MANAGEMENT ********************************************************/


/*!
* @function LTP_SaveState
* @brief Active Power Management routine to save the LTP internal state
* @param psFWSoftImage Pointer to the context of the LTP target
* @return
*	- IMG_SUCCESS on normal completion
*/
IMG_RESULT LTP_SaveState(VXE_KM_FW_SOFT_IMAGE *psFWSoftImage);


/*!
* @function LTP_RestoreState
* @brief Active Power Management routine to restore the LTP internal state
* @param hDevContext Handle on the device context containing the LTP target context
* @return
*	- IMG_SUCCESS on normal completion
*	- IMG_ERROR_DISABLED if trying to re-enable HW when there is nothing left to do
*/
IMG_RESULT LTP_RestoreState(IMG_HANDLE hDevContext);

#endif //!defined(_PROC_FW_IF_H_)
