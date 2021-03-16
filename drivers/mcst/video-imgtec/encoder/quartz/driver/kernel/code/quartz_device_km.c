/*!
 *****************************************************************************
 *
 * @File       quartz_device_km.c
 * @Title      Quartz device communication functions
 * @Description    This file contains the QUARTZ Device Kernel Mode component.
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

#include <tal.h>
#include <target.h>
#include "quartz_device_km.h"
#include "quartz_mmu.h"
#include <vxe_KM.h>
#include <sysos_api_km.h>
#include "sysenv_api_km.h"
#include <sysbrg_utils.h>

#include "e5500_public_regdefs.h"
#include "img_video_bus4_mmu_regs_defines.h"
#include "ltp_regs.h"

#include <rman_api.h>
#include <sysdev_utils.h>

#define __SYS_DEVICES__
#include <system.h>

#include <tal.h>

#include <memmgr_km.h>

#include "proc_FwIF.h"


#ifdef WIN32
#define TRACK_FREE(ptr) 		IMG_FREE(ptr)
#define TRACK_MALLOC(ptr) 		IMG_MALLOC(ptr)
#define TRACK_DEVICE_MEMORY_INIT
#define TRACK_DEVICE_MEMORY_SHOW
#include <sys/timeb.h>
#define TIMER_INIT
#define TIMER_START(a,b)
#define TIMER_END(a)
#define TIMER_CAPTURE(a)
#define TIMER_CLOSE
#define TRACK_DEVICE_MEMORY_ALLOC(a,b,c)
#define TRACK_DEVICE_MEMORY_FREE(a,b)
#define __func__ __@function__
//#include "timer.h"
#else
#define TRACK_FREE(ptr) 		IMG_FREE(ptr)
#define TRACK_MALLOC(ptr) 		IMG_MALLOC(ptr)
#define TRACK_DEVICE_MEMORY_INIT
#define TRACK_DEVICE_MEMORY_SHOW
#define TRACK_DEVICE_MEMORY_ALLOC(...)
#define TRACK_DEVICE_MEMORY_FREE(...)
#define TIMER_INIT
#define TIMER_START(...)
#define TIMER_END(...)
#define TIMER_CLOSE
#define TIMER_CAPTURE(...)
#endif

#include "coreflags.h"
#include "VXE_Enc_GlobalDefs.h"

#ifdef LOAD_FW_VIA_LINUX
char *firmware_name = "encoder_fw.bin";
module_param(firmware_name, charp, 0000);
MODULE_PARM_DESC(firmware_name, "Name of firmware image");
#endif



/* For multicore */
SYSDEVU_sInfo as_quartz_device[];
static int get_core_dev_id (const char *dev_name)
{
	int i;
	for (i = 0; i < VXE_KM_SUPPORTED_DEVICES; i++)
	{
		if (0 == strcmp(as_quartz_device[i].sDevInfo.pszDeviceName, dev_name))
		{
			/* Found a match */
			return i;
		}
	}

	/* Error, not found */
	return -1;
}

static IMG_HANDLE g_sMutexDevKm = NULL;


/*
* Extern definitions: defined by the kernel module build options or can come from the runtime parameters
* NOTE:
* They will be copied in the device context when a new connection is opened to it, they are
* to be seen as value holders more than variables we use.
*/
VXE_KM_SCHEDULING_MODEL g_eSchedulingModel = VXE_KM_DEFAULT_SCHED_MODEL;
IMG_UINT32 g_ui32MMUTileStride = VXE_DEFAULT_TILE_STRIDE;
IMG_BOOL g_bKMPPM = VXE_KM_DEFAULT_PPM;
IMG_UINT32 g_ui32MMUFlags = VXE_KM_DEFAULT_MMU_FLAGS;


#if defined (IMG_KERNEL_MODULE)

/* Defined by sysctl interface or kernel module parameters */

#else /*defined (IMG_KERNEL_MODULE)*/

/* Just because it may be a problem */
IMG_BOOL g_bCoreSR = IMG_TRUE;

// Are we going to enable pdump?
IMG_BOOL g_bDoingPdump = IMG_FALSE;
static IMG_CHAR *pszDriverVersion = "Driver Version:Local Driver Build";

#endif /*defined (IMG_KERNEL_MODULE)*/



/**************************************** EXTERNAL DEFINITIONS **************************************/

// HISR function
extern IMG_RESULT KM_CheckAndSchedule(VXE_KM_DEVCONTEXT* devContext);
// LISR function
extern IMG_RESULT KM_DispatchFeedback(VXE_KM_DEVCONTEXT *devContext);

// These are defined in vxe_km.c
extern IMG_VOID quartzkm_fnPowerRestore(IMG_HANDLE hDevHandle, IMG_VOID *pvDevInstanceData);
extern IMG_VOID quartzkm_fnPowerSave(IMG_HANDLE hDevHandle, IMG_VOID *pvDevInstanceData);
extern IMG_RESULT KM_TurnOffHW(VXE_KM_DEVCONTEXT *psDevContext);
extern IMG_RESULT km_populate_hw_config(VXE_KM_DEVCONTEXT *psDevContext);

/******************************************* LOCAL DEFINES ******************************************/
/* This number is identifying a video core from IMG */
#define VXE_KM_QUARTZ_ID (0x04070000)
#define MOVED_POWER_TRANS_TO_HISR



// If the interrupt are not active, there will be a thread polling the interrupt register state
#if defined (POLL_FOR_INTERRUPT)
/*
* The following code is only enabled when we don't have interrupt wired in, typically non-bridging
* cases but it can also be due to FPGA interrupt not working. Our goal here is to mimic what the
* DMAN layer would do if interrupts were enabled. With Quartz, we want to use both HISR (workqueue)
* and LISR (interrupt handler). We are doing an active polling for the LISR inside one thread, and
* we will use DMAN to signal the HISR workqueue.
*/

#if !defined(IMG_KERNEL_MODULE)
#include "osa.h"
#endif


/**
* \fn KM_AnyFeedbackIsWaiting
* \brief Check if any command has been issued inducing some feedback may be on the way
* \param apsSockets Array of socket pointers
* \return	- IMG_TRUE if at least one socket has been found active.
*			- IMG_FALSE if no sockets are active
**/
static IMG_BOOL KM_AnyAreWaiting(VXE_KM_COMM_SOCKET **apsSockets)
{
	IMG_UINT8 ui8SocketNum = 0;
	VXE_KM_COMM_SOCKET *psSocket = IMG_NULL;

	/* Cycle through all sockets to see if any have outstanding activity */
	while (ui8SocketNum < VXE_MAX_SOCKETS)
	{
		psSocket = apsSockets[ui8SocketNum++];
		if (psSocket && psSocket->b8StreamWaiting)
		{
			/* We found someone willing to do some work */
			return IMG_TRUE;
		}
	}
	return IMG_FALSE;
}


#define POLL_COUNT		(10000)
#define POLL_TIMEOUT	(4000)


/***************************************** PUBLIC VARIABLES *****************************************/


/**************************************** PRIVATE VARIABLES *****************************************/


/**************************************** PRIVATE FUNCTIONS *****************************************/
/**
* \fn KM_LISRThread
* \brief ISR handler with polling behaviour
* \params pParams Thread parameters passed at creation time
* \details
* This ISR simulated thread polls the interrupt state coming from the FW. When an IRQ is signaled,
* it will extract the feedback from the global shared FIFO to the per-socket feedback FIFO and signal
* the availability of feedback to upper layer (mainly the DFE thread associated with the UM context)
**/
static
#if !defined(IMG_KERNEL_MODULE)
IMG_VOID
#else
int
#endif
KM_LISRThread(IMG_VOID *pParams)
{
	IMG_RESULT eRet = IMG_ERROR_CANCELLED;
	VXE_KM_LISR_CONTROL* psIsrControl = (VXE_KM_LISR_CONTROL *)pParams;
	VXE_KM_DEVCONTEXT* psDevContext = psIsrControl->psKMDevContext;

	DEBUG_PRINT("%s() - Starting ISR polling Handler\n", __FUNCTION__);

	if (!psDevContext)
	{
		PRINT("Invalid parameter to %s()\n", __FUNCTION__);
#if ! defined(IMG_KERNEL_MODULE)
		return;
#else
		do_exit(-1);
		return -1;
#endif
	}

	do
	{
		/* It mainly has a pdump justification here: we delay the polling insertion to the point in time where we are sure to find something */
		while (!psIsrControl->bExit && !KM_AnyAreWaiting(psDevContext->apsDeviceSockets))
		{
#if ! defined(IMG_KERNEL_MODULE)
			OSA_ThreadSleep(ISR_SLEEPING_TIME_BETWEEN_POLL);
#else
			msleep(ISR_SLEEPING_TIME_BETWEEN_POLL);
#endif
			/* Should we turn off the HW ? */
			if (psDevContext->eLowPowerState == e_HW_LOW_POWER)
			{

				/* Give the workqueue a try */
				if (psIsrControl->bSignalHISR)
				{
					DMANKM_ActivateKmHisr(psDevContext->hDMANDevHandle);
				}
			}
		}

		/* Something can be done now */
		if (!psIsrControl->bExit)
		{
#if defined (OUTPUT_COMM_STATS)
			Output_COMM_General_Line("MSG-ISR_POL", "COMM_Track.txt");
#endif

			if (psDevContext->eLowPowerState != e_HW_IDLE)
			{
				/* Dequeue some feedback */
				eRet = KM_DispatchFeedback(psDevContext);


				if (eRet == IMG_ERROR_IDLE)
				{
#if defined(IMG_KERNEL_MODULE)
					/* If the HW is ever lock up, we will be in an active polling situation, eventually causing a kernel soft lockup. That is why we need to sleep! */
					msleep(ISR_SLEEPING_TIME_BETWEEN_POLL);
#endif
					eRet = IMG_SUCCESS;
				}
				/* Should we turn off the HW ? */
				if (psDevContext->eLowPowerState == e_HW_LOW_POWER)
				{

					/* Give the workqueue a try */
					if (psIsrControl->bSignalHISR)
					{
						DMANKM_ActivateKmHisr(psDevContext->hDMANDevHandle);
					}
				}
			}
		}


		/*
		* Now that the hardware is idle, we don't expect more feedback so we 
		* stall the LISR here in order to let some time to the HISR to re-enable
		* the hardware on new command insertion
		*/
		while (psDevContext->eLowPowerState == e_HW_IDLE)
		{
			if (psIsrControl->bExit)
			{
				break;
			}

#if ! defined(IMG_KERNEL_MODULE)
			OSA_ThreadSleep(ISR_SLEEPING_TIME_BETWEEN_POLL);
#else
			msleep(ISR_SLEEPING_TIME_BETWEEN_POLL);
			/* Give the workqueue a try */
			if (psIsrControl->bSignalHISR)
			{
				DMANKM_ActivateKmHisr(psDevContext->hDMANDevHandle);
			}
#endif
		}

	} while (!psIsrControl->bExit && eRet == IMG_SUCCESS);

#if defined(IMG_KERNEL_MODULE)
	do_exit(0);
	return 0;
#endif

	DEBUG_PRINT("%s() - Closing down ISR polling Handler\n", __FUNCTION__);
}


/**
* \fn KM_StartISRThread
* \brief Start the LISR polling thread at the appropriate moment
* \params psDevContext Reference on the VXE_KM_DEVCONTEXT structure
**/
IMG_VOID KM_StartISRThread(VXE_KM_DEVCONTEXT *psDevContext)
{
	if (psDevContext->sDevSpecs.g_sLISRControl.bExit)
	{
		psDevContext->sDevSpecs.g_sLISRControl.bExit = IMG_FALSE;
		// Create and start the ISR polling thread (dispatch message from the FW when producer register has been written to)
		psDevContext->sDevSpecs.g_sLISRControl.psKMDevContext = psDevContext;

#if !defined(IMG_KERNEL_MODULE)
		OSA_ThreadCreateAndStart(KM_LISRThread,
			&psDevContext->sDevSpecs.g_sLISRControl,
			"ISR polling Thread",
			OSA_THREAD_PRIORITY_LOWEST,
			&psDevContext->sDevSpecs.KM_LISRThreadHandle);
#else
		psDevContext->sDevSpecs.KM_LISRThreadHandle = kthread_run(KM_LISRThread, &psDevContext->sDevSpecs.g_sLISRControl, "ISRLooper");
		if (psDevContext->sDevSpecs.KM_LISRThreadHandle == ERR_PTR(-ENOMEM))
		{
			PRINT("LISR poller creation failed.\n");
			psDevContext->sDevSpecs.g_sLISRControl.bExit = IMG_TRUE;
			psDevContext->sDevSpecs.g_sLISRControl.psKMDevContext = NULL;
			psDevContext->sDevSpecs.g_sLISRControl.bSignalHISR = IMG_FALSE;
		}
#endif // !defined(IMG_KERNEL_MODULE)
	}
}

#endif // defined (POLL_FOR_INTERRUPT)


IMG_RESULT QUARTZKM_Initialise(VXE_KM_DEVCONTEXT *psDevContext, IMG_HANDLE hDevHandle);


/***************************************** PUBLIC FUNCTIONS *****************************************/


/*!
* @function DeInitTal
* @brief Deinitialise the TAL
*/
void DeInitTal(VXE_KM_DEVCONTEXT *psDevContext)
{
	TIMER_START(hardwareduration, "");
	MMDeviceMemoryDeInitialise((void*)psDevContext);
	TIMER_END("HW - TAL_Deinitialise in DeInitTal (quartz_device_km.c)");
}


/*!
******************************************************************************
*
* @function quartzdd_IntEnable
* @brief Enable interrupt coming from the hardware to the host
* @param psContext VXE (kernel level) device context reference
* @param ui32IntMask Interrupt(s) to enable
*
******************************************************************************/
static IMG_VOID	quartzdd_IntEnable(
	VXE_KM_DEVCONTEXT *	psContext,
	IMG_UINT32			ui32IntMask
)
{
	IMG_UINT32 crImgQuartzIntenab;

	if (!DMANKM_IsDevicePoweredOn(psContext->hDMANDevHandle))
	{
		/* device is not powered on so we can't do it ust now */
		return;
	}
	/* Disable interrupt handling in SYSOS layer to prevent setting to be corrupted */
	SYSOSKM_DisableInt();

	/* Read content of the register before configuring interrupts on the host side */
	TALREG_ReadWord32(psContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_HOST_INT_ENAB, &crImgQuartzIntenab);

	/* Set enable interrupt bits */
	crImgQuartzIntenab |= ui32IntMask;

	/* Update register content */
	TALREG_WriteWord32(psContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_HOST_INT_ENAB, crImgQuartzIntenab);

	/* Enable interrupt handling in SYSOS layer */
	SYSOSKM_EnableInt();
}

/*!
******************************************************************************
*
* @function quartzdd_IntDisable
* @brief Disable interrupt coming from the hardware to the host
* @param psContext VXE (kernel level) device context reference
* @param ui32IntMask Interrupt(s) to disable
*
******************************************************************************/
static IMG_VOID	quartzdd_IntDisable(
	VXE_KM_DEVCONTEXT *	psContext,
	IMG_UINT32			ui32IntMask
)
{
	IMG_UINT32		crImgQuartzIntenab;

	if (!DMANKM_IsDevicePoweredOn(psContext->hDMANDevHandle))
	{
		/* device is not powered on so we can't do it ust now */
		return;
	}
	/* Disable interrupt handling in SYSOS layer to prevent setting to be corrupted */
	SYSOSKM_DisableInt();

	/* Read content of the register before configuring interrupts on the host side */
	TALREG_ReadWord32(psContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_HOST_INT_ENAB, &crImgQuartzIntenab);

	/* Clear enable interrupt bits */
	crImgQuartzIntenab &= ~ui32IntMask;

	/* Update register content */
	TALREG_WriteWord32(psContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_HOST_INT_ENAB, crImgQuartzIntenab);

	/* Enable interrupt handling in SYSOS layer */
	SYSOSKM_EnableInt();
}

/*!
******************************************************************************
*
* @function quartzdd_IntClear
* @brief Acknowledge/clear interrupts
* @param psContext VXE (kernel level) device context reference
* @param ui32IntMask Interrupt(s) to clear
*
******************************************************************************/
static IMG_VOID	quartzdd_IntClear(
	VXE_KM_DEVCONTEXT *		psContext,
	IMG_UINT32				intClearMask
)
{
	if (!DMANKM_IsDevicePoweredOn(psContext->hDMANDevHandle))
	{
		/* device is not powered on so we can't do it ust now */
		return;
	}
	/* Disable interrupt handling in SYSOS layer to prevent setting to be corrupted */
	SYSOSKM_DisableInt();

	/* Update register content */
	TALREG_WriteWord32(psContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_INT_CLEAR, intClearMask);
	
	/* Enable interrupt handling in SYSOS layer */
	SYSOSKM_EnableInt();
}


/*!
******************************************************************************
*
* @function quartzdd_Initialise
* @brief Update the latest settings required to handle the hardware
* @param psContext VXE (kernel level) device context reference
* @details
* After checking that the device context has been initialised only once, it
* will initialise missing parts of the device context and enable interrupts
* coming from the encoder to the host
* @return
*	- IMG_SUCCESS on normal completion
*	- IMG_ERROR_FATAL if the register memspace can't be accessed
*
******************************************************************************/
IMG_RESULT quartzdd_Initialise(
	VXE_KM_DEVCONTEXT *psContext
)
{
	/* The initialisation should only occur once */
	if (!psContext->bInitialised)
	{
		if (NULL == psContext->sDevSpecs.hQuartzMultipipeBank)
		{
			IMG_ASSERT(psContext->sDevSpecs.hQuartzMultipipeBank != IMG_NULL);
			return IMG_ERROR_FATAL;
		}

		// Interrupts are only enabled in bridging build.
#if !defined(POLL_FOR_INTERRUPT) //!defined (SYSBRG_NO_BRIDGING)
		/* LISR will trigger on embedded core interrupt and MMU faults */
		quartzdd_IntEnable(psContext, MASK_QUARTZ_TOP_HOST_INTEN_PROC | MASK_QUARTZ_TOP_HOST_INTEN_MMU_FAULT);
#else
		(void)quartzdd_IntEnable;
#endif

		/* Device now initialised, and it will only be once */
		psContext->bInitialised = IMG_TRUE;
	}

	/* Return success */
	return IMG_SUCCESS;
}

/*!
******************************************************************************
*
* @function	quartzdd_Deinitialise
* @brief Unlink the KM with the hardware interrupts
* @param psContext VXE (kernel level) device context reference
*
******************************************************************************/
IMG_VOID quartzdd_Deinitialise(
	VXE_KM_DEVCONTEXT		*psContext
)
{
#if !defined(POLL_FOR_INTERRUPT)
	/* Disable all interrupts signalled to the host */
	quartzdd_IntDisable(psContext, ~0);
#else
	(void)psContext;
	(void)quartzdd_IntDisable;
#endif
}

#define SOFT_RESET_DELAY 	384

static IMG_RESULT quartzkm_ResetCore(VXE_KM_DEVCONTEXT *psDevContext)
{
	IMG_UINT32 	ui32RegVal;
#if defined (IMG_KERNEL_MODULE)
	IMG_UINT32 	ui32TimeOutus = ( ( ( ( (IMG_UINT32)(SOFT_RESET_DELAY * 1000)  / (IMG_UINT32)psDevContext->sDevSpecs.sHWConfig.ui32ClkFreqkHz) + 1 ) * 3 ) + 1 ) >> 1; // Always round up, add 50pc, use integer maths
#endif
#if ! defined (IMG_KERNEL_MODULE)
	IMG_RESULT eResult;
#endif
	/** Reset procedure for multipipe/general level features: cores, proc, MMU **/

	if (!DMANKM_IsDevicePoweredOn(psDevContext->hDMANDevHandle))
	{
		/* device is not powered on so we can't do it ust now */
		return IMG_ERROR_DEVICE_UNAVAILABLE;
	}

	/* Disable the embedded processor (accessing the core reg LTP_ENABLE) */
	TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzLTPBank, LTP_CR_LTP_ENABLE, 0x0);

	/* Soft reset of the encoder pipes (all four cores), the features' soft reset of each pipe is automatic */
	ui32RegVal = MASK_QUARTZ_TOP_ENCODER_PIPE_SOFT_RESET(0) | MASK_QUARTZ_TOP_ENCODER_PIPE_SOFT_RESET(1) | MASK_QUARTZ_TOP_ENCODER_PIPE_SOFT_RESET(2) | MASK_QUARTZ_TOP_ENCODER_PIPE_SOFT_RESET(3);
	TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, ui32RegVal);
	TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, 0x0);

#if defined (IMG_KERNEL_MODULE)
	/* wait for any outstanding transactions to go to zero  */
	udelay(ui32TimeOutus);
#endif

	/* Soft reset the MMU (BIF)  */
	TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, MASK_QUARTZ_TOP_CORE_SOFT_RESET);
	TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, 0x0);

	/* Delay*/
#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_Comment(psDevContext->sDevSpecs.hQuartzMMUBank, "Wait for MMU reset to complete");
	eResult = TALREG_Poll32(psDevContext->sDevSpecs.hQuartzMMUBank, IMG_BUS4_MMU_CONTROL1, TAL_CHECKFUNC_ISEQUAL, 0, MASK_IMG_BUS4_MMU_SOFT_RESET, 20000, 500);
	IMG_ASSERT(eResult == IMG_SUCCESS && "Timeout waiting for MMU reset to complete");
	if (IMG_SUCCESS != eResult)
	{
		return eResult;
	}
#else
	udelay(ui32TimeOutus);
#endif

	/* Soft reset of the encoder pipes again */
	TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, ui32RegVal);
	TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, 0x0);

	/* Soft reset the embedded processor (soft reset to one, then to zero: traversing the layers takes enough time) */
	TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, MASK_QUARTZ_TOP_PROC_SOFT_RESET);
	TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, 0x0);

	/* Soft reset the MMU (BIF) one last time */
	TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, MASK_QUARTZ_TOP_CORE_SOFT_RESET);
	TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, 0x0);

	/* Clear the int status at multipipe level just to be sure */
	TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_INT_CLEAR,
		MASK_QUARTZ_TOP_INTCLR_DMAC |
		MASK_QUARTZ_TOP_INTCLR_FRAME_ALARM |
		MASK_QUARTZ_TOP_INTCLR_MMU_FAULT |
		MASK_QUARTZ_TOP_INTCLR_PROC |
		MASK_QUARTZ_TOP_INTCLR_PROC_HALT |
		MASK_QUARTZ_TOP_INTCLR_PROC_FENCE_DONE);


	return IMG_SUCCESS;
}


/*!
******************************************************************************
*
* @function	quartzkm_OnFreeBucket
* @brief Callback register with RMAN_RegisterResource() call
* @param hDevHandle Handle on the device context in the DMAN layer
* @details
* Callback registered to trigger when the device context (KM layer) bucket is 
* destroyed. This happens in #quartzkm_fnDevDeinit with RMAN_DestroyBucket().
* After having turned off the interrupt polling (if is was activated), this
* function will turn off the embedded processor, unload the firmware, close
* all potentially opened sockets and de-initialise remaining parts of the
* hardware (memory for FW and MMU mainly)
*
******************************************************************************/
static IMG_VOID quartzkm_OnFreeBucket(
	IMG_HANDLE				hDevHandle
)
{
	VXE_KM_DEVCONTEXT* psDevContext = IMG_NULL;
	VXE_KM_FW_SOFT_IMAGE* psFWContext = IMG_NULL;
	IMG_RESULT eRet;
	IMG_UINT32 ui32SocketIndex;
	(void)eRet;

	/* Access the device and firmware context software representation */
	psDevContext = DMANKM_GetDevInstanceData(hDevHandle);
	IMG_ASSERT(psDevContext);
	if (!psDevContext)
	{
		return; /*callback return type obeys specific rules, nothing can be done with a NULL pointer however*/
	}
	psFWContext = &psDevContext->sFWSoftImage;

#if defined (INCLUDE_DEBUG_FEATURES)
	debugfs_unlink_context_to_debugfs(psDevContext);
#endif

	/* Close all the opened sockets (they will eventually need to be aborted */
	eRet = IMG_SUCCESS;
	for (ui32SocketIndex = 0; ui32SocketIndex < VXE_MAX_SOCKETS; ++ui32SocketIndex)
	{
		IMG_RESULT eTmpRet; /*report failure independently for each stream*/
		if (psDevContext->apsDeviceSockets[ui32SocketIndex])
		{
			//psDevContext->apsDeviceSockets[ui32SocketIndex]->hResBHandle;
			eTmpRet = KM_CloseSocket(psDevContext->apsDeviceSockets[ui32SocketIndex]->ui32ResourceId);
			if (IMG_SUCCESS != eTmpRet)
			{
				PRINT("%s() - Closing socket %i returned with error: %i\n", __FUNCTION__, ui32SocketIndex, eTmpRet);
			}
			eRet |= eTmpRet;
		}
	}
	IMG_ASSERT(IMG_SUCCESS == eRet); /*even if errors have been reported when closing down streams, carry on cleaning up*/

	if (psFWContext && psFWContext->bInitialized)
	{
		{
			eRet = LTP_Stop(psFWContext);
			if (IMG_SUCCESS != eRet)
			{
				PRINT("LTP could not be stopped (%i)", eRet); /*we want to carry on free'ing*/
			}
			eRet = LTP_WaitForCompletion(psFWContext);
			if (IMG_SUCCESS != eRet)
			{
				PRINT("LTP did not complete in time (%i)", eRet); /*we want to carry on free'ing*/
			}
		}
	}

#if defined (POLL_FOR_INTERRUPT)
	/* Shutdown down the interrupt polling thread and wait for it to exit */
	psDevContext->sDevSpecs.g_sLISRControl.bExit = IMG_TRUE;
#if !defined(IMG_KERNEL_MODULE)
	if (psDevContext->sDevSpecs.KM_LISRThreadHandle)
	{
		OSA_ThreadWaitExitAndDestroy(psDevContext->sDevSpecs.KM_LISRThreadHandle);
		psDevContext->sDevSpecs.KM_LISRThreadHandle = (IMG_HANDLE)0;
	}
#endif
#endif /*defined (POLL_FOR_INTERRUPT)*/


#if defined (USE_FW_TRACE)
	if (psDevContext->hFwTraceBuffer)
	{
		freeMemory((KM_DEVICE_BUFFER **)&psDevContext->hFwTraceBuffer);
		psDevContext->hFwTraceBuffer = IMG_NULL;
	}
#endif

	QUARTZ_KM_DestroyMutex(psDevContext->hCommTxLock);
	QUARTZ_KM_DestroyMutex(psDevContext->hCommAccessStreamsLock);
	QUARTZ_KM_DestroyMutex(psDevContext->hCheckAndScheduleLock);

	if (psFWContext && psFWContext->bInitialized)
	{
		LTP_Deinitialize(psFWContext);
	}

	QUARTZ_KM_LockMutex(g_sMutexDevKm, MTX_SUBCLASS_DEVKM);
	/* De-initialise the MMU if present (behaviours varies between bridging/no bridging builds) */
	DeInitTal(psDevContext);
	QUARTZ_KM_UnlockMutex(g_sMutexDevKm);

	if (NULL != psDevContext->sSchedModel.pvAllocation)
	{
		IMG_FREE(psDevContext->sSchedModel.pvAllocation);
	}

	/* The device context is now entirely de-initialised */
	psDevContext->bInitialised = IMG_FALSE;
}


/*!
******************************************************************************
*
* @function quartzkm_fnDevKmHisr
* @brief DMAN level function registered to behave as a workqueue, triggered by the LISR
* @param hDevHandle Handle on the device context in the DMAN layer
* @param pvDevInstanceData Handle on the device context (KM level)
*
******************************************************************************/
static IMG_VOID quartzkm_fnDevKmHisr (
	IMG_HANDLE				hDevHandle,
    IMG_VOID *				pvDevInstanceData
)
{
	/* Fetch the device context from the parameter */
	IMG_RESULT eRet;
	VXE_KM_DEVCONTEXT* psDevContext = (VXE_KM_DEVCONTEXT*)pvDevInstanceData;
	(void)hDevHandle;

	if (!psDevContext->bInitialised)
	{
		PRINT("Invalid parameter to %s()\n", __FUNCTION__);
		return;
	}

	if (psDevContext->bMMUFaultToSignal)
	{
#if defined (INCLUDE_DEBUG_FEATURES)

		/* Dump the page table */
#if defined (DEBUG_REG_OUTPUT)
		DBG_dump_reg_and_page((void*)psDevContext);
#endif
#endif
			
		/* Reset core */
		quartzkm_ResetCore(psDevContext);
		/* abort all of the contexts currently open */
		km_AbortAllContexts(psDevContext);

		psDevContext->bMMUFaultToSignal = IMG_FALSE;
		psDevContext->bCoreNeedsToClose = IMG_TRUE;

	}


issuing_new_command:

	QUARTZ_KM_LockMutex(psDevContext->hCheckAndScheduleLock, MTX_SUBCLASS_CHECKANDSCHED);
	/*Power management needs to be in the HISR (interruptible context) since we will poll the HW */
	if (psDevContext->eLowPowerState == e_HW_LOW_POWER)
	{
		KM_TurnOffHW(psDevContext);
	}
	QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);


	/* The workqueue waits to be signalled either by the LISR or when a command has been placed in a socket queue */
//	DEBUG_PRINT("psDevContext->eLowPowerState = %d | psDevContext->ui32IdleSocketsFlag = %08x, psDevContext->ui32IdleSockets = %d\n", psDevContext->eLowPowerState, psDevContext->ui32IdleSocketsFlag, psDevContext->ui32IdleSockets);

	/* We hit this situation when doing power management (and only real firwmare will reach it) */
	if (psDevContext->eLowPowerState == e_HW_IDLE)
	{
		/* New incoming command(s) on one socket would trigger HW power restore */
		if (psDevContext->ui32UsedSockets != psDevContext->ui32IdleSockets)
		{
#if ! defined (IMG_KERNEL_MODULE)
			TALPDUMP_ConsoleMessage(psDevContext->sFWSoftImage.hLTPDataRam, "Reactivating the hardware");
#endif
			quartzkm_fnPowerRestore(psDevContext->hDMANDevHandle, psDevContext);
#if ! defined (IMG_KERNEL_MODULE)
			TALPDUMP_ConsoleMessage(psDevContext->sFWSoftImage.hLTPDataRam, "Firmware restored");
#endif
		}
	}

	if (!psDevContext->bSuspendHISR)
	{
		/* Call the kernel-level scheduler */
		eRet = KM_CheckAndSchedule(psDevContext);
		switch (eRet)
		{
			/* Fatal */
		case IMG_ERROR_NOT_INITIALISED:
		case IMG_ERROR_INVALID_ID:
			PRINT("HISR ERROR - Workqueue error (%d), job cannot be performed because major problem occurred\n", eRet);
			break;
			/* Non-fatal */
		case IMG_SUCCESS:
#if ! defined (POLL_FOR_INTERRUPT)
			/* As long as everything is okay, why wouldn't we try again */
			goto issuing_new_command;
#else
			// Scheduled modes _MUST_ try issuing the next command in order to allow other context commands through (the scheduler will require multiple encode commands at a time)
			// This is required for e_4K422_60__1080p420_30 and e_4K422_60__1080p422_30 modes (currently the only eSchedModels defined)
			if (psDevContext->sSchedModel.eSchedModel != e_NO_SCHEDULING_SCENARIO)
				goto issuing_new_command;
#endif
			break;
		case IMG_ERROR_STORAGE_TYPE_EMPTY: /* nothing to do */
			DEBUG_VERBOSE_PRINT("HISR INFO - Socket command queue was empty\n");
			break;
		case IMG_ERROR_MAX_ENCODE_ON_FLY: /* needs to wait */
			DEBUG_PRINT("HISR INFO - Firmware context already reached the maximum number of encode command it can handle at the same time\n");
			break;
		case IMG_ERROR_STORAGE_TYPE_FULL: /* command FIFO full */
			DEBUG_PRINT("HISR INFO - The command FIFO between KM and FW is full, firmware needs more time to process them\n");
			break;
		case IMG_ERROR_INVALID_PARAMETERS: /* no socket object fetched */
			DEBUG_PRINT("HISR INFO - No socket object found - no command(s) sent\n");
			break;
		case IMG_ERROR_DISABLED:
			DEBUG_PRINT("HISR INFO - HW was turned off - no command being sent\n");
			break;
		case IMG_ERROR_COMM_RETRY:
			DEBUG_PRINT("HISR INFO - Scheduling model (%d) needed schedule Idx[%d] = %d -> FW Context Id (%d) to issue an encode\n", psDevContext->sSchedModel.eSchedModel, psDevContext->sSchedModel.ui16ScheduleIdx, psDevContext->sSchedModel.pui32SchedulingOrder[psDevContext->sSchedModel.ui16ScheduleIdx], psDevContext->sSchedModel.pui32SchedulingOrderToFWCtxtId[psDevContext->sSchedModel.pui32SchedulingOrder[psDevContext->sSchedModel.ui16ScheduleIdx]]);
			break;
		default:
			DEBUG_PRINT("HISR WARNING - Unexpected behaviour\n");
			break;
		}
	}
}

/*!
******************************************************************************
*
* @function quartzkm_fnDevKmLisr
* @brief DMAN level function registered to trigger on interrupts coming from the embedded processor of the encoder
* @param hDevHandle Handle on the device context in the DMAN layer
* @param pvDevInstanceData Handle on the device context (KM level)
* @details
* LISR stands for Low Level Interrupt Service Routine, which means closer to the hardware
* and not low-priority. In this function, the content of the interrupt register coming from
* the device is read, and if one has been fired it will service it.
* It also triggers the High Level ISR (ie the workqueue) to dequeue incoming commands
*
******************************************************************************/
static IMG_BOOL quartzkm_fnDevKmLisr (
	IMG_HANDLE				hDevHandle,
    IMG_VOID *				pvDevInstanceData
)
{
	IMG_UINT32 crMultiCoreIntStat;
	VXE_KM_DEVCONTEXT *psContext = (VXE_KM_DEVCONTEXT *)pvDevInstanceData;
	IMG_UINT32 ui32IntsToClear = 0;
	IMG_RESULT eRet;
	
	/* 0 - If interrupts not defined (meaning the context has not been initialised), then... */
	if (!psContext->bInitialised)
	{
		/* Don't signal this device... */
		return IMG_FALSE;
	}

	/* 1 - Read device interrupt status */
	TALREG_ReadWord32(psContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_INT_STAT, &crMultiCoreIntStat);

	/* If the previous page fault has been handled (i.e. not showing in the multipipe_int_stat), we allow the next one to be printed out */
	if (0 == (crMultiCoreIntStat & MASK_QUARTZ_TOP_INT_STAT_MMU_FAULT))
	{
		psContext->bMMUFaultSeen = IMG_FALSE;
	}

	/* 2 - Build the int_clr flag */
	if ((crMultiCoreIntStat & MASK_QUARTZ_TOP_INT_STAT_PROC) == (MASK_QUARTZ_TOP_INT_STAT_PROC))
	{
		/* Embedded proc signalled completion, we will handle it */
		ui32IntsToClear |= MASK_QUARTZ_TOP_INTCLR_PROC;
	}
	if ((crMultiCoreIntStat & MASK_QUARTZ_TOP_INT_STAT_MMU_FAULT) == (MASK_QUARTZ_TOP_INT_STAT_MMU_FAULT))
	{
		/* HW reported a page fault, so we will signal it */
		ui32IntsToClear |= MASK_QUARTZ_TOP_INTCLR_MMU_FAULT;
	}

	/* 3 - Clear interrupt source (the ISR cannot be interrupted while doing so, disable interrupts during the update of the register)... */
	if (0 != ui32IntsToClear)
	{
		quartzdd_IntClear(psContext, ui32IntsToClear);
	}

	/* 4 - If interrupts enabled and embedded processor fired one... */
	if ((crMultiCoreIntStat & MASK_QUARTZ_TOP_INT_STAT_PROC) == (MASK_QUARTZ_TOP_INT_STAT_PROC))
	{
		/* Now dispatch the messages */
		eRet = KM_DispatchFeedback(psContext);
		if (IMG_ERROR_NOT_INITIALISED == eRet)
		{
			/* If psContext is NULL, the isr is in a completely broken state, it is worth a printk() */
			PRINT("ERROR: %s() - Device context not initialized properly\n", __FUNCTION__);
			return IMG_FALSE;
		}

		/* signal the HISR to switch off the hardware */
		if(psContext->eLowPowerState == e_HW_LOW_POWER)
		{
			PRINT("calling DMANKM_ActivateKmHisr\n");
			DMANKM_ActivateKmHisr(psContext->hDMANDevHandle);
		}
		/* Signal this interrupt has been handled... */
		return IMG_TRUE;
	}
	
	if ((crMultiCoreIntStat & MASK_QUARTZ_TOP_INT_STAT_MMU_FAULT) == (MASK_QUARTZ_TOP_INT_STAT_MMU_FAULT))
	{
		/* No need to overload the kernel with message if the page fault has already been signalled */
		if (!psContext->bMMUFaultSeen)
		{
			TALREG_ReadWord32(psContext->sDevSpecs.hQuartzMMUBank, IMG_BUS4_MMU_STATUS0, &psContext->ui32MMUFaultReg0);
			TALREG_ReadWord32(psContext->sDevSpecs.hQuartzMMUBank, IMG_BUS4_MMU_STATUS1, &psContext->ui32MMUFaultReg1);
			psContext->bMMUFaultSeen = IMG_TRUE;
			psContext->bMMUFaultToSignal = IMG_TRUE;
			psContext->bCoreNeedsToClose = IMG_TRUE;
			PRINT("HW page fault. Address 0x%08x%s\n", psContext->ui32MMUFaultReg0 & MASK_IMG_BUS4_MMU_FAULT_ADDR, psContext->ui32MMUFaultReg0 & MASK_IMG_BUS4_MMU_PF_N_RW ? " (PF)" : " (RW)");
			PRINT("MMU STATUS 1 0x%08x\n", psContext->ui32MMUFaultReg1);

			/* disable all interrupts from this device before we start thinking about trying to recover */
			TALREG_WriteWord32(psContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_HOST_INT_ENAB, 0);

			/* Trigger HISR to reset the core and clean up the contexts */
			DMANKM_ActivateKmHisr(psContext->hDMANDevHandle);
		}

		return IMG_TRUE;
	}

	/* No incoming interrupts, don't signal this device... */
	return IMG_FALSE;
}

/*!
******************************************************************************
*
* @function quartzkm_fnDevInit
* @brief Allocate KM level context (+resource bucket) and register it in SYSDEV layer
* @param [in] hDevHandle Handle on the device context in the DMAN layer
* @param [in] hInitConnHandle Handle on the connection context in the DMAN layer
* @param [out] ppvDevInstanceData Reference on the allocated KM level device context
* See definition of #DMANKM_pfnDevInit.
*
******************************************************************************/
static IMG_RESULT quartzkm_fnDevInit (
	IMG_HANDLE					hDevHandle,
	IMG_HANDLE					hInitConnHandle,
    IMG_VOID **					ppvDevInstanceData
)
{
	IMG_RESULT eResult;
	VXE_KM_DEVCONTEXT *psDevContext;
	(void)hInitConnHandle;
	
	/* Allocate device context structure... */
	psDevContext = IMG_MALLOC(sizeof(*psDevContext));
	IMG_ASSERT(psDevContext != IMG_NULL);
	if (psDevContext == IMG_NULL)
	{
		return IMG_ERROR_OUT_OF_MEMORY;
	}
	IMG_MEMSET(psDevContext, 0, sizeof(*psDevContext));

	/* Create the resource bucket associated with the device context */
	eResult = RMAN_CreateBucket(&psDevContext->hResBHandle);

	/* Allow later usage of this allocated device context */
	*ppvDevInstanceData = psDevContext;

	/* Get the device name */
	psDevContext->pszDeviceName = DMANKM_GetDeviceName(hDevHandle);

	/* Open the device using SYSDEV layer, keep the handle on the SYSDEV context */
	eResult = SYSDEVU_OpenDevice(psDevContext->pszDeviceName, &psDevContext->hSysDevHandle);
	IMG_ASSERT(eResult == IMG_SUCCESS);
	if (eResult != IMG_SUCCESS)
	{
		return eResult;
	}

	/* Gain access to the DMAN context, this will be used to signal the HISR from a non-interrupt context */
	psDevContext->hDMANDevHandle = hDevHandle;

	/* Kernel module has not initialised this device yet */
	psDevContext->bInitialised = IMG_FALSE;

	/* SYSDEVU_sInfo entry in as_quartz_device[] and the device context we just created have been linked by SYSDEVU_OpenDevice call */


	eResult = QUARTZKM_Initialise(psDevContext, hDevHandle);
	IMG_ASSERT(eResult == IMG_SUCCESS && "Device init failed");
	if (IMG_SUCCESS != eResult)
	{
		PRINT("%s: Failure reported when initialising device (MMU init, semaphores/mutexes creation, initial setup)\n", __FUNCTION__);
		return eResult;
	}

	/* Return success */
	return IMG_SUCCESS;
}


/*!
******************************************************************************
*
* @function QUARTZKM_SetupScheduling
* @brief Wraps up the setup of some scheduling parameters
* @param psDevContext Quartz device context (created when first connection was opened)
* @return	- IMG_ERROR_CANCELLED if a scheduling model was specified but can't be done
*			- IMG_SUCCES on normal completion
*
******************************************************************************/
IMG_RESULT QUARTZKM_SetupScheduling(VXE_KM_DEVCONTEXT *psDevContext)
{
#ifndef REMOVE_4K1080PARALLEL_SCHEDULING
	IMG_UINT32 ui32SizeNeeded;
	IMG_UINT8 ui8Lp = 0;
#endif

	switch (psDevContext->sSchedModel.eSchedModel)
	{
#ifndef REMOVE_4K1080PARALLEL_SCHEDULING
	case e_4K422_60__1080p420_30:
		/* Generic model information */
		psDevContext->sSchedModel.ui32NumberOfContexts = 2;
		psDevContext->sSchedModel.ui32NumberOfPipes = 3;
		/* Allocation */

		psDevContext->sSchedModel.ui16ScheduleMax = 3;
		psDevContext->sSchedModel.ui16ScheduleIdx = 0;
		ui32SizeNeeded = psDevContext->sSchedModel.ui32NumberOfContexts * ((3/*dynamic arrays of int*/ * sizeof(IMG_UINT32)) + (4/*dynamic arrays of char*/ * sizeof(IMG_UINT8)));
		ui32SizeNeeded += (psDevContext->sSchedModel.ui16ScheduleMax  * sizeof(IMG_UINT32));
		
		psDevContext->sSchedModel.pvAllocation = IMG_MALLOC(ui32SizeNeeded);
		if (NULL == psDevContext->sSchedModel.pvAllocation)
		{
			/* No scheduling model is possible in this case */
			psDevContext->sSchedModel.eSchedModel = e_NO_SCHEDULING_SCENARIO;
			return IMG_ERROR_CANCELLED;
		}

		/* Initial memset */
		IMG_MEMSET(psDevContext->sSchedModel.pvAllocation, 0x0, ui32SizeNeeded);

		/* Arrays setup */
		psDevContext->sSchedModel.pui32CtxFeatures = (IMG_UINT32*)((IMG_BYTE*)psDevContext->sSchedModel.pvAllocation);
		psDevContext->sSchedModel.pui32SchedulingOrder = psDevContext->sSchedModel.pui32CtxFeatures + psDevContext->sSchedModel.ui32NumberOfContexts;


		psDevContext->sSchedModel.pui32SchedulingOrderToFWCtxtId = psDevContext->sSchedModel.pui32SchedulingOrder + psDevContext->sSchedModel.ui16ScheduleMax;
		psDevContext->sSchedModel.pui32RoundRobinWeight = psDevContext->sSchedModel.pui32SchedulingOrderToFWCtxtId + psDevContext->sSchedModel.ui32NumberOfContexts;
		psDevContext->sSchedModel.pui8FirstPipeIdx = (IMG_UINT8*)(psDevContext->sSchedModel.pui32RoundRobinWeight + psDevContext->sSchedModel.ui32NumberOfContexts);
		psDevContext->sSchedModel.pui8LastPipeIdx = psDevContext->sSchedModel.pui8FirstPipeIdx + psDevContext->sSchedModel.ui32NumberOfContexts;
		psDevContext->sSchedModel.pui8RoundRobinThresh = psDevContext->sSchedModel.pui8LastPipeIdx + psDevContext->sSchedModel.ui32NumberOfContexts;
		psDevContext->sSchedModel.pb8ContextAllocated = psDevContext->sSchedModel.pui8RoundRobinThresh + psDevContext->sSchedModel.ui32NumberOfContexts;
		/* Arrays filling */
		/* 4K 4:2:2 @ 60fps */
#ifdef DEBUG_4K1080PARALLEL_MODE
		// The debug version expects a reduced the height of the 4k and 1080 images (but retains the proportionality of pipes) for quicker debug
		// Debug version 4K height = 512, 1080 height = 270
		// The debug version also places 'nop' assembly commands into the code to act as quick identifiers to show threadpipe parallelism in the 4k 1080 cases
		psDevContext->sSchedModel.pui32CtxFeatures[0] = BUILD_VXEKMAPI_FEATURE_FLAG(VXEKMAPI_ENCDIM_LESS_THAN_4K, VXEKMAPI_ENCRES422, VXEKMAPI_FRAMERATE_31_TO_60, 0, 0, 1, 0);
#else
		// The real version is the full 4k
		psDevContext->sSchedModel.pui32CtxFeatures[0] = BUILD_VXEKMAPI_FEATURE_FLAG(VXEKMAPI_ENCDIM_4K_TO_8K, VXEKMAPI_ENCRES422, VXEKMAPI_FRAMERATE_31_TO_60, 0, 0, 1, 0);
#endif		

		psDevContext->sSchedModel.pui32RoundRobinWeight[0] = 0;
		psDevContext->sSchedModel.pui8FirstPipeIdx[0] = 0;
		psDevContext->sSchedModel.pui8LastPipeIdx[0] = 2;
		psDevContext->sSchedModel.pui8RoundRobinThresh[0] = 1;
		/* 1080p 4:2:0 @ 30fps */
		psDevContext->sSchedModel.pui32CtxFeatures[1] = BUILD_VXEKMAPI_FEATURE_FLAG(VXEKMAPI_ENCDIM_LESS_THAN_4K, VXEKMAPI_ENCRES420, VXEKMAPI_FRAMERATE_0_TO_30, 0, 0, 0, 0);
		psDevContext->sSchedModel.pui32RoundRobinWeight[1] = 1;
		psDevContext->sSchedModel.pui8FirstPipeIdx[1] = 0;
		psDevContext->sSchedModel.pui8LastPipeIdx[1] = 0;
		psDevContext->sSchedModel.pui8RoundRobinThresh[1] = 1;



		/* Final setup */
		psDevContext->sSchedModel.pui32SchedulingOrder[0] = 0;
		psDevContext->sSchedModel.pui32SchedulingOrder[1] = 1;
		psDevContext->sSchedModel.pui32SchedulingOrder[2] = 0;

		// These will eventually be filled with Socket Idx values that match the socket that will encode psDevContext->sSchedModel.pui32CtxFeatures[psDevContext->sSchedModel.pui32SchedulingOrder[lp]] (ie. the 4k (0) or 1080k (1) encode)
		for (ui8Lp = 0; ui8Lp < psDevContext->sSchedModel.ui32NumberOfContexts; ui8Lp++)
			psDevContext->sSchedModel.pui32SchedulingOrderToFWCtxtId[ui8Lp] = VXE_KM_SCHEDULING_ORDER_DEFAULT;

		break;

	case e_4K422_60__1080p422_30:
		/* Generic model information */
		psDevContext->sSchedModel.ui32NumberOfContexts = 2;
		psDevContext->sSchedModel.ui32NumberOfPipes = 3;
		/* Allocation */

		psDevContext->sSchedModel.ui16ScheduleMax = 3;
		psDevContext->sSchedModel.ui16ScheduleIdx = 0;
		ui32SizeNeeded = psDevContext->sSchedModel.ui32NumberOfContexts * ((3/*dynamic arrays of int*/ * sizeof(IMG_UINT32)) + (4/*dynamic arrays of char*/ * sizeof(IMG_UINT8)));
		ui32SizeNeeded += (psDevContext->sSchedModel.ui16ScheduleMax  * sizeof(IMG_UINT32));

		psDevContext->sSchedModel.pvAllocation = IMG_MALLOC(ui32SizeNeeded);
		if (NULL == psDevContext->sSchedModel.pvAllocation)
		{
			/* No scheduling model is possible in this case */
			psDevContext->sSchedModel.eSchedModel = e_NO_SCHEDULING_SCENARIO;
			return IMG_ERROR_CANCELLED;
		}

		/* Initial memset */
		IMG_MEMSET(psDevContext->sSchedModel.pvAllocation, 0x0, ui32SizeNeeded);

		/* Arrays setup */
		psDevContext->sSchedModel.pui32CtxFeatures = (IMG_UINT32*)((IMG_BYTE*)psDevContext->sSchedModel.pvAllocation);
		psDevContext->sSchedModel.pui32SchedulingOrder = psDevContext->sSchedModel.pui32CtxFeatures + psDevContext->sSchedModel.ui32NumberOfContexts;

		psDevContext->sSchedModel.pui32SchedulingOrderToFWCtxtId = psDevContext->sSchedModel.pui32SchedulingOrder + psDevContext->sSchedModel.ui16ScheduleMax;
		psDevContext->sSchedModel.pui32RoundRobinWeight = psDevContext->sSchedModel.pui32SchedulingOrderToFWCtxtId + psDevContext->sSchedModel.ui32NumberOfContexts;
		psDevContext->sSchedModel.pui8FirstPipeIdx = (IMG_UINT8*)(psDevContext->sSchedModel.pui32RoundRobinWeight + psDevContext->sSchedModel.ui32NumberOfContexts);
		psDevContext->sSchedModel.pui8LastPipeIdx = psDevContext->sSchedModel.pui8FirstPipeIdx + psDevContext->sSchedModel.ui32NumberOfContexts;
		psDevContext->sSchedModel.pui8RoundRobinThresh = psDevContext->sSchedModel.pui8LastPipeIdx + psDevContext->sSchedModel.ui32NumberOfContexts;
		psDevContext->sSchedModel.pb8ContextAllocated = psDevContext->sSchedModel.pui8RoundRobinThresh + psDevContext->sSchedModel.ui32NumberOfContexts;
		/* Arrays filling */
		/* 4K 4:2:2 @ 60fps */
#ifdef DEBUG_4K1080PARALLEL_MODE
		// The debug version expects a reduced the height of the 4k and 1080 images (but retains the proportionality of pipes) for quicker debug
		// Debug version 4K height = 512, 1080 height = 270
		// The debug version also places 'nop' assembly commands into the code to act as quick identifiers to show threadpipe parallelism in the 4k 1080 cases
		psDevContext->sSchedModel.pui32CtxFeatures[0] = BUILD_VXEKMAPI_FEATURE_FLAG(VXEKMAPI_ENCDIM_LESS_THAN_4K, VXEKMAPI_ENCRES422, VXEKMAPI_FRAMERATE_31_TO_60, 0, 0, 1, 0);
#else
		// The real version is the full 4k
		psDevContext->sSchedModel.pui32CtxFeatures[0] = BUILD_VXEKMAPI_FEATURE_FLAG(VXEKMAPI_ENCDIM_4K_TO_8K, VXEKMAPI_ENCRES422, VXEKMAPI_FRAMERATE_31_TO_60, 0, 0, 1, 0);
#endif		

		psDevContext->sSchedModel.pui32RoundRobinWeight[0] = 0;
		psDevContext->sSchedModel.pui8FirstPipeIdx[0] = 0;
		psDevContext->sSchedModel.pui8LastPipeIdx[0] = 2;
		psDevContext->sSchedModel.pui8RoundRobinThresh[0] = 1;
		/* 1080p 4:2:0 @ 30fps */
		psDevContext->sSchedModel.pui32CtxFeatures[1] = BUILD_VXEKMAPI_FEATURE_FLAG(VXEKMAPI_ENCDIM_LESS_THAN_4K, VXEKMAPI_ENCRES422, VXEKMAPI_FRAMERATE_0_TO_30, 0, 0, 0, 0);
		psDevContext->sSchedModel.pui32RoundRobinWeight[1] = 1;
		psDevContext->sSchedModel.pui8FirstPipeIdx[1] = 0;
		psDevContext->sSchedModel.pui8LastPipeIdx[1] = 0;
		psDevContext->sSchedModel.pui8RoundRobinThresh[1] = 1;
		/* Scheduling order */

		psDevContext->sSchedModel.pui32SchedulingOrder[0] = 0;
		psDevContext->sSchedModel.pui32SchedulingOrder[1] = 1;
		psDevContext->sSchedModel.pui32SchedulingOrder[2] = 0;

		// These will eventually be filled with Socket Idx values that match the socket that will encode psDevContext->sSchedModel.pui32CtxFeatures[psDevContext->sSchedModel.pui32SchedulingOrder[lp]] (ie. the 4k (0) or 1080k (1) encode)
		for (ui8Lp = 0; ui8Lp < psDevContext->sSchedModel.ui32NumberOfContexts; ui8Lp++)
			psDevContext->sSchedModel.pui32SchedulingOrderToFWCtxtId[ui8Lp] = VXE_KM_SCHEDULING_ORDER_DEFAULT;

		break;
#endif
	default:
		/* Unknown scheduling will simply be discarded */
		psDevContext->sSchedModel.eSchedModel = e_NO_SCHEDULING_SCENARIO;
		psDevContext->sSchedModel.pvAllocation = NULL;
		break;
	}

	return IMG_SUCCESS;
}


/*!
******************************************************************************
*
* @function QUARTZKM_Initialise
*
******************************************************************************/
IMG_RESULT QUARTZKM_Initialise(VXE_KM_DEVCONTEXT *psDevContext, IMG_HANDLE hDevHandle)
{
	IMG_RESULT eResult;
	IMG_UINT32 ui32MaxH, ui32MaxW;
	IMG_INT32 i32DevIdx;
	IMG_CHAR szMemSpaceName [128], szSuffix[4];
#if !defined(IMG_KERNEL_MODULE)
	IMG_BOOL bPdumpState;
#endif
#if defined(IMG_KERNEL_MODULE)
	IMG_UINT32 ui32RegVal;
#endif

	IMG_BOOL bRet;

	/* Already initialised, nothing more to do */
	if (psDevContext->bInitialised)
	{
		return IMG_SUCCESS;
	}

	i32DevIdx = get_core_dev_id(psDevContext->pszDeviceName);
	if (i32DevIdx < 0)
	{
		/* Given name could not be found in the list of supported devices */
		return IMG_ERROR_DEVICE_NOT_FOUND;
	}
	psDevContext->sDevSpecs.ui32CoreDevIdx = (IMG_UINT32)i32DevIdx; /*VXE_KM_SUPPORTED_DEVICES < 2^31 - 1*/
#if defined (SYSBRG_NO_BRIDGING)
	if (psDevContext->sDevSpecs.ui32CoreDevIdx == 0)
	{
		szSuffix[0] = '\0';
	}
	else
#endif
	{
		sprintf(szSuffix, "_%d", psDevContext->sDevSpecs.ui32CoreDevIdx);
	}

	sprintf(szMemSpaceName, "REG_QUARTZ_MULTIPIPE%s", szSuffix);
	/* Now that device has been allocated, enable interrupts */
	psDevContext->sDevSpecs.hQuartzMultipipeBank = TAL_GetMemSpaceHandle(szMemSpaceName);
	eResult = quartzdd_Initialise(psDevContext);
	IMG_ASSERT(eResult == IMG_SUCCESS && "Device initialisation failed");
	if (IMG_SUCCESS != eResult)
	{
		return eResult;
	}

	/* Register the function which will clear the KM to FW commumication when hDevHandle will be free'd */
	eResult = RMAN_RegisterResource(psDevContext->hResBHandle, RMAN_DUMMY_ID, quartzkm_OnFreeBucket, hDevHandle, IMG_NULL, IMG_NULL);
	IMG_ASSERT(eResult == IMG_SUCCESS && "Resource registration failed");
	if (IMG_SUCCESS != eResult)
	{
		return eResult;
	}

#if defined (INCLUDE_DEBUG_FEATURES)
	if (0 != debugfs_link_context_to_debugfs(psDevContext))
	{
		return IMG_ERROR_UNEXPECTED_STATE;
	}
#endif

	// Initialise the TAL
	TIMER_START(hardwareduration, "");

#if !defined(IMG_KERNEL_MODULE)
	{
		IMG_UINT32 ui32PdumpFlags;
		/* Pdump-img will only ever occur with non-bridging and non kernel module builds */
		IMG_BOOL bPdump1, bPdump2, bGzippedPdump;
		/* Pdump settings can come from two sources, either environment variables [priority] or command line parameters [considered afterwards] */
		ui32PdumpFlags = TALPDUMP_GetFlags();

		bPdump1 = (getenv("DOPDUMP1") ? IMG_TRUE : ui32PdumpFlags & TAL_PDUMP_FLAGS_PDUMP1 ? IMG_TRUE : IMG_FALSE);
		bPdump2 = (getenv("DOPDUMP2") ? IMG_TRUE : ui32PdumpFlags & TAL_PDUMP_FLAGS_PDUMP2 ? IMG_TRUE : IMG_FALSE);
		bGzippedPdump = (getenv("GZIPPDUMP") ? IMG_TRUE : ui32PdumpFlags & TAL_PDUMP_FLAGS_GZIP ? IMG_TRUE : IMG_FALSE);

		/* Going pdump if at least one of these three is enabled */
		g_bDoingPdump =
			bGzippedPdump ||  /* this condition is removed because it is the default for the sim and it blocks fw logging usage */
			bPdump1 || bPdump2;


		/* Enable the capture in the TAL layer */
		TALPDUMP_SetFlags(
			(bPdump1 ? TAL_PDUMP_FLAGS_PDUMP1 : 0) |
			(bPdump2 ? TAL_PDUMP_FLAGS_PDUMP2 : 0) |
			(bGzippedPdump ? TAL_PDUMP_FLAGS_GZIP : 0) |	/* this sim could force this, which would enable pdump something we do not want with fw logging */
			((bPdump1 || bPdump2) ? (TAL_PDUMP_FLAGS_RES | TAL_PDUMP_FLAGS_PRM) : 0)
			);
	}
#endif

	/* Set the handles on register banks */
	sprintf(szMemSpaceName, "REG_DMAC%s", szSuffix);
	psDevContext->sDevSpecs.hQuartzDMACBank = TAL_GetMemSpaceHandle(szMemSpaceName);
	sprintf(szMemSpaceName, "REG_MMU%s", szSuffix);
	psDevContext->sDevSpecs.hQuartzMMUBank = TAL_GetMemSpaceHandle(szMemSpaceName);
	sprintf(szMemSpaceName, "REG_LTP%s", szSuffix);
	psDevContext->sDevSpecs.hQuartzLTPBank = TAL_GetMemSpaceHandle(szMemSpaceName);
	sprintf(szMemSpaceName, "REG_PROC_DATA_RAM%s", szSuffix);
	psDevContext->sDevSpecs.hLTPDataRam = TAL_GetMemSpaceHandle(szMemSpaceName);
	sprintf(szMemSpaceName, "REG_PROC_INST_RAM%s", szSuffix);
	psDevContext->sDevSpecs.hLTPCodeRam = TAL_GetMemSpaceHandle(szMemSpaceName);
	psDevContext->sDevSpecs.hSysMemId = TAL_GetMemSpaceHandle("MEMSYSMEM");

#if defined (IMG_KERNEL_MODULE)
	/* We will use the core id register to identify the core we are trying to reach */
	TALREG_ReadWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_QUARTZ_CORE_ID, &ui32RegVal);
	if (VXE_KM_QUARTZ_ID != (ui32RegVal & VXE_KM_QUARTZ_ID))
	{
		return IMG_ERROR_DEVICE_NOT_FOUND;
	}


#endif

#if !defined(IMG_KERNEL_MODULE)
	/* Enable the pdump capturing on register banks */
	TALPDUMP_MemSpceCaptureEnable(psDevContext->sDevSpecs.hQuartzMultipipeBank, IMG_TRUE, &bPdumpState);
	TALPDUMP_MemSpceCaptureEnable(psDevContext->sDevSpecs.hQuartzDMACBank, IMG_TRUE, &bPdumpState);
	TALPDUMP_MemSpceCaptureEnable(psDevContext->sDevSpecs.hQuartzMMUBank, IMG_TRUE, &bPdumpState);
	TALPDUMP_MemSpceCaptureEnable(psDevContext->sDevSpecs.hQuartzLTPBank, IMG_TRUE, &bPdumpState);
	TALPDUMP_MemSpceCaptureEnable(psDevContext->sDevSpecs.hLTPDataRam, IMG_TRUE, &bPdumpState);
	TALPDUMP_MemSpceCaptureEnable(psDevContext->sDevSpecs.hLTPCodeRam, IMG_TRUE, &bPdumpState);
	TALPDUMP_MemSpceCaptureEnable(psDevContext->sDevSpecs.hSysMemId, IMG_TRUE, &bPdumpState);

	/* Start the capture on specified regions */
	TALPDUMP_CaptureStart(".");
#endif

#if defined (SYSBRG_NO_BRIDGING)
	if (g_bCoreSR)
#endif
	{
		/* Soft reset the whole core - is this necessary? */
		TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, MASK_QUARTZ_TOP_CORE_SOFT_RESET);
		TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, 0);
	}

	/* Access core revision and configuration */
	if (km_populate_hw_config(psDevContext) != IMG_SUCCESS)
	{
		PRINT("Unable to get encoder hardware config from registers \n");
		return IMG_ERROR_DEVICE_NOT_FOUND;
	}
	
	/* Store the global parameters in the device context (we don't rely on the global parameters anymore) */
	psDevContext->sDevSpecs.ui32MMUFlags = g_ui32MMUFlags;
	psDevContext->sDevSpecs.ui32MMUTileStride = g_ui32MMUTileStride;
	psDevContext->sDevSpecs.bKMPPM = g_bKMPPM;


	psDevContext->sSchedModel.eSchedModel = g_eSchedulingModel;
	eResult = QUARTZKM_SetupScheduling(psDevContext);
	if (IMG_SUCCESS != eResult)
	{
		PRINT("\nCannot initialise Quartz KM scheduling model. Execution will carry on with best-effort sharing\n");
	}
	psDevContext->bCoreNeedsToClose = IMG_FALSE;

	/** Reset procedure for multipipe/general level features: cores, proc, MMU **/
	eResult = quartzkm_ResetCore(psDevContext);
	if (eResult != IMG_SUCCESS)
	{
		return eResult;
	}

#if !defined(IMG_KERNEL_MODULE)
	TALPDUMP_ConsoleMessage(TAL_MEMSPACE_ID_ANY, pszDriverVersion);
#endif

	QUARTZ_KM_LockMutex(g_sMutexDevKm, MTX_SUBCLASS_DEVKM);
	/** MMU template initialisation: **/
	bRet = MMUDeviceMemoryInitialise(psDevContext);
	QUARTZ_KM_UnlockMutex(g_sMutexDevKm);
	if (IMG_FALSE == bRet)
	{
		PRINT("\nERROR: Could not initialise MMU with selected parameters!\n");
		return IMG_ERROR_NOT_INITIALISED;
	}

	/** MMU HW init (using the previously created heap template) **/
	if (IMG_FALSE == MMUDeviceMemoryHWSetup(psDevContext))
	{
		PRINT("HW device memory setup failed\n");
		return IMG_ERROR_NOT_INITIALISED;
	}

	psDevContext->sDevSpecs.sHWConfig.ui32CoreRev &= (MASK_QUARTZ_TOP_QUARTZ_MAINT_REV | MASK_QUARTZ_TOP_QUARTZ_MINOR_REV | MASK_QUARTZ_TOP_QUARTZ_MAJOR_REV);

	/* The simplified version of the device supported features is used for checking when opening a new stream */
	psDevContext->sDevSpecs.ui32SupportedFeaturesFlag = F_ENCODE(F_DECODE(psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig3, QUARTZ_TOP_QUARTZ_FBC_SUPPORTED), VXEKMAPI_FBC_FEATURE);
	psDevContext->sDevSpecs.ui32SupportedFeaturesFlag |= F_ENCODE(F_DECODE(psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig3, QUARTZ_TOP_QUARTZ_TILE_COLUMN_SUPPORTED), VXEKMAPI_COLUMN_STORE_ON);

	if (psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig & MASK_QUARTZ_TOP_QUARTZ_444_SUPPORTED)
	{
		psDevContext->sDevSpecs.ui32SupportedFeaturesFlag |= F_ENCODE(VXEKMAPI_ENCRES444, VXEKMAPI_ENCRES_FEATURE);
	}
	else if (psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig & MASK_QUARTZ_TOP_QUARTZ_422_SUPPORTED)
	{
		psDevContext->sDevSpecs.ui32SupportedFeaturesFlag |= F_ENCODE(VXEKMAPI_ENCRES422, VXEKMAPI_ENCRES_FEATURE);
	}
	ui32MaxH = 1 << F_EXTRACT(psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig2, QUARTZ_TOP_QUARTZ_LOG2_MAX_PICTURE_HEIGHT);
	ui32MaxW = 1 << F_EXTRACT(psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig2, QUARTZ_TOP_QUARTZ_LOG2_MAX_PICTURE_WIDTH);
	if (ui32MaxW >= VXE_LIMIT_WIDTH_4K && ui32MaxH >= VXE_LIMIT_HEIGTH_4K)
	{
		psDevContext->sDevSpecs.ui32SupportedFeaturesFlag |= F_ENCODE(VXEKMAPI_ENCDIM_4K_TO_8K, VXEKMAPI_ENCDIM_FEATURE);
	}

#if !defined (IMG_KERNEL_MODULE)
	/* Pdump comments with core details */
	{
		char szPdumpComment[80];
		SPRINT(szPdumpComment, "Core revision: 0x%08X", psDevContext->sDevSpecs.sHWConfig.ui32CoreRev);
		TALPDUMP_Comment(psDevContext->sDevSpecs.hQuartzMultipipeBank, szPdumpComment);
		SPRINT(szPdumpComment, "Core Config  : 0x%08X", psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig);
		TALPDUMP_Comment(psDevContext->sDevSpecs.hQuartzMultipipeBank, szPdumpComment);
		SPRINT(szPdumpComment, "Core Config 2: 0x%08X", psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig2);
		TALPDUMP_Comment(psDevContext->sDevSpecs.hQuartzMultipipeBank, szPdumpComment);
		SPRINT(szPdumpComment, "Core Config 3: 0x%08X", psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig3);
		TALPDUMP_Comment(psDevContext->sDevSpecs.hQuartzMultipipeBank, szPdumpComment);
		SPRINT(szPdumpComment, "Line Store Config: 0x%08X", psDevContext->sDevSpecs.sHWConfig.ui32LineStoreConfig);
		TALPDUMP_Comment(psDevContext->sDevSpecs.hQuartzMultipipeBank, szPdumpComment);
		SPRINT(szPdumpComment, "Number of cores: %d", QUARTZ_KM_GetNumberOfPipes(psDevContext));
		TALPDUMP_Comment(psDevContext->sDevSpecs.hQuartzMultipipeBank, szPdumpComment);
	}

	/* Poll on core revision for pdump */
	TALREG_Poll32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_QUARTZ_CORE_REV, TAL_CHECKFUNC_ISEQUAL, psDevContext->sDevSpecs.sHWConfig.ui32CoreRev, 0x00FF0000, 1, 1);
	TALREG_Poll32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_QUARTZ_CORE_REV, TAL_CHECKFUNC_GREATEREQ, psDevContext->sDevSpecs.sHWConfig.ui32CoreRev, 0x0000FF00, 1, 1);
#endif

	/* Reset the registers used for communication between KM and FW for the feedback */
	TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_PRODUCER, 0x0);
	TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_CONSUMER, 0x0);
#if ! defined (IMG_KERNEL_MODULE)
	/* in a test environment we call tell the firmware to only use the specified number of pipes, regardless of how many pipes it can see */
	TALPDUMP_Comment(psDevContext->sDevSpecs.hLTPDataRam, "Tell Firmware how many pipes to expect");
	TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FW_BOOTSTATUS, QUARTZ_KM_GetNumberOfPipes(psDevContext));
#else
	TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FW_BOOTSTATUS, 0x0);
#endif
	TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_SCRATCHREG_IDLE, 0x0);
	TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_READER, 0x0);
	TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_WRITER, 0x0);
	TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FW_FEEDBACK, 0x0);

#if FW_TRACE
	TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_TRACE_BASEADDR, 0x0);
	TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_TRACE_SIZE, 0x0);
	TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_TRACE_WOFF, 0x0);
#endif

	/* Reset the socket objects to IMG_NULL to be 100% sure that this is a fresh start */
	{
		IMG_UINT8 ui8Index;
		for (ui8Index = 0; ui8Index < VXE_MAX_SOCKETS; ++ui8Index)
		{
			psDevContext->apsDeviceSockets[ui8Index] = IMG_NULL;
		}
	}

	/* Concurrent accesses protection */
	eResult = QUARTZ_KM_CreateMutex(&psDevContext->hCommTxLock);
	IMG_ASSERT(eResult == IMG_SUCCESS && "TX lock mutex creation failed");
	if (eResult != IMG_SUCCESS)
	{
		return IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE;
	}
	eResult = QUARTZ_KM_CreateMutex(&psDevContext->hCommAccessStreamsLock);
	IMG_ASSERT(eResult == IMG_SUCCESS && "RX lock mutex creation failed");
	if (eResult != IMG_SUCCESS)
	{
		return IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE;
	}

	// We can call CheckAndSchedule from both User Mode and HISR thread so need to protect it with a Mutex
	eResult = QUARTZ_KM_CreateMutex(&psDevContext->hCheckAndScheduleLock);
	IMG_ASSERT(eResult == IMG_SUCCESS && "Check and schedule mutex creation failed");
	if (eResult != IMG_SUCCESS)
	{
		return IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE;
	}


#if defined (POLL_FOR_INTERRUPT)
	/* Control structure for the ISR polling thread */
	psDevContext->sDevSpecs.g_sLISRControl.psKMDevContext = NULL;
	psDevContext->sDevSpecs.g_sLISRControl.bExit = IMG_TRUE;
	psDevContext->sDevSpecs.g_sLISRControl.bSignalHISR = IMG_TRUE;
	psDevContext->sDevSpecs.KM_LISRThreadHandle = NULL;
#endif

	psDevContext->bInitialised = IMG_TRUE;

	/*
	* The kernel device and resource has been allocated and initialised,
	* next step is to setup the firmware but not immediately
	* Indeed, the device can be opened/closed several time
	* before the actual process begins, so we only insure that
	* no the firmware has not been initialised here
	*/
	psDevContext->sFWSoftImage.bInitialized = IMG_FALSE;
	psDevContext->sFWSoftImage.bPopulated = IMG_FALSE;

	return IMG_SUCCESS;
}


/*!
******************************************************************************
*
* @function quartzkm_fnDevDeinit
* @brief Deallocate device context, bucket, disable interrupts and close device at SYSDEV layer
* @param hDevHandle Handle on the device context in the DMAN layer
* @param hInitConnHandle Handle on the connection context in the DMAN layer
* @param pvDevInstanceData Handle on the KM level device context
* See definition of #DMANKM_pfnDevDeinit.
*
******************************************************************************/
static IMG_VOID quartzkm_fnDevDeinit (
	IMG_HANDLE					hDevHandle,
	IMG_HANDLE					hInitConnHandle,
    IMG_VOID *					pvDevInstanceData
)
{
#if defined (SYSBRG_NO_BRIDGING)
	IMG_BOOL bRet;
#endif
	VXE_KM_DEVCONTEXT *	psContext = (VXE_KM_DEVCONTEXT *)pvDevInstanceData;
	(void)hDevHandle;
	(void)hInitConnHandle;

	/* If the interrupt was defined then it is also safe to clear interrupts and reset the core... */
	if (psContext->bInitialised)
	{
		IMG_UINT32 crImgQuartzIntenab;

		/* Disable interrupts... */
		quartzdd_Deinitialise(psContext);

		/* Disable interrupts on Quartz core (isn't it done already with previous lines?) */
		TALREG_ReadWord32(psContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_HOST_INT_ENAB, &crImgQuartzIntenab);
		crImgQuartzIntenab &= ~MASK_QUARTZ_TOP_HOST_INTEN_PROC;
		TALREG_WriteWord32(psContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_HOST_INT_ENAB, crImgQuartzIntenab);

		/* Clear interrupt - just in case */
		TALREG_WriteWord32(psContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_INT_CLEAR, MASK_QUARTZ_TOP_INTCLR_PROC);
	}

#if defined (POLL_FOR_INTERRUPT)
	/* HISR has been destroyed by previous calls, we should not try to signal it */
	psContext->sDevSpecs.g_sLISRControl.bSignalHISR = IMG_FALSE;
#endif

#if defined (SYSBRG_NO_BRIDGING)
	bRet = KM_WaitForDeviceIdle(psContext);
	if (!bRet)
	{
		PRINT("ERROR:%s - Device did not reach idle state in time\n", __FUNCTION__);
		/*No return code from this function, therefore we carry on*/
	}
#endif

	/* This will call #quartzkm_OnFreeBucket */
	RMAN_DestroyBucket(psContext->hResBHandle);

	/* If we opened a device... */
	if (psContext->hSysDevHandle != IMG_NULL)
	{
		/* Then we close it in SYSDEV */
		SYSDEVU_CloseDevice(psContext->hSysDevHandle);
	}

	/* The device context (KM level) is not used anymore */
	IMG_FREE(pvDevInstanceData);
}

/*!
******************************************************************************
*
* @function quartzkm_fnDevConnect
* @brief Create the resource bucket used for the KM <-> device connection
* @param hConnHandle Handle on the connection context in the DMAN layer
* @param pvDevInstanceData Handle on the KM level device context
* @param ppvDevConnectionData Reference on the allocated connection data context
* See definition of #DMANKM_fnDevConnect.
*
******************************************************************************/
static IMG_RESULT quartzkm_fnDevConnect (
	IMG_HANDLE					hConnHandle,
    IMG_VOID *					pvDevInstanceData,
    IMG_VOID **					ppvDevConnectionData
)
{
	IMG_UINT32 ui32ConnId;
	IMG_RESULT result;
	VXE_KM_DEVCONTEXT *psDevContext;
	VXE_KM_CONNDATA *connData = (VXE_KM_CONNDATA *) IMG_MALLOC(sizeof(VXE_KM_CONNDATA));

	if (!pvDevInstanceData)
	{
		PRINT("%s() - ERROR: Device context does not exist\n", __FUNCTION__);
	}
	else
	{
		/* We don't know the connection id until the connection has been opened */
		psDevContext = (VXE_KM_DEVCONTEXT *)pvDevInstanceData;

		ui32ConnId = DMANKM_GetConnIdFromHandle(hConnHandle);
		/* Store it for further use when we need to link socket to connection */
		psDevContext->ui32ConnId = ui32ConnId;
	}

	/* Create a bucket for the resources... */
	result = RMAN_CreateBucket(&connData->hResBHandle);
	IMG_ASSERT(result == IMG_SUCCESS);
	if (result != IMG_SUCCESS)
	{
		return result;
	}

	*ppvDevConnectionData = connData;
	/* Return success... */
	return IMG_SUCCESS;
}

/*!
******************************************************************************
*
* @function quartzkm_fnDevDisconnect
* @brief Disconnect the KM from the device and free allocated structure
* @param hConnHandle Handle on the connection context in the DMAN layer
* @param pvDevInstanceData Handle on the KM level device context
* @param pvDevConnectionData Handle on the connection data context
* @param eDisconnType Disconnection type (unused)
* See definition of #DMANKM_pfnDevDisconnect.
*
******************************************************************************/
static IMG_RESULT quartzkm_fnDevDisconnect (
	IMG_HANDLE					hConnHandle,
    IMG_VOID *					pvDevInstanceData,
    IMG_VOID *					pvDevConnectionData,
	DMANKM_eDisconnType			eDisconnType
)
{
	IMG_RESULT eRet;
	VXE_KM_DEVCONTEXT *psDevContext;
	VXE_KM_CONNDATA *connData = (VXE_KM_CONNDATA *)pvDevConnectionData;
	(void)eDisconnType;

	if (pvDevInstanceData)
	{
		/* Clear the connection id since we are closing the connection (even though the free would do it) */
		psDevContext = (VXE_KM_DEVCONTEXT *)pvDevInstanceData;
		psDevContext->ui32ConnId = 0;
	}

	/* Destroying the bucket will cleanup all the socket which are opened */
	RMAN_DestroyBucket(connData->hResBHandle);

	/* After destroying the bucket associated with the connection context, free the connection data context */
	IMG_FREE(pvDevConnectionData);

	/* Insure a complete disconnection between KM and the device */
	eRet = DMANKM_DevDisconnectComplete(hConnHandle);
	IMG_ASSERT(eRet == IMG_SUCCESS);

	/* Return success... */
	return eRet;
}


/*!
******************************************************************************
*
* @function QUARTZKM_fnDevRegister
* @brief Register the callbacks used in the DMAN layer with the device specific ones 
* @param Reference on the device context in the DMAN layer
* See definition of #DMANKM_pfnDevRegister.
*
******************************************************************************/
IMG_RESULT QUARTZKM_fnDevRegister (
    DMANKM_sDevRegister *		psDevRegister
)
{
	psDevRegister->ui32ConnFlags = DMAN_CFLAG_SHARED;

	psDevRegister->pfnDevInit			= quartzkm_fnDevInit;
	psDevRegister->pfnDevDeinit			= quartzkm_fnDevDeinit;

	psDevRegister->pfnDevConnect		= quartzkm_fnDevConnect;
	psDevRegister->pfnDevDisconnect		= quartzkm_fnDevDisconnect;

	psDevRegister->pfnDevKmHisr			= quartzkm_fnDevKmHisr;
	psDevRegister->pfnDevKmLisr			= quartzkm_fnDevKmLisr;

	psDevRegister->pfnDevPowerPostS0	= quartzkm_fnPowerRestore;
	psDevRegister->pfnDevPowerPreS5		= quartzkm_fnPowerSave;

	/* Return success... */
	return IMG_SUCCESS;
}


/*************************************************** MODULE RELATED ********************************************************/

#if !defined(SYSBRG_NO_BRIDGING)

#include <linux/module.h>
#include <linux/version.h>

#ifdef TAL_TARGET_HEADER_NAME
#include TAL_TARGET_HEADER_NAME
#else
#error TAL_TARGET_HEADER_NAME has to be defined in order to use TAL light
#endif

#include <api_common.h>
#include "memmgr_api_quartz_rpc.h"
#include "vxe_km_api_quartz_rpc.h"

static SYSBRGKM_sAPIInfo asAPIInfo[] = {
	SYS_BRIDGE(HOSTUTILS)
	SYS_BRIDGE(MEMMGR)
};

#include "vxe_sysctl.h"
#else
#define __init
#define __exit
#endif


#if defined (SYSBRG_NO_BRIDGING)
/* in non-bridging, define a global string that can contain the path to the TAL config file */
char *g_szTalConfigFile = "quartz.cfg";
#endif

/* Make sure the build time define is valid */
STATIC_ASSERT(VXE_KM_SUPPORTED_DEVICES <= VXE_KM_MAX_DEVICE_SUPPORTED);
SYSDEVU_sInfo as_quartz_device[] =
{
#if 1
	{0, SYS_DEVICE("QUARTZ", QUARTZ, IMG_FALSE)},
#else
	{NULL, {"QUARTZ_0", &QUARTZKM_fnDevRegister, IMG_FALSE}},
#endif
	{NULL, {"QUARTZ_1", &QUARTZKM_fnDevRegister, IMG_FALSE}},
	{NULL, {"QUARTZ_2", &QUARTZKM_fnDevRegister, IMG_FALSE}},
	{NULL, {"QUARTZ_3", &QUARTZKM_fnDevRegister, IMG_FALSE}},
	{NULL, {"QUARTZ_4", &QUARTZKM_fnDevRegister, IMG_FALSE}},
	{NULL, {"QUARTZ_5", &QUARTZKM_fnDevRegister, IMG_FALSE}},
	{NULL, {"QUARTZ_6", &QUARTZKM_fnDevRegister, IMG_FALSE}},
	{NULL, {"QUARTZ_7", &QUARTZKM_fnDevRegister, IMG_FALSE}},
};
/* This assert will trigger is the above array is not initialised properly */
STATIC_ASSERT((sizeof(as_quartz_device) / sizeof(as_quartz_device[0])) == VXE_KM_MAX_DEVICE_SUPPORTED);

#if defined (IMG_KERNEL_MODULE)
#include <linux/errno.h>
#endif

int __init init_quartz(void)
{
	IMG_RESULT eRet;
	IMG_UINT32 i;
#if defined (IMG_KERNEL_MODULE)
	IMG_UINT32 j;
	int ret;
#endif

#if defined (SYSBRG_NO_BRIDGING)
#if ! defined (TARGET_CONF_BY_HEADER_FILE)
	char *szIPSetup = IMG_NULL;
	char *szFilePath = NULL;

	/* Look for an environment variable for the config file. */
	szFilePath = getenv("TOPAZHP_TAL_CONFIG");

	/* Check to see if we have been given a different path to the config file */
	if (g_szTalConfigFile && !szFilePath)
	{
		szFilePath = g_szTalConfigFile;
	}

	if (szFilePath)
	{
		TARGET_SetConfigFile(szFilePath);
	}
#endif /*! defined (TARGET_CONF_BY_HEADER_FILE)*/

	eRet = SYSENVKM_Initialise();
	if (eRet != IMG_SUCCESS)
	{
		PRINT("ERROR: %s() failed to initialise SYSENVKM! \n", __FUNCTION__);
		IMG_ASSERT(eRet == IMG_SUCCESS);
		return IMG_ERROR_GENERIC_FAILURE;
	}

#if ! defined (TARGET_CONF_BY_HEADER_FILE)
	if (szIPSetup)
	{
#if defined(SYSBRG_NO_BRIDGING)
		TARGET_SetConfigFile(szIPSetup);
#else
		PRINT("WARNING: %s() - -ipconfig not supported when compiling with TAL_PORT_FWRK\n", __FUNCTION__);
#endif
	}
#endif /*! defined (TARGET_CONF_BY_HEADER_FILE)*/
#endif /*defined(SYSBRG_NO_BRIDGING)*/

	eRet = QUARTZ_KM_CreateMutex(&g_sMutexDevKm);
	if (IMG_SUCCESS != eRet)
	{
#if defined (IMG_KERNEL_MODULE)
		ret = ENOLCK;
		goto init_mutex_creation_failed;
#else
		return eRet;
#endif
	}

	// Register quartz driver to SYSDEV..
	eRet = SYSDEVU_RegisterDriver(&as_quartz_device[0]);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Driver registration failed");
#if defined (IMG_KERNEL_MODULE)
		ret = EUNATCH;
		goto init_driver_registration_failed;
#else
		return eRet;
#endif
	}


	for (i = 0; i < VXE_KM_SUPPORTED_DEVICES; i++)
	{
		// Register quartz device to SYSDEV
		eRet = SYSDEVU_RegisterDevice(&as_quartz_device[i]);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "Device registration failed");
#if defined (IMG_KERNEL_MODULE)
			ret = ENODEV;
			goto init_device_registration_failed;
#else
			return eRet;
#endif
		}

#if ! defined(SYSBRG_NO_BRIDGING)
		gsTargetConfig.pasDevices[i].pvKmRegBase = as_quartz_device[i].pui32KmRegBase;
		gsTargetConfig.pasDevices[i].ui32RegSize = as_quartz_device[i].ui32RegSize;
	} /*for (dev = 0; dev < VXE_KM_SUPPORTED_DEVICES; dev++)*/

	eRet = TARGET_Initialise(&gsTargetConfig);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Target initialisation failed");
		ret = EFAULT;
		goto init_target_registration_failed;
	}

	// register SYSBRG APIs.
	for (i = 0; i<(sizeof(asAPIInfo)/sizeof(SYSBRGKM_sAPIInfo)); i++)
	{
		eRet = SYSBRGU_RegisterAPI(&asAPIInfo[i]);
		if (IMG_SUCCESS != eRet)
		{
			ret = EINTR;
			i = VXE_KM_SUPPORTED_DEVICES;
			goto init_sysbrg_api_register;
		}
	}

#if defined (VXE_KM_SYSCTL_SUPPORT)
	vxe_img_sysctl_header = img_vxe_km_register_sysctl_table();
	if (NULL == vxe_img_sysctl_header)
	{
		ret = ENOMEM;
		i = VXE_KM_SUPPORTED_DEVICES;
		goto init_sysbrg_api_register;
	}
#endif

#if defined (INCLUDE_DEBUG_FEATURES)
	create_debugfs_vxekm();
#endif

#else /*! defined(SYSBRG_NO_BRIDGING)*/
	} /*for (dev = 0; dev < VXE_KM_SUPPORTED_DEVICES; dev++)*/

	eRet = TALSETUP_Initialise();
	if (eRet != IMG_SUCCESS)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Unable to initialise TAL");
		return IMG_ERROR_FATAL;
	}

	eRet = TARGET_Initialise(IMG_NULL);
	if (eRet != IMG_SUCCESS)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Unable to initialise TARGET");
		return IMG_ERROR_DEVICE_UNAVAILABLE;
	}
#endif /*! defined(SYSBRG_NO_BRIDGING)*/

	return IMG_SUCCESS;

#if defined (IMG_KERNEL_MODULE)
init_sysbrg_api_register:
	for (i = 0; i<(sizeof(asAPIInfo) / sizeof(SYSBRGKM_sAPIInfo)); i++)
	{
		SYSBRGU_RemoveAPI(&asAPIInfo[i]);
	}
init_target_registration_failed:
	TARGET_Deinitialise(&gsTargetConfig);
init_device_registration_failed:
	for (j = 0; j < i; j++)
	{
		SYSDEVU_UnRegisterDriver(&as_quartz_device[j]);
		SYSDEVU_UnRegisterDevice(&as_quartz_device[j]);
	}
init_driver_registration_failed:
	QUARTZ_KM_DestroyMutex(g_sMutexDevKm);
init_mutex_creation_failed:
	PRINT("VXE init reported %i\n", ret);
	return -ret;
#endif
}

void __exit exit_quartz(void) {
	IMG_RESULT eRet;
	IMG_UINT32 i;


#if defined (IMG_KERNEL_MODULE)
	for (i = 0; i < VXE_KM_SUPPORTED_DEVICES; i++)
	{
		IMG_HANDLE hDevHandle;
		VXE_KM_DEVCONTEXT *psVxeDevContext;

		/* Guard against trying to unload a module if this device is still in use */
		eRet = DMANKM_LocateDevice(as_quartz_device[i].sDevInfo.pszDeviceName, &hDevHandle);
		if (IMG_SUCCESS == eRet)
		{
			psVxeDevContext = (VXE_KM_DEVCONTEXT *)DMANKM_GetDevInstanceData(hDevHandle);
			if (NULL != psVxeDevContext && IMG_TRUE == psVxeDevContext->bInitialised)
			{
				/* We can only inform about this situation (in case of forced removal [default], nothing can be done to prevent it) */
				PRINT("ERROR: Device context is still active when trying to unload a module. Reboot will probably be needed to sort out the situation.\n");
			}
		}
	}
#endif /*defined (IMG_KERNEL_MODULE)*/

	for (i = 0; i < VXE_KM_SUPPORTED_DEVICES; i++)
	{
		/* Unregister quartz driver and device from SYSDEV */
		eRet = SYSDEVU_UnRegisterDriver(&as_quartz_device[i]);
		IMG_ASSERT(IMG_SUCCESS == eRet && "SYSDEVU_UnRegisterDriver failed");

		eRet = SYSDEVU_UnRegisterDevice(&as_quartz_device[i]);
		IMG_ASSERT(IMG_SUCCESS == eRet && "SYSDEVU_UnRegisterDevice failed");

#if ! defined(SYSBRG_NO_BRIDGING)
		/* Unregister the device from the TAL layer (also destroy the memspace) */
		TAL_DeviceUnRegister(as_quartz_device[i].sDevInfo.pszDeviceName);
#endif

	} /*for (dev = 0; dev < VXE_KM_SUPPORTED_DEVICES; dev++)*/

#if ! defined(SYSBRG_NO_BRIDGING)
#if defined (VXE_KM_SYSCTL_SUPPORT)
	img_vxe_km_unregister_sysctl_table(vxe_img_sysctl_header);
#endif

#if defined (INCLUDE_DEBUG_FEATURES)
	destroy_debugfs_vxekm();
#endif

	// unregister SYSBRG APIs.
	for (i = 0; i<(sizeof(asAPIInfo)/sizeof(SYSBRGKM_sAPIInfo)); i++)
	{
		SYSBRGU_RemoveAPI(&asAPIInfo[i]);
	}


#if ! defined(SYSBRG_NO_BRIDGING)
	TARGET_Deinitialise(&gsTargetConfig);
#else
	TARGET_Deinitialise(IMG_NULL);
#endif

	QUARTZ_KM_DestroyMutex(g_sMutexDevKm);
#else /*! defined(SYSBRG_NO_BRIDGING)*/
	QUARTZ_KM_DestroyMutex(g_sMutexDevKm);

	/* Stop the abstraction layer...*/
	SYSENVKM_Deinitialise();
#endif /*! defined(SYSBRG_NO_BRIDGING)*/
}


#if !defined(SYSBRG_NO_BRIDGING)
module_init(init_quartz);
module_exit(exit_quartz);

MODULE_LICENSE("GPL v2");
MODULE_DESCRIPTION("Imagination Technologies encoder");
MODULE_AUTHOR("Imagination Technologies Ltd");
#endif
