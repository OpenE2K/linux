/*!
 *****************************************************************************
 *
 * @File       vxe_KM.c
 * @Title      Quartz kernel module core functions
 * @Description    This file contains the QUARTZ Kernel Mode component.
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


#include "img_errors.h"
#if ! defined (IMG_KERNEL_MODULE)
#include "osa.h"
#define msleep(x) OSA_ThreadSleep(x)
#endif
#include "tal.h"

#include "vxe_fw_if.h"
#include "quartz_device_km.h"
#include "quartz_mmu.h"
#include "vxe_KM.h"
#include "vxe_common.h"
#include "coreflags.h"

#include <dman_api_km.h>
#include <rman_api.h>
#include <quartz_device_km.h>
#include <talmmu_api.h>

// Memory manager, kernel side
#include <memmgr_km.h>

/* These globals are set when the kernel module is first initialized */
/* Extern declarations */

// The contents of this file provide basic dummy Kernel Mode/FW/Hardware behaviour
// Don't use linked lists because KM/FW/HW memory limitations will not allow it.


#include "e5500_public_regdefs.h"
#include "ltp_regs.h"

// Clock frequency measurement code
#if defined(IMG_KERNEL_MODULE)
#include <linux/time.h>
#endif
#define FREQ_CHECK_DELAY_MS 100 /* default "1" is not enough, Bug 116681 */



#if defined (POLL_FOR_INTERRUPT)
extern IMG_VOID KM_StartISRThread(VXE_KM_DEVCONTEXT *psDevContext);
#define POLL_COUNT		(10000)
#define POLL_TIMEOUT	(4000)
#endif


IMG_CHAR *apszCmd[VXE_COMMAND_COUNT] =
{
	"VXE_COMMAND_ENCODE_FRAME",
	"VXE_COMMAND_ACTIVATE_CONTEXT",
	"VXE_COMMAND_ABORT_CONTEXT",
	"VXE_COMMAND_DEACTIVATE_CONTEXT",
	"VXE_COMMAND_FENCE",
	"VXE_COMMAND_INSERT_HEADER",
	"VXE_COMMAND_UPDATE_PARAMETERS",
	"VXE_COMMAND_FIRMWARE_READY"
};




/****************************************************** DEFINES ************************************************************/


/* Mutexes used to safely and concurently share the kernel module */
#define COMM_LOCK_STREAMS					(0x01)	/*When accessing apsDeviceSockets[] concurrently */
#define COMM_LOCK_TX						(0x02)	/*When accessing sFWSoftImange.ui16ActiveContextMask concurrently (command being issued/seen) */
#define COMM_LOCK_BOTH						(COMM_LOCK_STREAMS | COMM_LOCK_TX)



/****************************************************** TYPEDEF ************************************************************/


/************************************************ PRIVATE VARIABLES ********************************************************/
/* Change the following depending on which method is to be used */
#if SECURE_MMU
static LOAD_METHOD g_eLoadMethod = LTP_LOADMETHOD_COPY;
#else
static LOAD_METHOD g_eLoadMethod = LTP_LOADMETHOD_DMA;
#endif

/************************************************ PRIVATE FUNCTIONS ********************************************************/

static IMG_RESULT quartz_SetupFirmware(VXE_KM_DEVCONTEXT* psDevContext, VXE_CODEC eCodec);
static IMG_UINT16 km_applyFeaturesWeight(IMG_UINT32 ui32FeaturesFlag);

IMG_RESULT QUARTZ_KM_CreateMutex(IMG_HANDLE *  phMutexHandle)
{
#if defined(IMG_KERNEL_MODULE)
	struct mutex  *psMutex;            //!< Linux mutex.

    psMutex = IMG_MALLOC(sizeof(struct mutex));
    IMG_ASSERT(psMutex != IMG_NULL);
    if (psMutex == IMG_NULL)
    {
        return IMG_ERROR_OUT_OF_MEMORY;
    }

    /* Initialise mutex */
    mutex_init(psMutex);

    /* Return the mutex structure...*/
    *phMutexHandle = (IMG_HANDLE) psMutex;
#else
	SYSOSKM_CreateMutex(phMutexHandle);
#endif
    return IMG_SUCCESS;
}

IMG_VOID QUARTZ_KM_DestroyMutex(IMG_HANDLE  hMutexHandle)
{
#if defined(IMG_KERNEL_MODULE)
	IMG_ASSERT(hMutexHandle != IMG_NULL);
    if (hMutexHandle == IMG_NULL)
    {
        return;
    }
   /* Destroy mutex */
    mutex_destroy((struct mutex  *)hMutexHandle);

    /* Free structure...*/
    IMG_FREE(hMutexHandle);
#else
	SYSOSKM_DestroyMutex(hMutexHandle);
#endif

}



#if defined(IMG_KERNEL_MODULE)
/* QUARTZ_KM_LockMutex & QUARTZ_KM_UnlockMutex implemented as macros in kernel builds */
#else
/*!
******************************************************************************

 @Function                QUARTZ_KM_LockMutex

******************************************************************************/
IMG_VOID QUARTZ_KM_LockMutex(IMG_HANDLE  hMutexHandle, IMG_UINT subclass)
{
	SYSOSKM_LockMutexNested(hMutexHandle, subclass);
}
/*!
******************************************************************************

 @Function                QUARTZ_KM_LockMutex

******************************************************************************/
IMG_VOID QUARTZ_KM_UnlockMutex(IMG_HANDLE  hMutexHandle)
{
	SYSOSKM_UnlockMutex(hMutexHandle);
}
#endif

/**
* \fn km_Lock
* \brief Get hands on the mutex(es) protecting the communication FW/KM
* \params psDevContext Pointer on the KM device context
* \params ui32Flags Which way should be locked (either TX, RX or both)
**/
static IMG_VOID km_Lock(VXE_KM_DEVCONTEXT* psDevContext, IMG_UINT32 ui32Flags)
{
	if (ui32Flags & COMM_LOCK_STREAMS)
	{
		QUARTZ_KM_LockMutex(psDevContext->hCommAccessStreamsLock, MTX_SUBCLASS_COMSTREAMS);
	}

	if (ui32Flags & COMM_LOCK_TX)
	{
		QUARTZ_KM_LockMutex(psDevContext->hCommTxLock, MTX_SUBCLASS_COMTX);
	}
}


/**
* \fn km_Unlock
* \brief Release mutex(es) protecting the communication FW/KM
* \params psDevContext Pointer on the KM device context
* \params ui32Flags Which way should be released (either TX, RX or both)
**/
static IMG_VOID km_Unlock(VXE_KM_DEVCONTEXT* psDevContext, IMG_UINT32 ui32Flags)
{
	if (ui32Flags & COMM_LOCK_TX)
	{
		QUARTZ_KM_UnlockMutex(psDevContext->hCommTxLock);
	}

	if (ui32Flags & COMM_LOCK_STREAMS)
	{
		QUARTZ_KM_UnlockMutex(psDevContext->hCommAccessStreamsLock);
	}
}


/**
* \fn km_WaitOnAbortSync
* \brief When the kernel module is being cleaned up, wait for stream abort
* \param psSocket Socket which is going to be aborted
* \return	- IMG_SUCCESS on normal completion
*			- IMG_ERROR_TIMEOUT if the abort acknowledgement got lost
**/
static IMG_RESULT km_WaitOnAbortSync(VXE_KM_COMM_SOCKET *psSocket)
{
	IMG_RESULT eRet;
	IMG_UINT32 ui32Retries = 0;
	IMG_UINT32 ui32Timeout = CALC_ABORT_TIMEOUT(psSocket->psDevContext->sDevSpecs.sHWConfig.ui32ClkFreqkHz);

	/* Abort is always followed by a fence so just wait for the fence */
	ui32Retries = 0;
	while (0 == (VXE_KM_STREAM_EVENTS_FENCE_END_ABORT & psSocket->ui32StreamStateFlags))
	{
		//PRINT("+SYSOSKM_WaitEventObject, stream %i\n", psSocket->ui8FWCtxtId);
		msleep(ui32Timeout);
		eRet = SYSOSKM_WaitEventObject(psSocket->hFWMessageAvailable_Sem, IMG_FALSE);
		//PRINT("-SYSOSKM_WaitEventObject, stream %i\n", psSocket->ui8FWCtxtId);

		/* Signal user in case of timeout */
		if (ui32Retries > WAIT_FOR_ABORT_RETRIES)
		{
			PRINT("Timeout waiting for stream abort acknowledgement [even flag %08x]\n", psSocket->ui32StreamStateFlags);
			return IMG_ERROR_TIMEOUT;
		}

		/* Failed so increase counter */
		if (eRet != IMG_SUCCESS)
		{
			ui32Retries++;
		}
	}

	/* Abort completed in time */
	return IMG_SUCCESS;
}

/**
* \fn km_AbortAllContexts
* \brief 
* \param psDevContext Device 
**/
IMG_VOID km_AbortAllContexts(VXE_KM_DEVCONTEXT* psDevContext)
{
	/* assuming something has gone wrong mark all contexts as deactivated and send feedback up indicating this */
	IMG_UINT32 ui32CurrentSocket;
	VXE_KM_COMM_SOCKET *psSocket;
	VXE_KM_FW_SOFT_IMAGE* psFWContext = &psDevContext->sFWSoftImage;

	/* There has been a page fault so all active contexts are lost */
	/* Marking each one as having had an irregular abort should force the user mode processes to clean up */
	for (ui32CurrentSocket = 0; ui32CurrentSocket < VXE_MAX_SOCKETS; ++ui32CurrentSocket)
	{
		/* Find the already openned socket from the device context */
		psSocket = psDevContext->apsDeviceSockets[ui32CurrentSocket];
		/* Is this socket active ? */
		if (psSocket)
		{
			psSocket->b8StreamAborted = IMG_TRUE;
			psSocket->bStreamShutdown = IMG_TRUE;
			psSocket->ui32StreamStateFlags |= VXE_KM_STREAM_EVENTS_IRREGULAR_ABORT;

			// Signal this semaphore to wake up any threads that are waitining for firmware action
			SYSOSKM_SignalEventObject(psSocket->hFWMessageAvailable_Sem);
		}
	}

	if (psFWContext && psFWContext->bInitialized)
	{	
		LTP_Deinitialize(psFWContext);
	}
}

/**
* \fn km_SocketIsIdle
* \brief When we poll for interrupts, we want to re-arrange the multi-threaded execution path to prevent poll timeout
* \params psSocket Socket object to be checked
* \details
* This function could be deleted because in essence we could insert more information in the command feedbacks
* to have more intel on the hardware behaviour. However this would add more logic in the kernel, which we do not
* need when using properly wired interrupts in an fully integrated environment. To avoid adding this unrequired
* logic, we have this function that will be in charge of delaying the recorded operations when we #POLL_FOR_INTERRUPT.
**/
static IMG_BOOL km_SocketIsIdle(VXE_KM_COMM_SOCKET *psSocket)
{
	return (psSocket->ui32CmdSent == psSocket->ui32AckRecv);
}

/**
* \fn km_WaitOnSocketDeactivate
* \brief Wait for all outstanding messages on a socket to be acknowledged after a deactivate has been sent (assumes no new messages will be sent)
* \param psSocket Socket which is going to be aborted
* \return	- IMG_SUCCESS on normal completion
*			- IMG_ERROR_TIMEOUT if the abort acknowledgement got lost
**/
static IMG_RESULT km_WaitOnSocketDeactivate(VXE_KM_COMM_SOCKET *psSocket)
{
	IMG_RESULT eRet;
	IMG_UINT32 ui32Retries = 0;
	IMG_UINT32 ui32Timeout = CALC_ABORT_TIMEOUT(psSocket->psDevContext->sDevSpecs.sHWConfig.ui32ClkFreqkHz);

	/* wait while there is a deactivae in flight */
	while ((VXE_KM_STREAM_EVENTS_DEACTIVATE_SENT & psSocket->ui32StreamStateFlags) && !km_SocketIsIdle(psSocket))
	{
		//PRINT("+SYSOSKM_WaitEventObject, stream %i\n", psSocket->ui8FWCtxtId);
		msleep(ui32Timeout);
		eRet = SYSOSKM_WaitEventObject(psSocket->hFWMessageAvailable_Sem, IMG_FALSE);
		//PRINT("-SYSOSKM_WaitEventObject, stream %i\n", psSocket->ui8FWCtxtId);

		/* Signal user in case of timeout */
		if (ui32Retries > WAIT_FOR_ABORT_RETRIES)
		{
			PRINT("Timeout waiting for the stream to be deactivated. HW is locked up [even flag %08x]\n", psSocket->ui32StreamStateFlags);
			return IMG_ERROR_TIMEOUT;
		}

		/* Failed so increase counter */
		if (eRet != IMG_SUCCESS)
		{
			ui32Retries++;
		}
	}

	/* Deactivate completed in time */
	return IMG_SUCCESS;
}


/**
* \brief Check that every stream has completed processing its feedback
* \param apsSockets Array of socket pointers
* \return	- IMG_TRUE if at least one socket has pending feedback
*			- IMG_FALSE if all feedback has been processed
*/
static IMG_BOOL km_CommIsIdle(VXE_KM_COMM_SOCKET **apsSockets)
{
	IMG_UINT32 ui32SocketNum;
	VXE_KM_COMM_SOCKET *psSocket = IMG_NULL;

	for (ui32SocketNum = 0; ui32SocketNum < VXE_MAX_SOCKETS; ui32SocketNum++)
	{
		psSocket = apsSockets[ui32SocketNum];
		if (psSocket && !km_SocketIsIdle(psSocket))
		{
			return IMG_FALSE;
		}
	}

	return IMG_TRUE;
}


/**
* \fn km_SocketFBfifoIsEmpty
* \brief Wraps up the feedback FIFO fullness check
* \params psSocket Reference on socket object
**/
static IMG_BOOL km_SocketFBfifoIsEmpty(VXE_KM_COMM_SOCKET *psSocket)
{
	return (psSocket->ui8OutgoingFIFOProducer == psSocket->ui8OutgoingFIFOConsumer);
}


/**
* \fn km_SocketCmdFIFOIsEmpty
* \brief Wraps up the command FIFO fullness check
* \params psSocket Reference on socket object
**/
static IMG_BOOL km_SocketCmdFIFOIsEmpty(VXE_KM_COMM_SOCKET *psSocket)
{
	return (psSocket->ui8CmdQueueProducer == psSocket->ui8CmdQueueConsumer);
}


/**
* \fn km_GetFeedbackConsumer
* \brief Wraps up #FW_REG_FEEDBACK_CONSUMER access
* \returns Content of bits [16..20] from FW_REG_FEEDBACK_CONSUMER
**/
static IMG_UINT32 km_GetFeedbackConsumer(VXE_KM_DEVCONTEXT *psDevContext)
{
	IMG_UINT32 ui32RegContent;
	TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_CONSUMER, &ui32RegContent);
	return F_EXTRACT(ui32RegContent, FW_FEEDBACK_CONSUMER_ID);
}


/**
* \fn km_GetFeedbackProducer
* \brief Wraps up #FW_REG_FEEDBACK_PRODUCER access
* \returns Content of bits [16..20] from FW_REG_FEEDBACK_PRODUCER
**/
static IMG_UINT32 km_GetFeedbackProducer(VXE_KM_DEVCONTEXT *psDevContext)
{
	IMG_UINT32 ui32RegContent;
	TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_PRODUCER, &ui32RegContent);
	return F_EXTRACT(ui32RegContent, FW_FEEDBACK_PRODUCER_ID);
}


/**
* \fn km_GetFeedbackProducer_LowLatency
* \returns Content of bits [17] from FW_REG_FEEDBACK_PRODUCER (bit 17 is used to wake up the queue in case of a low latency change)
**/
static IMG_UINT32 km_GetFeedbackProducer_LowLatency(VXE_KM_DEVCONTEXT *psDevContext)
{
	IMG_UINT32 ui32RegContent;
	TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_PRODUCER, &ui32RegContent);

	return F_EXTRACT(ui32RegContent, FW_FEEDBACK_PRODUCER_LOWLATENCYBITS);
}

/**
* \brief To prevent kernel lock-up on error condition, abort the stream
* \param psSocket Stream to abort
*/
static void km_unlock_by_abort(VXE_KM_COMM_SOCKET *psSocket)
{
	/* Following an error condition, we flag the socket for abort */
	psSocket->b8StreamAborted = IMG_TRUE;
	/* This abort is abnormal */
	psSocket->ui32StreamStateFlags |= VXE_KM_STREAM_EVENTS_IRREGULAR_ABORT;
	/* We want to unlock user-mode driver waiting on feedback, which will act on the abort feedback */
	SYSOSKM_SignalEventObject(psSocket->hFWMessageAvailable_Sem);
}

/**
* \brief Handle the error case where the kernel stream is aborted because of internal errors
* \param psSocket Stream to check
* \return
*	- IMG_SUCCESS under normal circumstances
*	- IMG_ERROR_GENERIC_FAILURE if an abnormal abort condition has been identified
*/
static IMG_RESULT km_handle_abnornal_abort(VXE_KM_COMM_SOCKET *psSocket)
{
	IMG_BOOL bAbnormalAbort;

	/* If the stream has been aborted irregularly, flag an error */
	bAbnormalAbort = psSocket->b8StreamAborted && (VXE_KM_STREAM_EVENTS_IRREGULAR_ABORT == (psSocket->ui32StreamStateFlags & VXE_KM_STREAM_EVENTS_IRREGULAR_ABORT));
	if (bAbnormalAbort)
	{
		/* Abnormal abort, is catched by caller */
		return IMG_ERROR_GENERIC_FAILURE;
	}

	/* No abornal abort, but a regular abort may be on flight */
	return IMG_SUCCESS;
}

/**
* \brief Handle the error case where the kernel stream is aborted because of internal errors
* \param psSocket Stream to check
* \return
*	- IMG_SUCCESS under normal circumstances
*	- IMG_ERROR_GENERIC_FAILURE if an abnormal abort condition has been identified
*/
IMG_RESULT km_populate_hw_config(VXE_KM_DEVCONTEXT *psDevContext)
{
	IMG_RESULT eRet;

	if (psDevContext->sDevSpecs.sHWConfig.ui32CoreId)
	{
		// HW_CAPS has already been filled in, no need to re-run
		return IMG_SUCCESS;
	}

	eRet = TALREG_ReadWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_QUARTZ_CORE_ID, &psDevContext->sDevSpecs.sHWConfig.ui32CoreId);
	if ((IMG_SUCCESS != eRet) || ((psDevContext->sDevSpecs.sHWConfig.ui32CoreId & 0xffff0000) != 0x04070000))
	{
		IMG_ASSERT(eRet == IMG_SUCCESS);
		IMG_ASSERT((psDevContext->sDevSpecs.sHWConfig.ui32CoreId & 0xffff0000) == 0x04070000);
		return eRet;
	}

	eRet = TALREG_ReadWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_QUARTZ_CORE_REV, &psDevContext->sDevSpecs.sHWConfig.ui32CoreRev);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS);
		return eRet;
	}

	eRet = TALREG_ReadWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_QUARTZ_CONFIG, &psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS);
		return eRet;
	}
	eRet = TALREG_ReadWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_QUARTZ_CONFIG_2, &psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig2);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS);
		return eRet;
	}
	eRet = TALREG_ReadWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_QUARTZ_CONFIG_3, &psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig3);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS);
		return eRet;
	}
	eRet = TALREG_ReadWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_QUARTZ_PROC_CONFIG, &psDevContext->sDevSpecs.sHWConfig.ui32ProcConfig);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS);
		return eRet;
	}
	eRet = TALREG_ReadWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_QUARTZ_LINE_STORE_CONFIG, &psDevContext->sDevSpecs.sHWConfig.ui32LineStoreConfig);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS);
		return eRet;
	}


// Clock frequency measurement code
#if defined(IMG_KERNEL_MODULE)
		{
			// Our KERNEL builds are only targeted at linux - so this is safe
			struct timespec64 LTPUploadfwStartTime = { 0, 0 };
			struct timespec64 LTPUploadfwEndTime = { 0, 0 };
			IMG_UINT32 ui32HWTimerStart, ui32HWTimerEnd, ui32ElapsedTime;
			IMG_UINT32 ui32Tmp;
			TALREG_ReadWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_IDLE_PWR_MAN, &ui32Tmp);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_IDLE_PWR_MAN, 0);

			TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_CYCLE_COUNTER_CTRL, F_ENCODE(0, QUARTZ_TOP_CYCLE_COUNTER_ENABLE));
			TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_CYCLE_COUNTER, 0);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_CYCLE_COUNTER_CTRL, F_ENCODE(1, QUARTZ_TOP_CYCLE_COUNTER_ENABLE));

			eRet = TALREG_ReadWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_CYCLE_COUNTER, &ui32HWTimerStart);
			if (IMG_SUCCESS != eRet)
			{
				IMG_ASSERT(eRet == IMG_SUCCESS);
				return eRet;
			}

			ktime_get_real_ts64(&LTPUploadfwStartTime);

			/* wait for some timer ticks */
			mdelay(FREQ_CHECK_DELAY_MS);

			eRet = TALREG_ReadWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_CYCLE_COUNTER, &ui32HWTimerEnd);
			if (IMG_SUCCESS != eRet)
			{
				IMG_ASSERT(eRet == IMG_SUCCESS);
				return eRet;
			}

			ktime_get_real_ts64(&LTPUploadfwEndTime);

			TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_IDLE_PWR_MAN, ui32Tmp);


			ui32ElapsedTime = ((LTPUploadfwEndTime.tv_sec - LTPUploadfwStartTime.tv_sec) * 1000000) + (LTPUploadfwEndTime.tv_nsec - LTPUploadfwStartTime.tv_nsec) / 1000;

			/* save and print the current LTP Clk Freq */
			psDevContext->sDevSpecs.sHWConfig.ui32ClkFreqkHz = (1000 * (ui32HWTimerEnd - ui32HWTimerStart)) / ui32ElapsedTime;
			DEBUG_PRINT("LTP Clk Freq: %d kHz\n", psDevContext->sDevSpecs.sHWConfig.ui32ClkFreqkHz);
}
#else
{
	// Registers return zero with Sim, so set to a default Sim value
	psDevContext->sDevSpecs.sHWConfig.ui32ClkFreqkHz = FAKE_SIM_FREQ_MAX_KHZ;
}
#endif


	return IMG_SUCCESS;
}

/**
* \brief Send the command to the firmware, called by #KM_SendCommandToFW
* \param [in] psSocket Stream issuing the command
* \param [in] eCommand First word of the command
* \param [in] ui32DevMemBlock Second word of the command
* \param [in] ui32CommandData Third word of the command
* \param [out] pui32CmdSeqNum Placeholder for the last command's word, holding unique command identifier
* \return
*	- IMG_ERROR_COMM_COMMAND_NOT_QUEUED if stream can't accept more commands
*	- IMG_ERROR_FATAL if the command type is unrecognised
*	- IMG_ERROR_COMM_RETRY if the stream command bufer can't be accessed
*	- IMG_SUCCESS on normal completion
*/
static IMG_RESULT km_SendCommandToFW(VXE_KM_COMM_SOCKET *psSocket, IMG_UINT32 eCommand, IMG_UINT32 ui32DevMemBlock, IMG_UINT32 ui32CommandData, IMG_UINT32 *pui32CmdSeqNum)
{
	IMG_UINT32 ui32CommandType, ui32CommandId;
	IMG_UINT32* pui32QueueSlot = IMG_NULL;

	/* If the socket buffer is already full, we can exit this function and signal the UM context that it has to deal with the problem */
	if ((psSocket->ui8CmdQueueProducer + 1) % VXE_KM_COMMAND_BUFFER_SIZE == psSocket->ui8CmdQueueConsumer)
	{
		return IMG_ERROR_COMM_COMMAND_NOT_QUEUED;
	}

	ui32CommandType = (eCommand &~MASK_FW_COMMAND_WB_INTERRUPT) & (MASK_FW_COMMAND_COMMAND_TYPE >> SHIFT_FW_COMMAND_COMMAND_TYPE);
	if (ui32CommandType >= VXE_COMMAND_COUNT)
	{
		/* Unrecognised command is being sent, return error. The caller would not do that under normal circumstances therefore we don't abort the stream */
		return IMG_ERROR_FATAL;
	}

	/*
	* At this point, we have a chance of seing our command put in the command FIFO.
	* If we are sending an ACTIVATE_CONTEXT command, <ui32DevMemBlock> will contain
	* the virtual address
	*/

    if (psSocket->ui8CmdQueueProducer > VXE_KM_COMMAND_BUFFER_SIZE)
    {
        /*ui8CmdQueueProducer is out of range - data corruption*/
        return IMG_ERROR_FATAL;
    }

	/* Queue the command in the same way it would be issued to the HW FIFO */
	pui32QueueSlot = &psSocket->aui32KernelCmdQueue[psSocket->ui8CmdQueueProducer * VXE_KM_COMMAND_BUFFER_WIDTH];
	if (!pui32QueueSlot)
	{
		return IMG_ERROR_COMM_RETRY;
	}

	if ((psSocket->ui32StreamStateFlags & VXE_KM_STREAM_EVENTS_DEACTIVATE_SENT) && (F_DECODE(eCommand, FW_COMMAND_COMMAND_TYPE) != VXE_COMMAND_ACTIVATE_CONTEXT))
	{
		/* once a deactivate has been sent the firmware cannot receive any other commands for this context */
		return IMG_ERROR_DISABLED;
	}

	/* Was will be the next command id? */
	ui32CommandId = psSocket->psDevContext->ui32LastCmdID;

	switch (F_DECODE(eCommand, FW_COMMAND_COMMAND_TYPE))
	{
	case VXE_COMMAND_ACTIVATE_CONTEXT:
		/* When reactivating a context, it is not being aborted anymore */
		psSocket->ui32StreamStateFlags = 0;
		/* Whenever a socket is sending a command, it gets out of the abort state (even though it is to signal an abort command) */
		psSocket->b8StreamAborted = IMG_FALSE;
		break;
	case VXE_COMMAND_ABORT_CONTEXT:
		/* An explicit abort command is being requested by upper layers */
		psSocket->ui32StreamStateFlags |= VXE_KM_STREAM_EVENTS_NORM_ABORT_HIGH;

		if (psSocket->sPendingAbort.bAbortPending)
		{
			/* Caller only needs to have this information */
			ui32CommandId = psSocket->sPendingAbort.ui32UniqueCmdId;
			/* This is not an expected behaviour since it should have been filtered by the low-level driver. We still provide a correct return path to user-mode */
			goto stream_new_command_end;
		}

		/* Stream will need to be aborted ASAP by the workqueue with the correct abort information */
		psSocket->sPendingAbort.ui32Command1stWord = eCommand | F_ENCODE(psSocket->ui8FWCtxtId, FW_COMMAND_SOCKET_ID);
		psSocket->sPendingAbort.ui32Command2ndWord = ui32CommandData;
		psSocket->sPendingAbort.ui32Command3rdWord = ui32DevMemBlock;
		psSocket->sPendingAbort.ui32UniqueCmdId = ui32CommandId;
		psSocket->sPendingAbort.bAbortPending = IMG_TRUE;

		/* An abort sequence is ended by a fence command so user-space will know exactly when it is safe to destroy the context */
		psSocket->psDevContext->ui32LastCmdID = (psSocket->psDevContext->ui32LastCmdID + 1) & CMD_ID_MASK; /*fence is a new command*/
	
		ui32CommandId = psSocket->psDevContext->ui32LastCmdID;

		/* Alter the parameters on the stack and let the normal flow insert the fence */
		eCommand = F_INSERT(eCommand, VXE_COMMAND_FENCE, FW_COMMAND_COMMAND_TYPE) | MASK_FW_COMMAND_WB_INTERRUPT;
		ui32CommandData = F_ENCODE(ui32CommandId, VXE_FENCE_UNIQUE_ID) | MASK_VXE_FENCE_IS_END_OF_ABORT;
		ui32DevMemBlock = 0;

		break;
	case VXE_COMMAND_DEACTIVATE_CONTEXT:
		psSocket->ui32StreamStateFlags |= VXE_KM_STREAM_EVENTS_DEACTIVATE_SENT;

		/* Trying to issue a deactivate command on top of an already deactivated socket */
		if (0 == (psSocket->psDevContext->sFWSoftImage.ui16ActiveContextMask & (1 << psSocket->ui8FWCtxtId)))
		{
			/* we need to fake an ACK to the usermode for this */
			IMG_UINT8 ui8NewProducer;

			DEBUG_PRINT("\nDeactivating an already inactive context. Stream is scheduled for complete shutdown\n");
			psSocket->bStreamShutdown = IMG_TRUE;

			/* Check the socket FIFO state */
			ui8NewProducer = psSocket->ui8OutgoingFIFOProducer + 1;
			if (ui8NewProducer == FEEDBACK_FIFO_MAX_COMMANDS)
			{
				ui8NewProducer = 0;
			}

			if (ui8NewProducer == psSocket->ui8OutgoingFIFOConsumer)
			{
				/* Flag the stream about it */
				psSocket->ui32StreamStateFlags |= VXE_KM_STREAM_EVENTS_FEEDBACK_LOST;
				DEBUG_VERBOSE_PRINT("The KM to UM level feedback FIFO is full, the feedback is lost\n");
			}
			else
			{
				/* Add the command in the feedback FIFO */
				IMG_UINT32* pui32FIFOSlot = &psSocket->aui32OutgoingFIFO[psSocket->ui8OutgoingFIFOProducer * FEEDBACK_FIFO_WORD_PER_COMMANDS];
				if (pui32FIFOSlot)
				{
					pui32FIFOSlot[0] = F_ENCODE(VXE_FWMSG_ACK, FW_FEEDBACK_MSG_TYPE) | F_ENCODE(VXE_COMMAND_DEACTIVATE_CONTEXT, FW_FEEDBACK_COMMAND_TYPE);
					pui32FIFOSlot[1] = 0;

					/* Feedback successfully added */
					psSocket->ui8OutgoingFIFOProducer = ui8NewProducer;

				}
			}
			// Signal that a new message is available for the context
			SYSOSKM_SignalEventObject(psSocket->hFWMessageAvailable_Sem);

		}
		break;
	}

	/* Increment the command counter only now because there are cases where no new command will be issued */
	psSocket->psDevContext->ui32LastCmdID = (psSocket->psDevContext->ui32LastCmdID + 1) & CMD_ID_MASK; /*fence is a new command*/

	if (!psSocket->bStreamShutdown)
	{
		DEBUG_PRINT("\nQueuing %s command for FW context %i (WB 0x%x)\n", apszCmd[ui32CommandType], psSocket->ui8FWCtxtId, ui32CommandId);

		pui32QueueSlot[0] = eCommand | F_ENCODE(psSocket->ui8FWCtxtId, FW_COMMAND_SOCKET_ID);
		pui32QueueSlot[1] = ui32CommandData; // == ui32CmdData for the FW
		pui32QueueSlot[2] = ui32DevMemBlock; // == ui32CmdExtraData for the FW
		pui32QueueSlot[3] = ui32CommandId; // == ui32WBFromHost for the FW

		/* Wrap around the maximum number of commands */
		psSocket->ui8CmdQueueProducer = (psSocket->ui8CmdQueueProducer + 1) % VXE_KM_COMMAND_BUFFER_SIZE;

		/* Sending a command makes this context active now */
		psSocket->psDevContext->sFWSoftImage.ui16ActiveContextMask |= (1 << psSocket->ui8FWCtxtId);
	}

stream_new_command_end:
	if (pui32CmdSeqNum)
	{
		*pui32CmdSeqNum = ui32CommandId;
	}

	return IMG_SUCCESS;
}



/************************************************* PUBLIC FUNCTIONS ********************************************************/
IMG_RESULT KM_InformLowPower(VXE_KM_DEVCONTEXT *psDevContext);
IMG_VOID quartzkm_fnPowerSave(IMG_HANDLE hDevHandle, IMG_VOID *pvDevInstanceData);
IMG_VOID quartzkm_fnPowerRestore(IMG_HANDLE hDevHandle, IMG_VOID *pvDevInstanceData);


/**
* \fn KM_WaitForDeviceIdle
* \brief Wait for a device to have nothing left to do
* \param psDevContext Device to be checked
* \return IMG_TRUE if the device could successfully reach its idle state in time, IMG_FALSE otherwise
**/
IMG_BOOL KM_WaitForDeviceIdle(VXE_KM_DEVCONTEXT* psDevContext)
{
	IMG_BOOL bRet;
	IMG_INT32 i32Attempts = WAIT_FOR_ABORT_RETRIES;
	IMG_INT32 i32SleepTime = CALC_ABORT_TIMEOUT(psDevContext->sDevSpecs.sHWConfig.ui32ClkFreqkHz);

	/* Wait for the previous shutdown procedure to complete! */
	if (psDevContext->eLowPowerState == e_HW_LOW_POWER)
	{
		/* First: give a chance to the workqueue to finish what it started */
		km_Lock(psDevContext, COMM_LOCK_BOTH);
		km_Unlock(psDevContext, COMM_LOCK_BOTH);

		while (i32Attempts >= 0)
		{
			bRet = km_CommIsIdle(psDevContext->apsDeviceSockets);
			if (bRet)
			{
				break;
			}
			else
			{
				/* Yield CPU control */
				msleep(i32SleepTime);
			}
			i32Attempts--;
		}


		i32Attempts = WAIT_FOR_ABORT_RETRIES;
		while (psDevContext->eLowPowerState != e_HW_IDLE)
		{
			msleep(i32SleepTime);
			i32Attempts--;
			if (i32Attempts < 0)
			{
				break;
			}
		}

		if (i32Attempts < 0 || !km_CommIsIdle(psDevContext->apsDeviceSockets))
		{
			return IMG_FALSE;
		}
	}

	return IMG_TRUE;
}


/**
* \fn KM_CheckAndSchedule
* \brief If any outstanding command extracted from the work queue can be executed, process it
* \params psDevContext Pointer on the KM device context
* \return	- IMG_SUCCESS if the command has been dequeued and put in the HW FIFO
*			- IMG_ERROR_NOT_INITIALISED if there is a problem with the device context
*			- IMG_ERROR_INVALID_PARAMETERS if there is a problem with the socket object
*			- IMG_ERROR_STORAGE_TYPE_EMPTY if the socket command queue is empty
*			- IMG_ERROR_COMM_COMMAND_NOT_QUEUED if the socket command queue is full
*			- IMG_ERROR_INVALID_ID if the socket command FIFO slot cannot be accessed
**/
IMG_RESULT KM_CheckAndSchedule(VXE_KM_DEVCONTEXT *psDevContext)
{
	VXE_KM_COMM_SOCKET		*psSocket = IMG_NULL;
	/* Select one context that will issue the command */
	IMG_UINT32				ui32SelectedContext = 0;
	/* Perform the insertion is the HW FIFO only if it is possible */
	IMG_UINT32				*pui32QueueSlot = IMG_NULL;
	VXE_COMMAND_ID			eCmdId;
	IMG_RESULT				eRet = IMG_SUCCESS;
	/* Compute the slot in LTP data RAM where to write to (update after each write) */
	IMG_UINT32 ui32OffsetToWriteTo;
	IMG_UINT32 ui32CommandFIFOProducer;
	IMG_UINT32 ui32CommandFIFOConsumer;
	IMG_UINT32 ui32NewFIFOCommandProducer;

	/* Scheduling in performed on a round robin basis */
	IMG_UINT32 *g_aui32Weights = &psDevContext->aui32RoundRobinWeights[0];
	IMG_UINT32 ui32Weight = 0;
	IMG_UINT32 ui32CurrentSocket;

	/** 1 - Device context checks **/
	if (!psDevContext || psDevContext->bInitialised != IMG_TRUE || psDevContext->sFWSoftImage.bInitialized != IMG_TRUE)
	{
		/* Something went wrong with the device context init */
		return IMG_ERROR_NOT_INITIALISED;
	}

	QUARTZ_KM_LockMutex(psDevContext->hCheckAndScheduleLock, MTX_SUBCLASS_CHECKANDSCHED);

	/*
	* We are accessing apsDeviceSockets to identify the stream sending the next command.
	* When opening a new stream, access to the device context is protected against concurrent
	* accesses hapenning at the same time. After having returned from the open() call,
	* each user mode process will have a single socket object assigned to, there are no more
	* risk of concurrent accesses to it. When it will be remove from the device context structure,
	* On stream destruction, the count of socket in use will be decremented at the end of clean-up,
	* as an atomic decrement instruction (no strem opening is expected to sneak in between and
	* corrupting this counter).
	*/

	/* If we are running in a specific mode */
	if (e_NO_SCHEDULING_SCENARIO != psDevContext->sSchedModel.eSchedModel)
	{
		IMG_UINT32 ui32SockIdx = psDevContext->sSchedModel.pui32SchedulingOrderToFWCtxtId[psDevContext->sSchedModel.pui32SchedulingOrder[psDevContext->sSchedModel.ui16ScheduleIdx]];

		if (VXE_KM_SCHEDULING_ORDER_DEFAULT != ui32SockIdx)
		{
			psSocket = psDevContext->apsDeviceSockets[ui32SockIdx];
			if (psSocket)
			{
				if (psSocket->ui8CmdQueueConsumer != psSocket->ui8CmdQueueProducer)
				{
					ui32SelectedContext = psSocket->ui8FWCtxtId;
				}
				else
				{
					psSocket = NULL;
				}
			}
		}
		else
		{
			psSocket = NULL;
		}
	}

	if (NULL == psSocket)
	{
		/* KM scheduler want to select the next socket to issue a command through the command FIFO */
		for (ui32CurrentSocket = 0; ui32CurrentSocket < VXE_MAX_SOCKETS; ++ui32CurrentSocket)
		{
			/* Find the already openned socket from the device context */
			psSocket = psDevContext->apsDeviceSockets[ui32CurrentSocket];
			/* Does this socket have anything to send? */
			if (psSocket)
			{
				if (psSocket->ui8CmdQueueConsumer != psSocket->ui8CmdQueueProducer)
				{
					/* Favoritise this socket */
					g_aui32Weights[ui32CurrentSocket]++;
					if (g_aui32Weights[ui32CurrentSocket] > ui32Weight)
					{
						/*
						* Since we will pick another context, the previous selected one will
						* be granted additional interest from the scheduler for the next
						* selection loop.
						*/
						if (ui32SelectedContext != ui32CurrentSocket)
						{
							g_aui32Weights[ui32SelectedContext]++;
						}
						/*
						* Since the socket gained interest from the scheduler, it will potentially
						* be elected in the end, so we reduce its "waiting time" directly to avoid
						* its infinite selection.
						* The new weight to beat is the value before the decrement, so that in case
						* of equality amongts several weights, the first one will be selected.
						*/
						ui32Weight = g_aui32Weights[ui32CurrentSocket]--;
						ui32SelectedContext = ui32CurrentSocket;
					}
				}
				else if ((psDevContext->sDevSpecs.bKMPPM) && km_SocketIsIdle(psSocket))
				{
					/* This socket does not have any command to issue and none in flight, it is considered idle */
					psSocket->bStreamIdle = IMG_TRUE;
				}
			}
		}
	}

	psSocket = psDevContext->apsDeviceSockets[ui32SelectedContext];
	if (!psSocket)
	{
		/* Check if a socket has been left opened but not selected by the scheduling algorithm */
		for (ui32CurrentSocket = 0; ui32CurrentSocket < VXE_MAX_SOCKETS; ++ui32CurrentSocket)
		{
			psSocket = psDevContext->apsDeviceSockets[ui32CurrentSocket];
			if (psSocket)
				break;
		}

		if (!psSocket)
		{
			/* No socket are openned so nothing to do */
			QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);
			return IMG_ERROR_INVALID_PARAMETERS;
		}
	}

	/* Prevent infinite increase using the threshold information specified earlier */
	if (g_aui32Weights[ui32SelectedContext] > psSocket->ui8RoundRobinThresh)
	{
		g_aui32Weights[ui32SelectedContext] = 0;
	}

	/** 2 - Socket object checks **/
	if (psSocket->ui8CmdQueueConsumer == psSocket->ui8CmdQueueProducer)
	{
		/* Empty queue, nothing to do but the firmware could be locked somewhere - desperately waiting to be kicked, we need to do it */
		eRet = IMG_ERROR_STORAGE_TYPE_EMPTY;
		if (psDevContext->eLowPowerState == e_HW_IDLE)
		{
			/* the hardware is already off and we have nothing to do */
			QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);
			return eRet;
		}
	}
	else
	{
		/** 3 - Get the queued command **/
		pui32QueueSlot = &psSocket->aui32KernelCmdQueue[psSocket->ui8CmdQueueConsumer * VXE_KM_COMMAND_BUFFER_WIDTH];
		if (!pui32QueueSlot)
		{
			/* Problem obtaining the socket command buffer */
			QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);
			return IMG_ERROR_INVALID_ID;
		}

#if defined (OUTPUT_COMM_STATS)
		Output_COMM_Stats_To_File(psSocket, "COMM_Send Entry", pui32QueueSlot[0], "COMM_Track.txt");
#endif

		if (psDevContext->eLowPowerState == e_HW_LOW_POWER && psDevContext->bSuspendHISR)
		{
			/* 
			 * The firmware has been instructed to deactivate but it has not completed yet so wait. If we got here with psDevContext->bSuspendHISR set then we must be in a call from user mode.
			 */
			QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);
			if (!KM_WaitForDeviceIdle(psDevContext))
			{
				/* firmware has not completed shutdown for some reason */
				/* signal that a clean up is required */
				psDevContext->bMMUFaultToSignal = IMG_TRUE;
				return IMG_ERROR_TIMEOUT;
			}
			QUARTZ_KM_LockMutex(psDevContext->hCheckAndScheduleLock, MTX_SUBCLASS_CHECKANDSCHED);
		}
		/* We lock the comm layer because active power management may want to send a DEACTIVATE_CONTEXT command (bypassing the workqueue) while we are issuing another one */
		km_Lock(psDevContext, COMM_LOCK_TX);
		if (psDevContext->eLowPowerState != e_HW_ACTIVE || psDevContext->bSuspendHISR)
		{
			/* if the new command is a deactivate, abort or fence and the hardware is idle then we can just skip them since the firmware is not running */
			eCmdId = F_EXTRACT(pui32QueueSlot[0], FW_COMMAND_COMMAND_TYPE);
			if ((eCmdId == VXE_COMMAND_ABORT_CONTEXT) || (eCmdId == VXE_COMMAND_DEACTIVATE_CONTEXT) || (eCmdId == VXE_COMMAND_FENCE))
			{
				psSocket->b8StreamAborted = IMG_TRUE;
				psSocket->bStreamShutdown = IMG_TRUE;

				km_Unlock(psDevContext, COMM_LOCK_TX);
				QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);

				if (!KM_WaitForDeviceIdle(psDevContext))
				{
						/* firmware has not completed shutdown for some reason */
						/* signal that a clean up is required */
						psDevContext->bMMUFaultToSignal = IMG_TRUE;
						return IMG_ERROR_TIMEOUT;
				}
				else
				{
						return IMG_ERROR_ALREADY_COMPLETE;
				}
			}
			/*
			* The hardware is idle and we have work to do so wake it up.
			*/
			DEBUG_PRINT("  HW is idle and/or HISR is suspended so wake up\n");
			quartzkm_fnPowerRestore(psDevContext->hDMANDevHandle, psDevContext);
		}

		TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_WRITER, &ui32CommandFIFOProducer);
		TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_READER, &ui32CommandFIFOConsumer);
		ui32NewFIFOCommandProducer = (ui32CommandFIFOProducer + 1) % HW_FIFO_SIZE;
		if (ui32NewFIFOCommandProducer == ui32CommandFIFOConsumer)
		{
			/* Releases ownership, avoiding deadlocks */
			km_Unlock(psDevContext, COMM_LOCK_TX);

#if ! defined (IMG_KERNEL_MODULE)
			/* When pdump-ing, we will wait for space in the FIFO */
			TALPDUMP_VerboseComment(NULL, "Poll for space in the command FIFO");
			eRet = TALREG_Poll32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_READER, TAL_CHECKFUNC_NOTEQUAL, ui32NewFIFOCommandProducer, 0xffffffff, POLL_COUNT, POLL_TIMEOUT);
			if (IMG_SUCCESS != eRet)
			{
				IMG_ASSERT(eRet == IMG_SUCCESS && "Time out waiting for space in command FIFO");
				QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);
				return eRet;
			}
#endif

			psDevContext->bCommandsWaiting = IMG_TRUE;

			/* The HW FIFO is already full, no more command can be inserted, FW needs some time to extract and process them */
			QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);
			return IMG_ERROR_STORAGE_TYPE_FULL;
		}
		else
			psDevContext->bCommandsWaiting = IMG_FALSE;

#if !defined (IMG_KERNEL_MODULE)
		/* When pdump-ing, we will wait for space in the FIFO */
		TALPDUMP_VerboseComment(NULL, "Poll for space in the command FIFO");
		eRet = TALREG_Poll32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_READER, TAL_CHECKFUNC_NOTEQUAL, ui32NewFIFOCommandProducer, 0xffffffff, POLL_COUNT, POLL_TIMEOUT);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "Time out waiting for space in command FIFO");
			QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);
			return eRet;
		}
#endif

		/* Sending a command makes this context active now */
		psDevContext->sFWSoftImage.ui16ActiveContextMask |= (1 << psSocket->ui8FWCtxtId);

		if (IMG_TRUE == psSocket->sPendingAbort.bAbortPending && IMG_FALSE == psSocket->sPendingAbort.bAbortSent)
		{
			/* Get the offset where we are going to write */
			ui32OffsetToWriteTo = FW_COMMAND_FIFO_START + (ui32CommandFIFOProducer * HW_FIFO_WORDS_PER_COMMANDS) * 4;

			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo, psSocket->sPendingAbort.ui32Command1stWord);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo + 0x4, psSocket->sPendingAbort.ui32Command2ndWord);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo + 0x8, psSocket->sPendingAbort.ui32Command3rdWord);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo + 0xc, psSocket->sPendingAbort.ui32UniqueCmdId);

			/* Update the offset for the next time we will write commands (also used as the producer index) */
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_WRITER, ui32NewFIFOCommandProducer);

			/* One command have been sent */
			psSocket->ui32CmdSent++;
			/* The pending abort has been issued to the firmware */
			psSocket->sPendingAbort.bAbortSent = IMG_TRUE;

			/* Everything has been successfull */
			eRet = IMG_SUCCESS;
			psSocket->bStreamIdle = IMG_FALSE;

#if defined (INCLUDE_DEBUG_FEATURES)
			debugfs_write_last_cmd(psDevContext->sDevSpecs.ui32CoreDevIdx,
				psSocket->sPendingAbort.ui32Command1stWord,
				psSocket->sPendingAbort.ui32Command2ndWord,
				psSocket->sPendingAbort.ui32Command3rdWord,
				psSocket->sPendingAbort.ui32UniqueCmdId);
#endif

#if defined (OUTPUT_COMM_STATS)
			Output_COMM_Stats_Msg_To_File(psSocket, "MSG-TX", psSocket->sPendingAbort.ui32Command1stWord, psSocket->sPendingAbort.ui32Command2ndWord, psSocket->sPendingAbort.ui32UniqueCmdId, "COMM_Track.txt");
#endif

			/* calculate the FIFO position for the next command since we have used the position we calculated above */
			ui32CommandFIFOProducer = ui32NewFIFOCommandProducer;
			ui32NewFIFOCommandProducer = (ui32CommandFIFOProducer + 1) % HW_FIFO_SIZE;
			if (ui32NewFIFOCommandProducer == ui32CommandFIFOConsumer)
			{
				/* Releases ownership, avoiding deadlocks */
				km_Unlock(psDevContext, COMM_LOCK_TX);

	#if ! defined (IMG_KERNEL_MODULE)
				/* When pdump-ing, we will wait for space in the FIFO */
				TALPDUMP_VerboseComment(NULL, "Poll for space in the command FIFO");
				eRet = TALREG_Poll32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_READER, TAL_CHECKFUNC_NOTEQUAL, ui32NewFIFOCommandProducer, 0xffffffff, POLL_COUNT, POLL_TIMEOUT);
				if (IMG_SUCCESS != eRet)
				{
					IMG_ASSERT(eRet == IMG_SUCCESS && "Time out waiting for space in command FIFO");
					QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);
					return eRet;
				}
	#endif

				psDevContext->bCommandsWaiting = IMG_TRUE;

				/* The HW FIFO is already full, no more command can be inserted, FW needs some time to extract and process them */
				QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);
				return IMG_ERROR_STORAGE_TYPE_FULL;
			}
		}

		{
			/** 4 - Insert the extracted command in the HW FIFO if possible **/
			eCmdId = F_EXTRACT(pui32QueueSlot[0], FW_COMMAND_COMMAND_TYPE);

			/* If an abort has been issued to this context, all commands will be skipped and won't cause interrupt */
			if (psSocket->ui32StreamStateFlags & VXE_KM_STREAM_EVENTS_NORM_ABORT_HIGH)
			{
				/*firmware must not do anything for these commands other than raising an interrupt since the stream is aborting*/
				pui32QueueSlot[0] |= (MASK_FW_COMMAND_TO_SKIP | MASK_FW_COMMAND_WB_INTERRUPT);
			}

			/* Our firmware will only support VXE_KM_MAX_ENCODE_ISSUED outstanding encode commands per context */
			if (VXE_COMMAND_ENCODE_FRAME == eCmdId)
			{
				if ((VXE_KM_MAX_ENCODE_ISSUED == psSocket->ui32EncCmdCount) && !psSocket->sPendingAbort.bAbortPending)
				{
					/* No commands will be issued, therefore we unlock the mutex */
					km_Unlock(psDevContext, COMM_LOCK_TX);
					/* Stream is still processing commands */
					psSocket->bStreamIdle = IMG_FALSE;
					/* Max command for this context already on fly, this is not an error but we don't want to do anything else to happen */

					QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);
					DEBUG_PRINT("HISR_INFO Not issuing encode to Socket %d because it already has %d outstanding\n", psSocket->ui8FWCtxtId, psSocket->ui32EncCmdCount);
					return IMG_ERROR_MAX_ENCODE_ON_FLY;
				}
				/* If we need to enforce a specific scheduling model, where the encode commands order is constrained */
				else if (e_NO_SCHEDULING_SCENARIO != psDevContext->sSchedModel.eSchedModel)
				{
					// Enforce the correct ordering of ENCODE_FRAME commmands
					if (ui32SelectedContext != psDevContext->sSchedModel.pui32SchedulingOrderToFWCtxtId[psDevContext->sSchedModel.pui32SchedulingOrder[psDevContext->sSchedModel.ui16ScheduleIdx]])
					{
						DEBUG_PRINT("HISR INFO - ENCODE_FRAME command for Context %i (consumer %i) was rejected by scheduler\n", ui32SelectedContext, psSocket->ui8CmdQueueConsumer);
						// This encode command is out of order - don't send it yet - return
						km_Unlock(psDevContext, COMM_LOCK_TX);

						QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);
						return IMG_ERROR_COMM_RETRY;
					}
					else
					{
#ifndef REMOVE_4K1080PARALLEL_SCHEDULING
						DEBUG_PRINT("HISR INFO - ENCODE_FRAME command for Context %i (consumer %i) (%s) accepted by scheduler\n", ui32SelectedContext, psSocket->ui8CmdQueueConsumer, ((psDevContext->sSchedModel.ui16ScheduleIdx < 2) ? "parallel mode" : "normal mode"));

						if (psDevContext->sSchedModel.eSchedModel == e_4K422_60__1080p420_30 ||
							psDevContext->sSchedModel.eSchedModel == e_4K422_60__1080p422_30)
						{
							if (psDevContext->sSchedModel.ui16ScheduleIdx < 2)
							{
								// Set CmdData to indicate pipe sharing
								pui32QueueSlot[1] |= MASK_VXE_ENCODE_FRAME_PIPEZEROSHARED;
							}
						}
#endif

						// The expected encode command will be sent and the schedule index counter is incremented
						psDevContext->sSchedModel.ui16ScheduleIdx++;
						if (psDevContext->sSchedModel.ui16ScheduleIdx >= psDevContext->sSchedModel.ui16ScheduleMax)
						{
							psDevContext->sSchedModel.ui16ScheduleIdx = 0;
						}
					}
				}
				/* count outstanding encodes.*/
				psSocket->ui32EncCmdCount++;
				if(VXE_KM_MAX_ENCODE_ISSUED == psSocket->ui32EncCmdCount)
				{
					/* this encode takes us to the limit of outstanding encodes so make sure it triggers an interrupt (in case one wasn't requested) */
					pui32QueueSlot[0] |= MASK_FW_COMMAND_WB_INTERRUPT;
				}

			}

#if defined (OUTPUT_COMM_STATS)
			Output_COMM_Stats_Msg_To_File(psSocket, "MSG-TX", pui32QueueSlot[0], pui32QueueSlot[1], pui32QueueSlot[3], "COMM_Track.txt");
#endif

			/* Get the offset where we are going to write */
			ui32OffsetToWriteTo = FW_COMMAND_FIFO_START + (ui32CommandFIFOProducer * HW_FIFO_WORDS_PER_COMMANDS) * 4;

			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo, pui32QueueSlot[0]);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo + 0x4, pui32QueueSlot[1]);

			// Write the extra data (offset in memory for most of the commands, could also be the virtual address directly - VXE_ACTIVATE_CONTEXT for instance -)
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo + 0x8, pui32QueueSlot[2]);

			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo + 0xc, pui32QueueSlot[3]);

			/* Update the offset for the next time we will write commands (also used as the producer index) */
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_WRITER, ui32NewFIFOCommandProducer);

			/* One command have been sent */
			psSocket->ui32CmdSent++;

#if defined (INCLUDE_DEBUG_FEATURES)
			debugfs_write_last_cmd(psDevContext->sDevSpecs.ui32CoreDevIdx, pui32QueueSlot[0], pui32QueueSlot[1], pui32QueueSlot[2], pui32QueueSlot[3]);
#endif

			/* We unlock the comm layer now that our command has been placed in the command FIFO, if APM wanted to issue a VXE_DEACTIVATE_CONTEXT command, it will be released */
			km_Unlock(psDevContext, COMM_LOCK_TX);

			psSocket->bStreamIdle = IMG_FALSE;

			switch (eCmdId)
			{
			case VXE_COMMAND_ENCODE_FRAME:
				if (pui32QueueSlot[1] & MASK_VXE_ENCODE_FRAME_POWER_TRANS)
				{
					/* Seeing this bit in the command makes the socket going to sleep (we may want to avoid this in low latency situations) */
					psSocket->bStreamIdle = IMG_TRUE;
				}

				/* Keep track of the encode command history */
				psSocket->asEncCmdHistory[psSocket->ui8EncCmdHistoryProd].bFrameReadyForProvision = IMG_TRUE;
				psSocket->asEncCmdHistory[psSocket->ui8EncCmdHistoryProd].bEncodeHasBeenSeen = IMG_FALSE;
				/* We used the same MASK_ and SHIFT_ macros here because if we want to identify an encode command feedback it will be identified this way */
				psSocket->asEncCmdHistory[psSocket->ui8EncCmdHistoryProd].ui32UniqueCmdId = F_ENCODE(pui32QueueSlot[3], FW_FEEDBACK_COMMAND_ID);
				psSocket->ui8EncCmdHistoryProd++;
				if (psSocket->ui8EncCmdHistoryProd >= VXE_KM_MAX_ENCODE_ISSUED)
				{
					psSocket->ui8EncCmdHistoryProd = 0;
				}

				break;
			case VXE_COMMAND_DEACTIVATE_CONTEXT:
				/* The only way to see a deactivate command going through the workqueue is for it to be the last one sent to remove the context */
				psSocket->bStreamIdle = IMG_FALSE;

#ifndef REMOVE_4K1080PARALLEL_SCHEDULING
				if (psDevContext->sSchedModel.eSchedModel != e_NO_SCHEDULING_SCENARIO)
				{
					DEBUG_PRINT("HISR INFO - COMMAND_DEACTIVATE_CONTEXT encountered - KM scheduling model deactivated to allow remaining contexts to complete.\n");

					// Override any existing scheduling code so that all encodes currently queued can complete without scheduling restrictions before low power mode
					psDevContext->sSchedModel.eSchedModel = e_NO_SCHEDULING_SCENARIO;
					if (NULL != psDevContext->sSchedModel.pvAllocation)
					{
						IMG_FREE(psDevContext->sSchedModel.pvAllocation);
						psDevContext->sSchedModel.pvAllocation = NULL;
					}
				}
#endif
				break;
			}

#if defined (OUTPUT_COMM_STATS)
			Output_COMM_Stats_To_File(psSocket, "COMM_Send Exit", pui32QueueSlot[0], "COMM_Track.txt");
#endif

			/* Command has been dequeued from the buffer */
			IMG_MEMSET(pui32QueueSlot, 0, VXE_KM_COMMAND_BUFFER_WIDTH * sizeof(IMG_UINT32));
			psSocket->ui8CmdQueueConsumer = (psSocket->ui8CmdQueueConsumer + 1) % VXE_KM_COMMAND_BUFFER_SIZE;

			// Everything has been successfull
			eRet = IMG_SUCCESS;
		}
	}

	// Signal to FW that the host has done some processing that may unlock it
	{
		if (psSocket->bStreamIdle)
		{
			/* Check that this socket has not yet been marked idle (protects the global counter) */
			if (0 == ((1 << psSocket->ui8FWCtxtId) & psDevContext->ui32IdleSocketsFlag))
			{
				/* Set the flag before imcrementing the counter (acts as a simily mutex) */
				psDevContext->ui32IdleSocketsFlag |= (1 << psSocket->ui8FWCtxtId);
				psDevContext->ui32IdleSockets++;
			}
		}

		/* Turn off the HW when doing power transitions */
		if (psDevContext->ui32UsedSockets && psDevContext->ui32UsedSockets == psDevContext->ui32IdleSockets)
		{
			KM_InformLowPower(psDevContext);
			psDevContext->eLowPowerState = e_HW_LOW_POWER;
		}

		/* mark the encoder not idle */
		TALREG_WriteWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_MULTIPIPE_IDLE_PWR_MAN, 0);

		/* Kick the HW afterwards after we eventually inserted the DEACTIVATE_CONTEXT command(s) */
		LTP_Kick(&(psDevContext->sFWSoftImage), 1);
	}

	/* When doing PPM, we can have some socket being idle while others are still doing work */
	if (0 == psDevContext->sDevSpecs.bKMPPM)
	{
		if (psDevContext->ui32UsedSockets > 1 && psDevContext->ui32IdleSockets != 0)
		{
#if defined (IMG_KERNEL_MODULE)
			IMG_ASSERT(IMG_FALSE && "APM will not work with multi-context");
#else
			PRINT("ERROR: %s() - Multi-context and Active Power Management will not work together.\n", __FUNCTION__);
#endif /*defined (IMG_KERNEL_MODULE)*/
			eRet = IMG_ERROR_NOT_SUPPORTED;
		}
	}

	QUARTZ_KM_UnlockMutex(psDevContext->hCheckAndScheduleLock);
	// May be IMG_SUCCESS, IMG_ERROR_STORAGE_TYPE_EMPTY or IMG_ERROR_MAX_ENCODE_ON_FLY
	return eRet;
}



IMG_RESULT KM_CheckForLowLatencyCommand(VXE_KM_DEVCONTEXT *psDevContext, IMG_UINT32 ui32LowLatencyTrigVal)
{
	VXE_KM_COMM_SOCKET *psSocket;
	IMG_UINT32 ui32PipeCodedList, ui32Reg, ui32RegContent;
	ui32PipeCodedList = MAX_CODED_LISTS_PER_ENCODE;

	while (ui32PipeCodedList--)
	{
		ui32Reg = FW_PIPELOWLATENCYINFO_START + (ui32PipeCodedList << 2/* x sizeof(IMG_UINT32)*/);
		TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32Reg, &ui32RegContent);

		if (ui32RegContent)
		{
			IMG_UINT32 ui32HeaderCnt, ui32PrevHeaderCnt, ui32CmdIdSig, ui32NodeCnt, ui32PrevNodeCnt, ui32SocketCmdIdSig;
			IMG_UINT32 ui32Ctx = F_DECODE(ui32RegContent, FW_PIPELOWLATENCYINFO_CTX);

			if (!psDevContext->apsDeviceSockets[ui32Ctx])
			{
				DEBUG_PRINT("Context[%d]: %s() - Kernel stream object does not exist\n", ui32Ctx, __FUNCTION__);
				return IMG_ERROR_CANCELLED;
			}
			psSocket = psDevContext->apsDeviceSockets[ui32Ctx];

			ui32NodeCnt = F_DECODE(ui32RegContent, FW_PIPELOWLATENCYINFO_NODECNTTHISHEADER);
			ui32HeaderCnt = F_DECODE(ui32RegContent, FW_PIPELOWLATENCYINFO_HEADCNT);
			ui32CmdIdSig = F_DECODE(ui32RegContent, FW_PIPELOWLATENCYINFO_CMDID_SIG);

			ui32PrevNodeCnt = F_DECODE(psSocket->ui32PrevHeaderNodeInfo, FW_PIPELOWLATENCYINFO_NODECNTTHISHEADER);
			ui32PrevHeaderCnt = F_DECODE(psSocket->ui32PrevHeaderNodeInfo, FW_PIPELOWLATENCYINFO_HEADCNT);

			// Ensure we'll be checking the same representation of the command ID (frame ID) as that passed from the register
			if (psSocket->ui32CurCmdId != IDX_LOWLATENCY_NOT_STARTED)
			{
#if ! defined (SILENCE_LOW_LATENCY_DEBUG)
				DEBUG_PRINT("Context[%d]: KM_CheckForLowLatencyCommand() - %s low latency message for Frame CmdId %i (HeaderCnt %i, NodeCnt %i).\n", ui32Ctx, (ui32NodeCnt ? "NODE FILLED" : "CODED HEADER"), ui32CmdIdSig, ui32HeaderCnt, ui32NodeCnt);
#endif
				ui32SocketCmdIdSig = psSocket->ui32CurCmdId & (MASK_FW_PIPELOWLATENCYINFO_CMDID_SIG >> SHIFT_FW_PIPELOWLATENCYINFO_CMDID_SIG);
			}
			else
			{
#if ! defined (SILENCE_LOW_LATENCY_DEBUG)
				DEBUG_PRINT("Context[%d]: KM_CheckForLowLatencyCommand() - %s low latency message for Frame CmdId %i (HeaderCnt %i, NodeCnt %i) rejected  (lowlatency mode not active on that context).\n", ui32Ctx, (ui32NodeCnt ? "NODE FILLED" : "CODED HEADER"), ui32CmdIdSig, ui32HeaderCnt, ui32NodeCnt);
#endif
				return IMG_ERROR_CANCELLED;
			}

			// If the per-tile node counter is positive attempt to pass on a node full notification
			// Only add the low latency message if it for the currently encoding frame (not generated in the past)

			if ((ui32HeaderCnt == (MASK_FW_PIPELOWLATENCYINFO_HEADCNT >> SHIFT_FW_PIPELOWLATENCYINFO_HEADCNT)) &&
				(ui32NodeCnt == (MASK_FW_PIPELOWLATENCYINFO_NODECNTTHISHEADER >> SHIFT_FW_PIPELOWLATENCYINFO_NODECNTTHISHEADER)))
			{
#if ! defined (SILENCE_LOW_LATENCY_DEBUG)
				DEBUG_PRINT("Context[%d]: KM_CheckForLowLatencyCommand() - End of frame low latency message intended only for pdumpplayback triggering ignored\n", ui32Ctx);
#endif
			}
			else
			{
				if (ui32CmdIdSig == ui32SocketCmdIdSig)
				{
					if (ui32HeaderCnt == ui32PrevHeaderCnt)
					{
						// Only add the node full message if it's a NEW message and it's in the current header
						if (ui32NodeCnt > ui32PrevNodeCnt)
						{
#if ! defined(IMG_KERNEL_MODULE)
							{
								IMG_RESULT eRet;
								// Added for pdump reprobucibility
								// Ensure the playback register value is equal to (or greater that) the value that caused this message.
								// Register fields ordered in priority order: |ID = Frame | Head = Tile/Slice | NodeCnt | NA |
								TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "KM_CheckForLowLatencyCommand - NODE Sync");

								eRet = TALREG_Poll32(psDevContext->sDevSpecs.hLTPDataRam, ui32Reg, TAL_CHECKFUNC_GREATEREQ, ui32RegContent, (0xffffffff & ~MASK_FW_PIPELOWLATENCYINFO_CMDID_SIG), POLL_COUNT, POLL_TIMEOUT);
								IMG_ASSERT(eRet == IMG_SUCCESS && "KM_CheckForLowLatencyCommand - NODE2 Time out waiting for firmware to catch up ");
							}
#endif

							psSocket->ui32CurCodedList = ui32PipeCodedList;
							// We'll need to mock up a low latency node return
							psSocket->ui32PrevHeaderNodeInfo = F_ENCODE(ui32NodeCnt, FW_PIPELOWLATENCYINFO_NODECNTTHISHEADER) |
								F_ENCODE(ui32CmdIdSig, FW_PIPELOWLATENCYINFO_CMDID_SIG) |
								F_ENCODE(ui32HeaderCnt, FW_PIPELOWLATENCYINFO_HEADCNT) |
								F_ENCODE(LL_NODE_FULL_TYPE, FW_PIPELOWLATENCYINFO_SEND); // Use the ctx field to signal a new entry and type of mock up required
#if ! defined (SILENCE_LOW_LATENCY_DEBUG)
							DEBUG_PRINT("Context[%d]: KM_CheckForLowLatencyCommand() - NODE FILLED low latency message intended for Frame CmdId %i (HeaderCnt %i, NodeCnt %i) received and sent to KM_SendLowLatencyCommand().\n", ui32Ctx, ui32CmdIdSig, ui32HeaderCnt, ui32NodeCnt);
#endif

							//psSocket->ui32PrevNodeCnt = ui32PrevNodeCnt;  NOTE: This is now done upon receipt of the low latency message in KM_SendLowLatencyCommand_API()

#ifndef REMOVE_LL_COUNTERS
							psDevContext->apsDeviceSockets[ui32Ctx]->ui32LowLatencyMsgsSentFromKM++;
#endif

#if ! defined(IMG_KERNEL_MODULE)
							psDevContext->apsDeviceSockets[ui32Ctx]->ui32PrevNodeCnt = ui32PrevNodeCnt;
#endif


							// Signal the socket context
							SYSOSKM_SignalEventObject(psSocket->hFWMessageAvailable_Sem);
						}
					}
					else if (ui32HeaderCnt > ui32PrevHeaderCnt)
					{
						// if the header count has incremented we should send a header notification
						{
#if ! defined(IMG_KERNEL_MODULE)
							{
								IMG_RESULT eRet;
								// Added for pdump reprobucibility
								// Ensure the playback register value is equal to (or greater that) the value that caused this message.
								// Register fields ordered in priority order: |ID = Frame | Head = Tile/Slice | NodeCnt | NA |
								TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "KM_CheckForLowLatencyCommand - CODED HEADER Sync");

								eRet = TALREG_Poll32(psDevContext->sDevSpecs.hLTPDataRam, ui32Reg, TAL_CHECKFUNC_GREATEREQ, ui32RegContent, (0xffffffff & ~MASK_FW_PIPELOWLATENCYINFO_CMDID_SIG), POLL_COUNT, POLL_TIMEOUT);
								IMG_ASSERT(eRet == IMG_SUCCESS && "KM_CheckForLowLatencyCommand - CODER HEADER2 Time out waiting for firmware to catch up ");
							}
#endif

							psSocket->ui32CurCodedList = ui32PipeCodedList;
							// We'll need to mock up a coded header return
							psSocket->ui32PrevHeaderNodeInfo = F_ENCODE(ui32NodeCnt, FW_PIPELOWLATENCYINFO_NODECNTTHISHEADER) |
								F_ENCODE(F_DECODE(ui32RegContent, FW_PIPELOWLATENCYINFO_CMDID_SIG), FW_PIPELOWLATENCYINFO_CMDID_SIG) |
								F_ENCODE(ui32HeaderCnt, FW_PIPELOWLATENCYINFO_HEADCNT) |
								F_ENCODE(LL_CODED_HEADER_TYPE, FW_PIPELOWLATENCYINFO_SEND); // Use the ctx field to signal a new entry and type of mock up required

#if ! defined (SILENCE_LOW_LATENCY_DEBUG)
							DEBUG_PRINT("Context[%d]: KM_CheckForLowLatencyCommand() - CODED HEADER low latency message intended for Frame CmdId %i (HeaderCnt %i, NodeCnt %i) received and sent to KM_SendLowLatencyCommand().\n", ui32Ctx, ui32CmdIdSig, ui32HeaderCnt, ui32NodeCnt);
#endif
							// Signal the socket context
							SYSOSKM_SignalEventObject(psSocket->hFWMessageAvailable_Sem);
						}

					}
				}
				else
				{
#if ! defined (SILENCE_LOW_LATENCY_DEBUG)
					DEBUG_PRINT("Context[%d]: KM_CheckForLowLatencyCommand() - %s low latency message intended for Frame CmdId %i (HeaderCnt: %i, NodeCnt %i) but encountered during Frame CmdId %i rejected.\n", ui32Ctx, (ui32NodeCnt ? "NODE FILLED" : "CODED HEADER"), ui32CmdIdSig, ui32HeaderCnt, ui32NodeCnt, ui32SocketCmdIdSig);
#endif
				}
			}

		}
	}

	return IMG_SUCCESS;
}


/**
* \fn KM_DispatchFeedback
* \brief Once feedback came back from the FW in the shared memory, this function will place it in the socket FIFO to be given back to UM
* \params psDevContext Pointer on the KM device context
* \return	- IMG_SUCCESS if the feedback has been extracted properly,
*			- IMG_ERROR_NOT_INITIALISED if there is a problem with the device context
* \details
* After checking the content of producer/consumer registers and asserted that the device context has
* been initialised, this function will extract the feedback from the shared memory (LTP data RAM).
* It will extract the two words of feedback from this poll and make them available to the socket they
* targetted. It also updates the consumer register to inform that one chunk of feedback has been consumed.
* Further note: This function will dequeue all available feedback in order to limit the number of interrupts
* and imporve the response time
**/
IMG_RESULT KM_DispatchFeedback(VXE_KM_DEVCONTEXT *psDevContext)
{
	IMG_RESULT eRet = IMG_ERROR_IDLE;
	// Extracted information
	IMG_UINT32 ui32FirstWordFeedback, ui32SecondWordFeedback;
	IMG_UINT32 ui32SocketId;
	VXE_KM_COMM_SOCKET *psSocketData = IMG_NULL;

	// FW index in the feedback FIFO
	IMG_UINT32 ui32FeedbackProducerIndex;
	// KM index in the feedback FIFO
	IMG_UINT32 ui32FeedbackConsumerIndex;
	// Offset to read from in the LTP RAM
	IMG_UINT16 ui16Offset;
	IMG_UINT32 ui32LowLatencyBits;
#if ! defined (IMG_KERNEL_MODULE)
	// May be used to check the poll return code
	IMG_RESULT ePollRet;
#endif
	IMG_UINT32 ui32RegTmp;

	if (!psDevContext)
	{
		/* This error cannot by handled otherwise */
		return IMG_ERROR_NOT_INITIALISED;
	}


	/* ISR checks the content of the two registers keeping track of the feedback FIFO state */
	ui32FeedbackConsumerIndex = km_GetFeedbackConsumer(psDevContext);
	ui32FeedbackProducerIndex = km_GetFeedbackProducer(psDevContext);

	ui32LowLatencyBits = km_GetFeedbackProducer_LowLatency(psDevContext);

#if defined (IMG_KERNEL_MODULE)
	KM_CheckForLowLatencyCommand(psDevContext, ui32LowLatencyBits);
#endif

#if !defined (IMG_KERNEL_MODULE)
	/* We know that if we get there, the firmware should produce feedback anytime soon, we if the registers are not set, it's a matter of time */
	while (ui32FeedbackConsumerIndex == ui32FeedbackProducerIndex)
	{
		IMG_UINT32 ui32TempLowLatency;

		/* Check that there is something to read in the feedback FIFO */
		/* Wait for the firmware to send the feedback for one processed command */
		TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Prod/cons same, poll for incoming feedback");
		ePollRet = TALREG_Poll32(
			psDevContext->sDevSpecs.hLTPDataRam,
			FW_REG_FEEDBACK_PRODUCER,
			TAL_CHECKFUNC_NOTEQUAL,
			F_ENCODE(ui32FeedbackConsumerIndex, FW_FEEDBACK_PRODUCER_ID) | F_ENCODE(ui32LowLatencyBits, FW_FEEDBACK_PRODUCER_LOWLATENCYBITS),
			MASK_FW_FEEDBACK_PRODUCER_ID | MASK_FW_FEEDBACK_PRODUCER_LOWLATENCYBITS,
			POLL_COUNT,
			POLL_TIMEOUT);

		IMG_ASSERT(ePollRet == IMG_SUCCESS && "Timeout waiting for incoming feedback ");

		// If the low latency counter bits have changed then see if we can dispatch a low latency message
		ui32TempLowLatency = km_GetFeedbackProducer_LowLatency(psDevContext);

		if (ui32TempLowLatency != ui32LowLatencyBits)
		{
			KM_CheckForLowLatencyCommand(psDevContext, ui32LowLatencyBits);		
			ui32LowLatencyBits = ui32TempLowLatency;
		}

		/* What is the new producer index? */
		TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Read next producer");

		ui32FeedbackProducerIndex = km_GetFeedbackProducer(psDevContext);
	}

	// LOW LATENCY EXTRA PDUMP SYNC
	{
		ePollRet = TALREG_Poll32(
			psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_PRODUCER, TAL_CHECKFUNC_NOTEQUAL,
			F_ENCODE(ui32FeedbackConsumerIndex, FW_FEEDBACK_PRODUCER_ID),
			MASK_FW_FEEDBACK_PRODUCER_ID,
			POLL_COUNT, POLL_TIMEOUT);

		IMG_ASSERT(ePollRet == IMG_SUCCESS && "KM_CheckForLowLatencyCommand - FEEDBACK PRODUCER1 Time out waiting for firmware to catch up ");
	}



#endif

	/*
	* We want to service all interrupts here, for several reasons:
	* - we want to limit the number of IT the HW sends, so one interrupt
	* can be triggered after several some feedback has been produced by the
	* the FW (typically in high-latency)
	* - we have the hand, so the firmware might be locked up at some point
	* waiting for space, it is less efficient to only leave one slot free if
	* we were able to empty more
	*/
	while (ui32FeedbackConsumerIndex != ui32FeedbackProducerIndex)
	{
#if !defined (IMG_KERNEL_MODULE)
		IMG_UINT32 ui32TempLowLatency;
		do
		{
			/*
			* If interrupts aren't enabled we need to keep polling till we receive some results on our FIFO
			* We check that we have at least one message to read (This test is only useful to guarantee PDUMP
			* playback as the other tests already cover things for normal driver operation)
			*/
			TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Sync point to process pending feedback");
			ePollRet = TALREG_Poll32(
				psDevContext->sDevSpecs.hLTPDataRam,
				FW_REG_FEEDBACK_PRODUCER,
				TAL_CHECKFUNC_NOTEQUAL,
				F_ENCODE(ui32FeedbackConsumerIndex, FW_FEEDBACK_PRODUCER_ID) | F_ENCODE(ui32LowLatencyBits, FW_FEEDBACK_PRODUCER_LOWLATENCYBITS),
				MASK_FW_FEEDBACK_PRODUCER_ID | MASK_FW_FEEDBACK_PRODUCER_LOWLATENCYBITS,
				POLL_COUNT,
				POLL_TIMEOUT);
			TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Processing the pending feedback");

			IMG_ASSERT(ePollRet == IMG_SUCCESS && "Timeout waiting for incoming feedback ");

			// If the low latency counter bits have changed then see if we can dispatch a low latency message
			ui32TempLowLatency = km_GetFeedbackProducer_LowLatency(psDevContext);

			if (ui32TempLowLatency != ui32LowLatencyBits)
			{
				KM_CheckForLowLatencyCommand(psDevContext, ui32LowLatencyBits);
				ui32LowLatencyBits = ui32TempLowLatency;
			}

		} while (ui32FeedbackConsumerIndex == km_GetFeedbackProducer(psDevContext));


		// LOW LATENCY EXTRA PDUMP SYNC
		{
			ePollRet = TALREG_Poll32(
				psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_PRODUCER, TAL_CHECKFUNC_NOTEQUAL,
				F_ENCODE(ui32FeedbackConsumerIndex, FW_FEEDBACK_PRODUCER_ID),
				MASK_FW_FEEDBACK_PRODUCER_ID,
				POLL_COUNT, POLL_TIMEOUT);

			IMG_ASSERT(ePollRet == IMG_SUCCESS && "KM_CheckForLowLatencyCommand - FEEDBACK PRODUCER2 Time out waiting for firmware to catch up ");
		}
#endif






		/* Extract the feedback */
		ui16Offset = (ui32FeedbackConsumerIndex*FEEDBACK_FIFO_WORD_PER_COMMANDS) * 4/*sizeof(IMG_UINT32)*/ + FW_FEEDBACK_FIFO_START;
		TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, ui16Offset, &ui32FirstWordFeedback);
		TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, ui16Offset + 4, &ui32SecondWordFeedback);

		DEBUG_VERBOSE_PRINT("\nFEEDBACK - FirstWord = 0x%08X, SecondWord = 0x%08X\n", ui32FirstWordFeedback, ui32SecondWordFeedback);

		ui32SocketId = F_EXTRACT(ui32FirstWordFeedback, FW_FEEDBACK_CONTEXT_ID);

#if !defined (IMG_KERNEL_MODULE)
		{
			/* Poll on per context counter that is updated in firmware whenever a message is sent. It should allow multi pipe multi context tests to be repeatable */
			IMG_UINT32 ui32CurrentCounterValue;
			TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_CTXT_STATUS_COUNTER(ui32SocketId), &ui32CurrentCounterValue);
			TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Poll on per context counter to make sure that we aren't proceeding too quickly");
			ePollRet = TALREG_Poll32(
				psDevContext->sDevSpecs.hLTPDataRam,
				FW_CTXT_STATUS_COUNTER(ui32SocketId),
				TAL_CHECKFUNC_GREATEREQ,
				ui32CurrentCounterValue,
				0xffffffff,
				POLL_COUNT,
				POLL_TIMEOUT);

			IMG_ASSERT(ePollRet == IMG_SUCCESS && "Timeout waiting for per context counter ");
		}
#endif


#if defined (OUTPUT_COMM_STATS)
		Output_COMM_Stats_Line_To_File("MSG-RX", ui32FirstWordFeedback, ui32SecondWordFeedback, "COMM_Track.txt", ui32FeedbackConsumerIndex);
#endif

		/* Insert the feedback in the socket FIFO only if it can receive it, otherwise simply discard it */
		psSocketData = psDevContext->apsDeviceSockets[ui32SocketId];
		if (psSocketData)
		{
			IMG_UINT8 ui8NewProducer;

			/* We received an acknowledgement for a command */
			if ((F_DECODE(ui32FirstWordFeedback, FW_FEEDBACK_MSG_TYPE) == VXE_FWMSG_ACK) && (F_EXTRACT(ui32FirstWordFeedback, FW_FEEDBACK_COMMAND_TYPE) != VXE_COMMAND_FIRMWARE_READY))
			{
				psSocketData->ui32AckRecv++;
			}

			/* Only if we are in a situation where user-space went away */
			if (VXE_KM_STREAM_EVENTS_CLEANUP_ABORT_SENT == (psSocketData->ui32StreamStateFlags & VXE_KM_STREAM_EVENTS_CLEANUP_ABORT_SENT))
			{
				/* Abort cleanup has progressed */
				if (VXE_COMMAND_ABORT_CONTEXT == F_EXTRACT(ui32FirstWordFeedback, FW_FEEDBACK_COMMAND_TYPE))
				{
					psSocketData->ui32StreamStateFlags |= VXE_KM_STREAM_EVENTS_CLEANUP_ABORT_SEEN;
				}
				/* Fence indicating abort completion has progressed */
				else if (VXE_COMMAND_FENCE == F_EXTRACT(ui32FirstWordFeedback, FW_FEEDBACK_COMMAND_TYPE) &&
					(MASK_FW_FEEDBACK_FENCE_IS_END_OF_ABORT & ui32SecondWordFeedback))
				{
					psSocketData->ui32StreamStateFlags |= VXE_KM_STREAM_EVENTS_FENCE_END_ABORT;
				}
			}

			/* Check the socket FIFO state */
			ui8NewProducer = psSocketData->ui8OutgoingFIFOProducer + 1;
			if (ui8NewProducer == FEEDBACK_FIFO_MAX_COMMANDS)
			{
				ui8NewProducer = 0;
			}

			if (ui8NewProducer == psSocketData->ui8OutgoingFIFOConsumer)
			{
				/* Flag the stream about it */
				psSocketData->ui32StreamStateFlags |= VXE_KM_STREAM_EVENTS_FEEDBACK_LOST;
				DEBUG_VERBOSE_PRINT("The KM to UM level feedback FIFO is full, the feedback is lost\n");
			}
			else
			{
				/* Add the command in the feedback FIFO */
				IMG_UINT32* pui32FIFOSlot = &psSocketData->aui32OutgoingFIFO[psSocketData->ui8OutgoingFIFOProducer * FEEDBACK_FIFO_WORD_PER_COMMANDS];
				if (pui32FIFOSlot)
				{
					pui32FIFOSlot[0] = ui32FirstWordFeedback;
					pui32FIFOSlot[1] = ui32SecondWordFeedback;

					/* Feedback successfully added */
					psSocketData->ui8OutgoingFIFOProducer = ui8NewProducer;

#if defined (INCLUDE_DEBUG_FEATURES)
					debugfs_write_last_feedback(psSocketData->psDevContext->sDevSpecs.ui32CoreDevIdx, ui32FirstWordFeedback, ui32SecondWordFeedback);
#endif
				}
			}
			// Signal that a new message is available for the context
			SYSOSKM_SignalEventObject(psSocketData->hFWMessageAvailable_Sem);
		}

		/* Update the consumer register content */
		++ui32FeedbackConsumerIndex;
		if (ui32FeedbackConsumerIndex == FEEDBACK_FIFO_MAX_COMMANDS)
		{
			ui32FeedbackConsumerIndex = 0;
		}

		/* The last command id executed by a FW thread dispatch should not be changed, only the consumer id is */
		TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_CONSUMER, &ui32RegTmp);
		ui32RegTmp = F_INSERT(ui32RegTmp, ui32FeedbackConsumerIndex, FW_FEEDBACK_CONSUMER_ID);
		TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_CONSUMER, ui32RegTmp);

		/* Update the producer index to dequeue the next feedback */
		TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Read next producer");

		ui32FeedbackProducerIndex = km_GetFeedbackProducer(psDevContext);

		eRet = IMG_SUCCESS;
	}

	/* Everything has been dequeued, we should be able to continue now */
	return eRet;
}


/**
* \fn KM_OnCloseSocket
* \brief Callback registered in RMAN which trigger when the socket resource is destroyed
* \params pvSocket Reference on the socket object this callback is bound to
**/
IMG_VOID KM_OnCloseSocket(IMG_VOID *pvSocket)
{
	IMG_UINT32 nIndex;
	IMG_UINT16 weight_to_free;
	VXE_KM_COMM_SOCKET *psSocket = (VXE_KM_COMM_SOCKET *)pvSocket;

	/* Iterate through all socket register in the device context to see if the parameter is one of them */
	for (nIndex = 0; nIndex < VXE_MAX_SOCKETS; nIndex++)
	{
		if (psSocket->psDevContext->apsDeviceSockets[nIndex] == psSocket)
		{
			break;
		}
	}


	/* if nIndex == VXE_MAX_SOCKETS OpenSocket failed (since the socket has not been found in the device context array) */
	if (nIndex != VXE_MAX_SOCKETS)
	{
#if defined(IMG_KERNEL_MODULE)
		/* Warning otherwise */
		IMG_UINT32 ui32WbValue;

		/*
		* This callback is called under any circumstance, on normal user mode
		* context destruction but also if the user mode application stopped
		* working.
		* On normal de-activation, the stream will be marked inactive and any
		* resource attached to it will be free'd without waiting.
		* When this callback is called on abnormal shutdown, course of actions
		* is a bit different:
		* 1. Abort the stream first
		* 2. Wait for abort completion since hardware might be encoding frames
		*	 for this context. This means that hardware still needs the context
		*	 resources (buffers mapped to hardware space, device memory holding
		*	 firmware context). Therefore, we need to make sure that hardware has
		*	 finished before releasing these resources.
		* 3. The above is even more important when there are several encodes 
		*	 being performed simultaneously by the firmware because releasing
		*	 the resources too early will cause a kernel page-fault that will break
		*	 any other encode context (not just the one causing the page-fault).
		*/

		km_Lock(psSocket->psDevContext, COMM_LOCK_TX);
		if (psSocket->psDevContext->bCoreNeedsToClose == IMG_FALSE &&	/* If hardware has caused a page fault, aborting the context will not succeed */
			(psSocket->psDevContext->sFWSoftImage.ui16ActiveContextMask & (1 << psSocket->ui8FWCtxtId)) && 	/* Context is active */
			IMG_FALSE == psSocket->bStreamIdle) /* Context is not idle */
		{
			IMG_RESULT eRet;
			/* This stream is marked for cleanup */
			psSocket->ui32StreamStateFlags |= VXE_KM_STREAM_EVENTS_CLEANUP_ABORT_SENT;

			/* Issue the abort command */
			eRet = km_SendCommandToFW(psSocket, F_ENCODE(VXE_COMMAND_ABORT_CONTEXT, FW_COMMAND_COMMAND_TYPE) | MASK_FW_COMMAND_WB_INTERRUPT, 0, 0, &ui32WbValue);
			if(eRet == IMG_SUCCESS)
			{
				eRet = km_SendCommandToFW(psSocket, F_ENCODE(VXE_COMMAND_DEACTIVATE_CONTEXT, FW_COMMAND_COMMAND_TYPE) | MASK_FW_COMMAND_WB_INTERRUPT, 0, 0, &ui32WbValue);
			}
			km_Unlock(psSocket->psDevContext, COMM_LOCK_TX);
			if(IMG_ERROR_DISABLED == eRet)
			{
				/* the firmware has already been deactivated so we just need to wait for the deactivate to complete */
				eRet = km_WaitOnSocketDeactivate(psSocket);
				IMG_ASSERT(eRet == IMG_SUCCESS && "Deactivate did not complete in time");
			}
			else
			{
				if (IMG_SUCCESS != eRet)
				{
					PRINT("Issuing abort to the firmware reported %i\n", eRet);
					IMG_ASSERT(eRet == IMG_SUCCESS && "Error while issuing abort command to the firmware");
				}
				/* Workqueue needs signalling */
				DMANKM_ActivateKmHisr(psSocket->psDevContext->hDMANDevHandle);

				/* Wait for the abort to be seen */
				eRet = km_WaitOnAbortSync(psSocket);
				IMG_ASSERT(eRet == IMG_SUCCESS && "Abort did not complete in time");

				eRet = km_WaitOnSocketDeactivate(psSocket);
				IMG_ASSERT(eRet == IMG_SUCCESS && "Deactivate did not complete in time");
			}

		}
		else 
		{
			if (!(psSocket->psDevContext->sFWSoftImage.ui16ActiveContextMask & (1 << psSocket->ui8FWCtxtId)) &&  (psSocket->psDevContext->eLowPowerState == e_HW_IDLE))
			{
				/* the hardware is already off due to our power management so tell DMAN to switch it back on. This ensures that it will be cleanly tidied up when we exit */
				PRINT("Switching on HW to allow clean shutdown\n");
				DMANKM_ResumeDevice(psSocket->psDevContext->hDMANDevHandle, IMG_TRUE);
			}
			km_Unlock(psSocket->psDevContext, COMM_LOCK_TX);
		}
#endif
		/* Set it to NULL here -not any time sooner-, we need it in case we had to abort the stream. */
		psSocket->psDevContext->apsDeviceSockets[nIndex] = IMG_NULL;

		if (psSocket->psDevContext->sSchedModel.eSchedModel != e_NO_SCHEDULING_SCENARIO)
		{
			psSocket->psDevContext->sSchedModel.pb8ContextAllocated[psSocket->ui16CtxIdxInSchedModel] = IMG_FALSE;
			weight_to_free = VXEKMAPI_MAX_FEATURE_WEIGHT;
		}
		else
		{
			weight_to_free = km_applyFeaturesWeight(psSocket->ui32FeaturesFlag);
		}

		/* Since the stream is closed, we need to free the pipes it was using */
		for (nIndex = psSocket->ui8FirstPipeIdx; nIndex <= psSocket->ui8LastPipeIdx; nIndex++)
		{
			if (psSocket->psDevContext->aui16PipesAllocation[nIndex] - weight_to_free < 0)
			{
				psSocket->psDevContext->aui16PipesAllocation[nIndex] = 0;
			}
			else
			{
				psSocket->psDevContext->aui16PipesAllocation[nIndex] -= weight_to_free;
			}
		}

		/* Clear the active contexts' flag */
		psSocket->psDevContext->sFWSoftImage.ui16ActiveContextMask &= ~(1 << psSocket->ui8FWCtxtId);

		/* Check whether this socket was marked idle (protects the global counter) */
		if (0 != ((1 << psSocket->ui8FWCtxtId) & psSocket->psDevContext->ui32IdleSocketsFlag))
		{
			/* Decrease the counter not to interfere with other streams */
			psSocket->psDevContext->ui32IdleSocketsFlag &= ~(1 << psSocket->ui8FWCtxtId);
			psSocket->psDevContext->ui32IdleSockets--;
		}

		km_Lock(psSocket->psDevContext, COMM_LOCK_STREAMS); /*global device context update*/
		/* The device context does not need this socket anymore, one slot became free */
		psSocket->psDevContext->ui32UsedSockets--;
		km_Unlock(psSocket->psDevContext, COMM_LOCK_STREAMS);
	}

	if (psSocket->hFWMessageAvailable_Sem)
	{
		SYSOSKM_DestroyEventObject(psSocket->hFWMessageAvailable_Sem);
	}

	/* Free all the resources attached to this socket */
	RMAN_DestroyBucket(psSocket->hResBHandle);

	IMG_FREE(psSocket);
}


/**
* \fn km_selectDevice
* \brief Select the device context on which to open the stream
* \param [in] ui32RequiredFeatures Features required by the context to be present on the device
* \param [in] ui32ReqPipes Number of pipes requested by user
* \param [in] ui32ConnId Device connection identifier given by user
* \param [out] ppsDevContext Selected device context
* \param [out] ppsConnData Global bucket in which to store the stream object (memory leak prevention)
* \returns
* - IMG_ERROR_GENERIC_FAILURE if the connection id is not correct (intransigent about their correctness: one failure and we exit immediately).
* - IMG_ERROR_DEVICE_NOT_FOUND if any NULL pointer is encountered.
* - IMG_ERROR_DEVICE_UNAVAILABLE if no suitable device could be found
* - IMG_SUCCESS on normal completion
* \details
* This function handles each connection identifier obtained from user space.
* It will elect the device which is less loaded and ping-pong between all devices
* in order to best split the workload evenly.
**/
static IMG_RESULT km_selectDevice(IMG_UINT32 ui32RequiredFeatures, IMG_UINT32 ui32ReqPipes,
	IMG_UINT32 aui32DeviceConnectionIds[VXE_KM_SUPPORTED_DEVICES],
	VXE_KM_DEVCONTEXT **ppsDevContext, VXE_KM_CONNDATA **ppsConnData)
{
	IMG_HANDLE hDevHandle;
	IMG_HANDLE hConnHandle;
	IMG_RESULT result;
	VXE_KM_DEVCONTEXT *psDevContext, *psElectedDevContext = NULL;
	VXE_KM_CONNDATA *psConnData, *psElectedConnData = NULL;
	IMG_UINT32 ui32DevPipes, ui32StreamUsed, ui32FeaturesFlag, ui32ReqFeatures, ui32LeastUsed = VXE_MAX_SOCKETS, i;
    IMG_INT16 i16RequestedCoreId = F_DECODE(ui32RequiredFeatures, VXEKMAPI_CORE_ID);

	/* Mask off the context specific features */
	ui32ReqFeatures = (ui32RequiredFeatures & DEVICE_LEVEL_FEATURES);
	ui32DevPipes = 0;


    if (i16RequestedCoreId != INVALID_CORE_ID)
	{
		/* a specific core has been requested so check that it is available */

        if (i16RequestedCoreId >= VXE_KM_SUPPORTED_DEVICES)
        {
            DEBUG_PRINT("%s() - Selected device out of range %d\n", __FUNCTION__);
            return IMG_ERROR_DEVICE_NOT_FOUND;
        }

        /* The device has not been discovered yet, only signal the error w/o asserting */
        result = DMANKM_GetConnHandleFromId(aui32DeviceConnectionIds[i16RequestedCoreId], &hConnHandle);
        if (result != IMG_SUCCESS)
        {

            return IMG_ERROR_GENERIC_FAILURE;
        }

        hDevHandle = DMANKM_GetDevHandleFromConn(hConnHandle);
        if (!hDevHandle)
        {
        return IMG_ERROR_DEVICE_NOT_FOUND;
        }
        psDevContext = DMANKM_GetDevInstanceData(hDevHandle);
        if (!psDevContext)
        {
        return IMG_ERROR_DEVICE_NOT_FOUND;
        }
        psConnData = DMANKM_GetDevConnectionData(hConnHandle);
        if (!psConnData)
        {
        return IMG_ERROR_DEVICE_NOT_FOUND;
        }

        ui32DevPipes = QUARTZ_KM_GetNumberOfPipes(psDevContext); /*access hardware outside the lock*/

        km_Lock(psDevContext, COMM_LOCK_STREAMS);
        ui32StreamUsed = psDevContext->ui32UsedSockets;
        ui32FeaturesFlag = psDevContext->sDevSpecs.ui32SupportedFeaturesFlag;
        km_Unlock(psDevContext, COMM_LOCK_STREAMS);

        if (ui32StreamUsed < VXE_MAX_SOCKETS && /*still some space on the device*/
            (ui32ReqFeatures & ui32FeaturesFlag) == ui32ReqFeatures && /*device supports the features this context needs*/
            (ui32DevPipes >= ui32ReqPipes)) /*device has enough pipes to satisfy the stream requirements*/
        {
            psElectedDevContext = psDevContext;
            psElectedConnData = psConnData;
        }
        DEBUG_PRINT("%s() - Selecting the device %d was successful!\n", __FUNCTION__, i16RequestedCoreId);
    }
    
    else
    {
	    /* Loop through the array */
	    for (i = 0; i < VXE_KM_SUPPORTED_DEVICES; i++)
	    {
		    /* The device has not been discovered yet, only signal the error w/o asserting */
		    result = DMANKM_GetConnHandleFromId(aui32DeviceConnectionIds[i], &hConnHandle);
		    if (result != IMG_SUCCESS)
		    {
			    return IMG_ERROR_GENERIC_FAILURE;
		    }

		    hDevHandle = DMANKM_GetDevHandleFromConn(hConnHandle);
		    if (!hDevHandle)
		    {
			    return IMG_ERROR_DEVICE_NOT_FOUND;
		    }
		    psDevContext = DMANKM_GetDevInstanceData(hDevHandle);
		    if (!psDevContext)
		    {
			    return IMG_ERROR_DEVICE_NOT_FOUND;
		    }
		    psConnData = DMANKM_GetDevConnectionData(hConnHandle);
		    if (!psConnData)
		    {
			    return IMG_ERROR_DEVICE_NOT_FOUND;
		    }

		    ui32DevPipes = QUARTZ_KM_GetNumberOfPipes(psDevContext); /*access hardware outside the lock*/

		    km_Lock(psDevContext, COMM_LOCK_STREAMS);
		    ui32StreamUsed = psDevContext->ui32UsedSockets;
		    ui32FeaturesFlag = psDevContext->sDevSpecs.ui32SupportedFeaturesFlag;
		    km_Unlock(psDevContext, COMM_LOCK_STREAMS);

		    if (ui32StreamUsed < ui32LeastUsed && /*still some space on the device*/
			    (ui32ReqFeatures & ui32FeaturesFlag) == ui32ReqFeatures && /*device supports the features this context needs*/
			    (ui32DevPipes >= ui32ReqPipes)) /*device has enough pipes to satisfy the stream requirements*/
		    {
			    psElectedDevContext = psDevContext;
			    psElectedConnData = psConnData;
			    ui32LeastUsed = ui32StreamUsed;
		    }
	    }
    }

	if (!psElectedDevContext || !psElectedConnData)
	{
		/* No device could be found */
		return IMG_ERROR_DEVICE_UNAVAILABLE;
	}

	DEBUG_PRINT("%s() - Elected device %d\n", __FUNCTION__, psElectedDevContext->sDevSpecs.ui32CoreDevIdx);

	/* Return output parameters */
	*ppsDevContext = psElectedDevContext;
	*ppsConnData = psElectedConnData;

	return IMG_SUCCESS;
}


/**
* \fn KM_OpenSocket
* \brief Setup the required fields to handle communication between KM and FW through the socket object after initialising it
* \param [in] aui32DevConnId Device connection identifiers, kernel will only read what it supports
* \param [in] eCodec Codec to be used for this socket
* \param [in] ui32FeaturesFlag Reduced set of features which state impacts latency/pipe allocation
* \param [in] ui8PipesToUse Pipes this context needs to use
* \param [out] pui32CtxtId Numeric context identifier (matches the FWCtxtId - FW_COMMAND_SOCKET_ID)
* \param [out] pui32SockId Unique socket identifier used for further access to the socket object
* \param [out] pui8FirstPipeIdx First pipe kernel allocated for this context
* \param [out] pui8LastPipeIdx Last pipe kernel allocated for this context
**/
IMG_RESULT KM_OpenSocket(SYSBRG_POINTER_ARG(IMG_UINT32) aui32DevConnId, VXE_CODEC eCodec, IMG_UINT32 ui32FeaturesFlag, IMG_UINT8 ui8PipesToUse,
	SYSBRG_POINTER_ARG(IMG_UINT8) pui8CtxtId, SYSBRG_POINTER_ARG(IMG_UINT32) pui32SockId, SYSBRG_POINTER_ARG(IMG_UINT8) pui8FirstPipeIdx, SYSBRG_POINTER_ARG(IMG_UINT8) pui8LastPipeIdx)
{
	VXE_KM_COMM_SOCKET *psSocket = IMG_NULL;
	IMG_UINT32 ui32ResourceId;
	IMG_UINT32 ui32SocketNum = 0;
	IMG_RESULT result;
	VXE_KM_CONNDATA *psConnData;
	VXE_KM_DEVCONTEXT *psDevContext;
	IMG_UINT8 ui8FirstPipe_km, ui8LastPipe_km, ui8ObtainedPipes;
	IMG_UINT32 aui32DeviceConnectionIds [VXE_KM_SUPPORTED_DEVICES];

	/* Trust the user to have send an array of valid connection id, and no more than VXE_KM_SUPPORTED_DEVICES */
	result = SYSOSKM_CopyFromUser(aui32DeviceConnectionIds, aui32DevConnId, sizeof(aui32DeviceConnectionIds));
	if (IMG_SUCCESS != result)
	{
		/* User space gave corrupted address */
		return IMG_ERROR_OPERATION_PROHIBITED;
	}

	result = km_selectDevice(ui32FeaturesFlag, ui8PipesToUse, aui32DeviceConnectionIds, &psDevContext, &psConnData);
	if (result != IMG_SUCCESS)
	{
		return result;
	}

	/** 1 - Perform some check upon device context and socket initialisation **/
	/* Device context existence */
	if (!psDevContext || !psDevContext->bInitialised)
	{
		return IMG_ERROR_NOT_INITIALISED;
	}

	if (psDevContext->bCoreNeedsToClose)
	{
		return IMG_ERROR_DEVICE_UNAVAILABLE;
	}

	/* Reasonable socket index */
	if (psDevContext->ui32UsedSockets >= VXE_MAX_SOCKETS)
	{
		return IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE;
	}

	/* Allocate the socket object (do it before locking the mutex since kmalloc() may sleep) */
	psSocket = (VXE_KM_COMM_SOCKET *)IMG_MALLOC(sizeof(VXE_KM_COMM_SOCKET));
	if (!psSocket)
	{
		return IMG_ERROR_MALLOC_FAILED;
	}

	/* Re-check if the range is valid, but this time holding the mutex */
	km_Lock(psDevContext, COMM_LOCK_STREAMS);
	/* find an empty socket */
	while(ui32SocketNum < VXE_MAX_SOCKETS)
	{
		if (psDevContext->apsDeviceSockets[ui32SocketNum] == IMG_NULL)
		{
			/* found an empty socket */
			break;
		}
		ui32SocketNum++;
	}

	if(ui32SocketNum >= VXE_MAX_SOCKETS)
	{
		/* Another process took the last slot */
		km_Unlock(psDevContext, COMM_LOCK_STREAMS);
		IMG_FREE(psSocket);
		/* We could not find an empty socket, all of them are in use */
		return IMG_ERROR_VALUE_OUT_OF_RANGE;
	}

	/** 2 - Setup the required fields **/	
	IMG_MEMSET(psSocket, 0, sizeof(VXE_KM_COMM_SOCKET));
	/* Register the socket object */
	psDevContext->apsDeviceSockets[ui32SocketNum] = psSocket;
	psDevContext->ui32UsedSockets++;

	/* Now that the device context has been updated, the lock can be released */
	km_Unlock(psDevContext, COMM_LOCK_STREAMS);

	/*
	* The socket object contains an index which mirrors which FW context it talks to.
	* This Fw context index is the same as the socket object index in the device context array of all sockets.
	* If two apps talk to one context, one will talk to FW ctx 0, the other to FW ctx 1 (FW needs to contain at least two contexts)
	*/
	psSocket->ui8FWCtxtId = ui32SocketNum & 0xff;
	psSocket->psDevContext = psDevContext;

	/* don't include the requested core id in the stored features flag */
	psSocket->ui32FeaturesFlag = ui32FeaturesFlag & (~(MASK_VXEKMAPI_CORE_ID));

	psSocket->ui32PrevHeaderNodeInfo = 0;
	psSocket->ui32CurCmdId = IDX_LOWLATENCY_NOT_STARTED;

	/* Update the codec to be used */
	psSocket->eCodec = eCodec;

	/* Create bucket to handle socket resources */
	RMAN_CreateBucket(&psSocket->hResBHandle);

	result = RMAN_RegisterResource(psConnData->hResBHandle, RMAN_SOCKETS_ID, KM_OnCloseSocket, (IMG_VOID *)psSocket, IMG_NULL, &ui32ResourceId);
	IMG_ASSERT(result == IMG_SUCCESS && "Socket resource has not been registered");
	if (result != IMG_SUCCESS)
	{
		IMG_FREE(psSocket);
		km_Lock(psDevContext, COMM_LOCK_STREAMS); /*global device context update*/
		psDevContext->apsDeviceSockets[ui32SocketNum] = NULL;
		psDevContext->ui32UsedSockets--;
		km_Unlock(psDevContext, COMM_LOCK_STREAMS);
		return result;
	}

	/* This id is used later in the kernel layer */
	psSocket->ui32ResourceId = ui32ResourceId;

	result = SYSOSKM_CreateEventObject(&psSocket->hFWMessageAvailable_Sem);
	IMG_ASSERT(result == IMG_SUCCESS && "Could not create feedback semaphore");
	if (IMG_SUCCESS != result)
	{
		KM_CloseSocket(ui32ResourceId);
	}

	/* From now on, we truly share the device context amongst several sockets - we were just adding independent entries before, so mutexes are required */
	km_Lock(psDevContext, COMM_LOCK_STREAMS);
	
	/* If we are opening the first socket, we will also initialize the firmware */
	if (!psDevContext->sFWSoftImage.bInitialized && !psDevContext->sFWSoftImage.bPopulated)
	{
		/* Check the return code first */
		result = quartz_SetupFirmware(psDevContext, psSocket->eCodec);
		if (IMG_SUCCESS != result)
		{
			km_Unlock(psDevContext, COMM_LOCK_STREAMS);
			PRINT("\nERROR: Firmware cannot be loaded! (%i)\n", result);
			return result;
		}

		/* Make sure the state is consistent */
		if (!psDevContext->sFWSoftImage.bInitialized)
		{
			km_Unlock(psDevContext, COMM_LOCK_STREAMS);
			PRINT("\nERROR: Firmware cannot be loaded!\n");
			KM_CloseSocket(ui32ResourceId);
			return IMG_ERROR_UNEXPECTED_STATE;
		}

#if defined (POLL_FOR_INTERRUPT)
		KM_StartISRThread(psDevContext);
#endif
	}
	else
	/* When we open another socket, we have to check if the codec is supported by the firmware build */
	if ( !(g_asLookupTableCodecToMask[eCodec].ui16CodecMask & (psDevContext->sFWSoftImage.sFirmwareBuildInfos.ui32FWSupportedCodecs & 0xffff)) ) // we only use 16LSB of the mask from the build, no issue for now
	{
		km_Unlock(psDevContext, COMM_LOCK_STREAMS);
		PRINT("\nERROR: Incompatible firmware! Required support for: %x Loaded FW: %x\n", g_asLookupTableCodecToMask[eCodec].ui16CodecMask, psDevContext->sFWSoftImage.sFirmwareBuildInfos.ui32FWSupportedCodecs);
		/* The selected firmware build does not support the codec we want, so destroy the socket we just created */
		KM_CloseSocket(ui32ResourceId);
		return IMG_ERROR_NOT_SUPPORTED;
	}

	/* Query the kernel to know which pipe(s) we can use, giving it the total number we ideally would use */
	ui8ObtainedPipes = QUARTZ_KM_RequestPipes(psSocket, ui8PipesToUse, &ui8FirstPipe_km, &ui8LastPipe_km);
	if (0 == ui8ObtainedPipes)
	{
		km_Unlock(psDevContext, COMM_LOCK_STREAMS);
		PRINT("\nERROR: Could not allocate the requested amount of pipe!\n");
		KM_CloseSocket(ui32ResourceId);
		return IMG_ERROR_STORAGE_TYPE_FULL;
	}

	km_Unlock(psDevContext, COMM_LOCK_STREAMS);

	/* Store the pipe index inside the stream object so we can release them properly on close */
	psSocket->ui8FirstPipeIdx = ui8FirstPipe_km;
	psSocket->ui8LastPipeIdx = ui8LastPipe_km;

	/* Copy data back from KM to UM */
	result = SYSOSKM_CopyToUser(pui8CtxtId, &psSocket->ui8FWCtxtId, sizeof(psSocket->ui8FWCtxtId));
	result |= SYSOSKM_CopyToUser(pui32SockId, &ui32ResourceId, sizeof(ui32ResourceId));
	result |= SYSOSKM_CopyToUser(pui8FirstPipeIdx, &ui8FirstPipe_km, sizeof(ui8FirstPipe_km));
	result |= SYSOSKM_CopyToUser(pui8LastPipeIdx, &ui8LastPipe_km, sizeof(ui8LastPipe_km));

	/* We expect 0 as success */
	return result;
}


/**
* \fn KM_CloseSocket
* \brief Close the socket identified by its unique id and free its related structures
* \params ui32SockId Unique socket identifier to be closed
**/
IMG_RESULT KM_CloseSocket(IMG_UINT32 ui32SockId)
{
	IMG_RESULT result;
	IMG_HANDLE resHandle;

	result = RMAN_GetResource(ui32SockId, RMAN_SOCKETS_ID, IMG_NULL, &resHandle);
	IMG_ASSERT(result == IMG_SUCCESS);
	if (result != IMG_SUCCESS)
	{
		PRINT("RMAN_GetResource(%x) returned %x\n", ui32SockId, result);
		return IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE;
	}

	/* This will trigger KM_OnCloseSocket() callback */
	RMAN_FreeResource(resHandle);

	return IMG_SUCCESS;
}


IMG_RESULT KM_LinkSocketToFW(IMG_UINT32 ui32SockId, IMG_UINT32 ui32FWVirtualAddr)
{
	IMG_RESULT eRet;
	VXE_KM_COMM_SOCKET *psSocket = IMG_NULL;

	eRet = RMAN_GetResource(ui32SockId, RMAN_SOCKETS_ID, (IMG_VOID **)&psSocket, IMG_NULL);
	IMG_ASSERT(eRet == IMG_SUCCESS);
	if (eRet != IMG_SUCCESS)
	{
		return IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE;
	}

	psSocket->ui32ContextMemory = ui32FWVirtualAddr;

	return IMG_SUCCESS;
}


/**
* \fn KM_SendCommandToFW
* \brief Insert a 4 words commands in the socket command FIFO
* \params [in] ui32SockId Unique socket object identifier
* \params [in] eCommand Command to be inserted
* \params [in] ui32DevMemBlock Offset in the context device memory pool for the external device memory allocated block - can be the virtual address too in certain cases
* \params [in] ui32CommandData Useful data for the command that can fit on 32bits and directly usable without access to the external memory
* \params [out] pui32CmdSeqNum Last unique command identifier that was sent to the FW, KM can use it to keep track of what the FW has already processed
* \return - IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE if the socket object cannot be fetched from RMAN layer
*		  - IMG_ERROR_NOT_INITIALISED if there is a problem with the device context
*		  - IMG_ERROR_INVALID_ID if the socket id is invalid
*		  - IMG_ERROR_INVALID_PARAMETERS if the socket object for this id has not been created
*		  - IMG_ERROR_COMM_COMMAND_NOT_QUEUED if the socket command FIFO is already full
*		  - IMG_ERROR_COMM_RETRY if the socket command FIFO slot cannot be found
*		  - IMG_ERROR_FATAL if a non-recognised command is being sent
*		  - IMG_SUCCESS if the command has been inserted properly
* \details
* After performing existence check for both the device context and the socket object associate with the UM context,
* this function will try (if some space is available) to insert the command in the socket command buffer (FIFO).
* Once all four words have been placed in the socket command queue, it terminates by signaling the "work queue"
* scheduling function (either the DMAN LISR or the LISR thread when we poll for interrupts) which will actually
* performs the command insertion from the KM to the command FIFO (it might not be the last command queued but a
* command for another context)
**/
IMG_RESULT KM_SendCommandToFW(IMG_UINT32 ui32SockId, IMG_UINT32 eCommand, IMG_UINT32 ui32DevMemBlock, IMG_UINT32 ui32CommandData, SYSBRG_POINTER_ARG(IMG_UINT32) pui32CmdSeqNum)
{
	IMG_UINT32 ui32CommandId;
	IMG_RESULT eRet;
	VXE_KM_COMM_SOCKET *psSocket = IMG_NULL;
	VXE_KM_DEVCONTEXT *psDevContext;

	eRet = RMAN_GetResource(ui32SockId, RMAN_SOCKETS_ID, (IMG_VOID **)&psSocket, IMG_NULL);
	if (eRet != IMG_SUCCESS)
	{
		/* Trying to send a command with an invalid stream id, just report the error */
		return IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE;
	}

	psDevContext = psSocket->psDevContext;

	/* Existence checks for the device context */
	if (!psDevContext || psDevContext->bInitialised != IMG_TRUE || psDevContext->sFWSoftImage.bInitialized != IMG_TRUE)
	{
		km_unlock_by_abort(psSocket);
		return IMG_ERROR_NOT_INITIALISED;
	}
	/* The socket index has to be a valid one */
	if (psSocket->ui8FWCtxtId >= VXE_MAX_SOCKETS)
	{
		km_unlock_by_abort(psSocket);
		return IMG_ERROR_INVALID_ID;
	}

	/* Check the socket integrity */
	if (psSocket != psDevContext->apsDeviceSockets[psSocket->ui8FWCtxtId])
	{
		km_unlock_by_abort(psSocket);
		/* there is no socket with this id */
		return IMG_ERROR_INVALID_PARAMETERS;
	}

	km_Lock(psDevContext, COMM_LOCK_TX);
	eRet = km_SendCommandToFW(psSocket, eCommand, ui32DevMemBlock, ui32CommandData, &ui32CommandId);
	km_Unlock(psDevContext, COMM_LOCK_TX);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}


	// Inform the UM level about the unique command identifier that is to be sent to the FW
	eRet = SYSOSKM_CopyToUser(pui32CmdSeqNum, &ui32CommandId, sizeof(ui32CommandId));

	/*
	* To perform the insertion job from the kernel socket object into the command FIFO at the firmware interface,
	* we delegate this task to a workqueue. DMAN layer already has this built-in mechanism where the scheduling
	* function is register as DMANKM_sDevRegister::pfnDevKmHisr.
	*/
	// Rather than create the HISR thread to schedule the command, call the scheduling function directly.
	// The only error that matters at this stage is IMG_ERROR_ALREADY_COMPLETE
	{
		IMG_RESULT eRetSchedule;
		eRetSchedule = KM_CheckAndSchedule(psDevContext);

		if ((eRet == IMG_SUCCESS) && (eRetSchedule == IMG_ERROR_ALREADY_COMPLETE))
		{
			eRet = eRetSchedule;
		}
	}

	return eRet;
}


IMG_RESULT KM_EnableFirmwareTrace(IMG_UINT32 ui32DevConnId, IMG_UINT32 ui32Size)
{
#if defined (USE_FW_TRACE)
	IMG_HANDLE hConnHandle = NULL, hDMANDevHandle = NULL;
	IMG_RESULT eRet = IMG_SUCCESS;
	VXE_KM_DEVCONTEXT *psDevContext = NULL;
	KM_DEVICE_BUFFER *psFwTraceBuffer;

	/* The device has not been discovered yet, only signal the error w/o asserting */
	eRet = DMANKM_GetConnHandleFromId(ui32DevConnId, &hConnHandle);
	if (eRet != IMG_SUCCESS)
	{
		return IMG_ERROR_NOT_INITIALISED;
	}

	hDMANDevHandle = DMANKM_GetDevHandleFromConn(hConnHandle);
	if (!hDMANDevHandle)
	{
		IMG_ASSERT(hDMANDevHandle && "Error retrieving dev handle from conn");
		return IMG_ERROR_DEVICE_NOT_FOUND;
	}

	if (!DMANKM_IsDevicePoweredOn(hDMANDevHandle))
	{
		/* device is not powered on so we can't do it ust now */
		return IMG_ERROR_NOT_INITIALISED;
	}
	psDevContext = DMANKM_GetDevInstanceData(hDMANDevHandle);

	/* Existence checks for the device context */
	if (!psDevContext || psDevContext->bInitialised != IMG_TRUE )
	{
		return IMG_ERROR_NOT_INITIALISED;
	}

	if (psDevContext->hFwTraceBuffer)
	{
		return IMG_ERROR_ALREADY_INITIALISED;
	}

	/* Allocate memory */
	TALPDUMP_Comment(NULL, "Allocate FW trace buffer");
	eRet = allocMemory((IMG_HANDLE)psDevContext, ui32Size, 64, IMG_FALSE, &psFwTraceBuffer, IMG_MAP_HOST_UM|IMG_MAP_FIRMWARE);
	IMG_ASSERT(eRet == IMG_TRUE);

	if (eRet != IMG_TRUE)
	{
		return IMG_ERROR_OUT_OF_MEMORY;
	}
	psDevContext->ui32FwTraceSize = ui32Size;
	psDevContext->hFwTraceBuffer = (IMG_HANDLE)psFwTraceBuffer;

	/* if the firmware is already initialised then tell it about the log now */
	if (psDevContext->sFWSoftImage.bInitialized == IMG_TRUE)
	{
			IMG_UINT32 ui32DevVirtAddr;

			/* write details to firmware */
			eRet = TALMMU_GetDevVirtAddress(psFwTraceBuffer->talmmuHandle, &ui32DevVirtAddr);
			IMG_ASSERT(eRet == IMG_SUCCESS);

			if (eRet != IMG_SUCCESS)
			{
				freeMemory(&psFwTraceBuffer);
				psDevContext->hFwTraceBuffer = IMG_NULL;
				return IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE;
			}

			TALPDUMP_Comment(psDevContext->sFWSoftImage.hLTPDataRam, "Tell FW about trace buffer");
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_TRACE_BASEADDR, ui32DevVirtAddr);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_TRACE_SIZE, psDevContext->ui32FwTraceSize);
	}


	return IMG_SUCCESS;
#else
	return IMG_ERROR_NOT_SUPPORTED;
#endif
}

IMG_RESULT KM_GetFirmwareTrace(IMG_UINT32 ui32DevConnId, SYSBRG_POINTER_ARG(IMG_UINT64) pui64fwLogToken,  SYSBRG_POINTER_ARG(IMG_UINT32) pui32fwLogSize, SYSBRG_POINTER_ARG(IMG_UINT32) pui32fwLogWoff)
{
#if defined (USE_FW_TRACE)
	IMG_UINT32 ui32Size, ui32Woff;
	IMG_HANDLE hConnHandle = NULL, hDMANDevHandle = NULL;
	IMG_UINT64 ui64umToken;
	IMG_RESULT eRet = IMG_SUCCESS;
	VXE_KM_DEVCONTEXT *psDevContext = NULL;
	KM_DEVICE_BUFFER *psFwTraceBuffer;

	/* The device has not been discovered yet, only signal the error w/o asserting */
	eRet = DMANKM_GetConnHandleFromId(ui32DevConnId, &hConnHandle);
	if (eRet != IMG_SUCCESS)
	{
		return IMG_ERROR_NOT_INITIALISED;
	}

	hDMANDevHandle = DMANKM_GetDevHandleFromConn(hConnHandle);
	if (!hDMANDevHandle)
	{
		IMG_ASSERT(hDMANDevHandle && "Error retrieving dev handle from conn");
		return IMG_ERROR_DEVICE_NOT_FOUND;
	}

	if (!DMANKM_IsDevicePoweredOn(hDMANDevHandle))
	{
		/* device is not powered on so we can't do it ust now */
		return IMG_ERROR_DEVICE_UNAVAILABLE;
	}

	psDevContext = DMANKM_GetDevInstanceData(hDMANDevHandle);

	/* Existence checks for the device and firmware context */
	if (!psDevContext || psDevContext->bInitialised != IMG_TRUE || psDevContext->sFWSoftImage.bInitialized != IMG_TRUE || !psDevContext->hFwTraceBuffer)
	{
		return IMG_ERROR_NOT_INITIALISED;
	}
	psFwTraceBuffer = (KM_DEVICE_BUFFER *)psDevContext->hFwTraceBuffer;

#if defined (SYSBRG_NO_BRIDGING)
	ui64umToken = (IMG_UINT64)((IMG_UINTPTR) psFwTraceBuffer->pvKmAddress);
#else
	ui64umToken = ((KM_DEVICE_BUFFER *)psDevContext->hFwTraceBuffer)->ui64umToken;
#endif
	TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_TRACE_SIZE, &ui32Size);
	TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_TRACE_WOFF, &ui32Woff);

	/* we don't want to pdump this */
	TALPDUMP_Comment(NULL, "Save out firmware trace buffer");
	updateHostMemory(psFwTraceBuffer);

	SYSOSKM_CopyToUser(pui32fwLogSize, &ui32Size, sizeof(ui32Size));
	SYSOSKM_CopyToUser(pui32fwLogWoff, &ui32Woff, sizeof(ui32Woff));
	SYSOSKM_CopyToUser(pui64fwLogToken, &ui64umToken, sizeof(IMG_UINT64));

	return IMG_SUCCESS;
#else
	return IMG_ERROR_NOT_SUPPORTED;
#endif
}

IMG_RESULT KM_SendLowLatencyCommand_API(VXE_KM_COMM_SOCKET *psSocket, SYSBRG_POINTER_ARG(VXE_FWMESSAGE_TYPE) peMessage, SYSBRG_POINTER_ARG(IMG_UINT32) pui32Data, SYSBRG_POINTER_ARG(IMG_UINT32) pui32ExtraInfo)
{
	VXE_FWMESSAGE_TYPE eMessage_km;
	IMG_UINT32 ui32Data_km, ui32ExtraInfo_km;
	IMG_UINT32 ui32CodedHeaderIdx;
	IMG_UINT32 ui32NodeCntThisSlice;
	IMG_UINT32 ui32APICmdIdSig;
	IMG_UINT32 ui32SocketCmdIdSig;
	IMG_UINT32 ui32IndexOfCodedList;
	IMG_UINT32 ui32SendType;
	IMG_UINT32 ui32NewNodeCnt;
	IMG_UINT32 ui32ThisHeaderNodeInfo;
	IMG_RESULT eRet;

	// If KM is active and we're running with interrupts, the value of the socket prevheadernodeinfo could be changed while we use it here
	// We'll copy it locally (aotmic operation) here so that this code is guaranteed to be reacting to a correct message
	ui32ThisHeaderNodeInfo = psSocket->ui32PrevHeaderNodeInfo;


	ui32SendType = (F_DECODE(ui32ThisHeaderNodeInfo, FW_PIPELOWLATENCYINFO_SEND));



	IMG_ASSERT(ui32SendType > 0 && "Illegal send type in KM_SendLowLatencyCommand_API");

	ui32CodedHeaderIdx = (F_DECODE(ui32ThisHeaderNodeInfo, FW_PIPELOWLATENCYINFO_HEADCNT)) - 1;
	ui32NodeCntThisSlice = F_DECODE(ui32ThisHeaderNodeInfo, FW_PIPELOWLATENCYINFO_NODECNTTHISHEADER);

	ui32APICmdIdSig = F_DECODE(ui32ThisHeaderNodeInfo, FW_PIPELOWLATENCYINFO_CMDID_SIG);

	// If the per-tile node counter is positive attempt to pass on a node full notification
	// Only add the low latency message if it for the currently encoding frame (not generated in the past)

	// Ensure we'll be checking the same representation of the command ID (frame ID) as that passed from the register
	if (psSocket->ui32CurCmdId != IDX_LOWLATENCY_NOT_STARTED)
	{
		ui32SocketCmdIdSig = psSocket->ui32CurCmdId & (MASK_FW_PIPELOWLATENCYINFO_CMDID_SIG >> SHIFT_FW_PIPELOWLATENCYINFO_CMDID_SIG);
	}
	else
	{
#if ! defined (SILENCE_LOW_LATENCY_DEBUG)
		DEBUG_PRINT("Context[%d]: KM_SendLowLatencyCommand_API() - %s low latency message Frame CmdId %i (HeaderCnt %i, NodeCnt %i) rejected (low latency mode not active on that context).\n", psSocket->ui8FWCtxtId, (ui32NodeCntThisSlice ? "NODE FILLED" : "CODED HEADER"), ui32APICmdIdSig, ui32CodedHeaderIdx + 1, ui32NodeCntThisSlice);
#endif
		return IMG_ERROR_CANCELLED;
	}


	if (ui32APICmdIdSig == ui32SocketCmdIdSig)
	{
		ui32IndexOfCodedList = psSocket->ui32CurCodedList;

		eMessage_km = VXE_FWMSG_CODED_BUFFER;

#if ! defined (SILENCE_LOW_LATENCY_DEBUG)
		DEBUG_PRINT("\nContext[%d]: KM_SendLowLatencyCommand_API() - Sending LOW LATENCY message for Command Id: %i\n", psSocket->ui32CurCmdId);
#endif
		ui32Data_km = F_ENCODE(VXE_FWMSG_CODED_BUFFER, FW_FEEDBACK_MSG_TYPE) |
			F_ENCODE(psSocket->ui32CurCmdId, FW_FEEDBACK_COMMAND_ID) | // Use the full version of the command ID as stored by the KM Socket
			F_ENCODE(psSocket->ui8FWCtxtId, FW_FEEDBACK_CONTEXT_ID);

		if (ui32SendType == LL_NODE_FULL_TYPE)
		{

			if (ui32NodeCntThisSlice <= psSocket->ui32PrevNodeCnt)
			{
				IMG_ASSERT(ui32NodeCntThisSlice > psSocket->ui32PrevNodeCnt && "ERROR: Unexpected node counts, setting to 1");
				ui32NewNodeCnt = 1;
			}
			else
			{
				ui32NewNodeCnt = ui32NodeCntThisSlice - psSocket->ui32PrevNodeCnt;
			}
			
			// This is a new node entry that should be passed to API
			ui32ExtraInfo_km = F_ENCODE(0, FW_FEEDBACK_FULLHEADERRETURN) |
				F_ENCODE(0, FW_FEEDBACK_FINALCODEDOUTPUTFLAG) |
				F_ENCODE(ui32IndexOfCodedList, FW_FEEDBACK_CBLISTINDEX) |
				F_ENCODE(ui32NewNodeCnt, FW_FEEDBACK_EXTRAINFOWORD);

#if ! defined (SILENCE_LOW_LATENCY_DEBUG)
			DEBUG_PRINT("Context[%d]: KM_SendLowLatencyCommand_API() - NODE FILLED low latency message Frame CmdId %i (IndexOfCodedList %i, HeaderCnt %i, NodeCnt %i (%i - %i)) received and added to Context[%d] API FIFO\n", psSocket->ui8FWCtxtId, ui32APICmdIdSig, ui32IndexOfCodedList, ui32CodedHeaderIdx + 1, ui32NodeCntThisSlice - psSocket->ui32PrevNodeCnt, ui32NodeCntThisSlice, psSocket->ui32PrevNodeCnt, psSocket->ui8FWCtxtId);
#endif
		}
		else
		{
			// This is a new coded header entry that should be passed to API
			ui32ExtraInfo_km = F_ENCODE(1, FW_FEEDBACK_FULLHEADERRETURN) |
				F_ENCODE(0, FW_FEEDBACK_FINALCODEDOUTPUTFLAG) |
				F_ENCODE(ui32IndexOfCodedList, FW_FEEDBACK_CBLISTINDEX) |
				F_ENCODE(ui32CodedHeaderIdx, FW_FEEDBACK_EXTRAINFOWORD);

#if ! defined (SILENCE_LOW_LATENCY_DEBUG)
			DEBUG_PRINT("Context[%d]: KM_SendLowLatencyCommand_API() - CODED HEADER low latency message Frame CmdId %i (HeaderCnt %i) received and added to API FIFO\n", psSocket->ui8FWCtxtId, ui32APICmdIdSig, ui32CodedHeaderIdx + 1);
#endif
		}

		// Mock up the new message for this sockets FIFO
		/* Copy back data from KM to UM */
		eRet = SYSOSKM_CopyToUser(peMessage, &eMessage_km, sizeof(eMessage_km));
		eRet |= SYSOSKM_CopyToUser(pui32Data, &ui32Data_km, sizeof(ui32Data_km));
		eRet |= SYSOSKM_CopyToUser(pui32ExtraInfo, &ui32ExtraInfo_km, sizeof(ui32ExtraInfo_km));
		/* eRet is expected to be (0 | 0 | 0) = 0 == IMG_SUCCESS */

#ifndef REMOVE_LL_COUNTERS
		psSocket->ui32LowLatencyMsgsReceivedAndSentToAPI++;
#endif

		// If the prevheadernodeinfo hasn't been changed by an interrupt then we should mark this command as processed (clear the send bit), if it has then leave it alone so that the new LL command can be picked up next time.
		if (ui32ThisHeaderNodeInfo == psSocket->ui32PrevHeaderNodeInfo)
			psSocket->ui32PrevHeaderNodeInfo &= ~(MASK_FW_PIPELOWLATENCYINFO_SEND); //Clear the send bit

#if defined(IMG_KERNEL_MODULE)
		psSocket->ui32PrevNodeCnt = ui32NodeCntThisSlice; // Mark these nodes as having been sent (psSocket->ui32PrevNodeCnt is not altered by the KM ISR routines so should be thread safe)
#endif

		return eRet;
	}
	else
	{
#if ! defined (SILENCE_LOW_LATENCY_DEBUG)
		DEBUG_PRINT("Context[%d]: KM_SendLowLatencyCommand_API() - %s low latency message Frame CmdId %i (HeaderCnt %i, NodeCnt %i) encountered during Frame CmdId %i and rejected.\n", psSocket->ui8FWCtxtId, (ui32SendType == LL_NODE_FULL_TYPE ? "NODE FILLED" : "CODED HEADER"), ui32APICmdIdSig, ui32CodedHeaderIdx+1, ui32NodeCntThisSlice, ui32SocketCmdIdSig);
#endif
		return IMG_ERROR_CANCELLED;
	}
}


/**
* \fn KM_WaitForMessageFW
* \brief Waits for the next feedback message from Firmware for a given context
* \params [in] ui32SockId Socket unique id on which feedback should come back from FW
* \params [out] peMessage The feedback message type that came back
* \params [out] pui32Data Data associated with the message that came back (first word)
* \params [out] pui32ExtraInfo Extra data associated with the message that came back (second word)
**/
IMG_RESULT KM_WaitForMessageFW(IMG_UINT32 ui32SockId, SYSBRG_POINTER_ARG(VXE_FWMESSAGE_TYPE) peMessage, SYSBRG_POINTER_ARG(IMG_UINT32) pui32Data, SYSBRG_POINTER_ARG(IMG_UINT32) pui32ExtraInfo)
{
	VXE_KM_COMM_SOCKET *psSocket = IMG_NULL;
	VXE_KM_DEVCONTEXT *psDevContext;
	// Kernel space variables used to extract information
	VXE_FWMESSAGE_TYPE eMessage_km;
	IMG_UINT32 ui32Data_km, ui32ExtraInfo_km;
	IMG_BOOL bActivateHISR;

	IMG_RESULT eRet;

	eRet = RMAN_GetResource(ui32SockId, RMAN_SOCKETS_ID, (IMG_VOID **)&psSocket, IMG_NULL);
	/* Waiting for a command to come back implies that the stream _must_ exist, otherwise the error is fatal. That is why we assert */
	IMG_ASSERT(eRet == IMG_SUCCESS);
	if (eRet != IMG_SUCCESS)
	{
		/* there is no socket with this id */
		return IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE;
	}

	psDevContext = psSocket->psDevContext;

	if (!psDevContext || !psDevContext->bInitialised)
	{
		return IMG_ERROR_NOT_INITIALISED;
	}

	if (psSocket->ui8FWCtxtId >= VXE_MAX_SOCKETS)
	{
		return IMG_ERROR_INVALID_ID;
	}

	eRet = km_handle_abnornal_abort(psSocket);
	if (IMG_ERROR_GENERIC_FAILURE == eRet)
	{
		/* Abnormal abort, go back the user-space */
		return eRet;
	}

#if defined (POLL_FOR_INTERRUPT)
	/* When polling for interrupt, delay the boolean update as long as we know for certain that feedback is coming back (for pdump replay) */
	if (km_SocketIsIdle(psSocket) && km_SocketFBfifoIsEmpty(psSocket))
#else
	/* If we don't poll for interrupt and there is nothing to do, we return otherwise we would stall */
	if (km_SocketFBfifoIsEmpty(psSocket))
#endif
	{
		/* A socket might be idle because the final deactivate command has not been sent since the socket was already inactive */
		if (psSocket->bStreamShutdown)
		{
			/* We need to signal the UM that the second deactivation has completed */
			eMessage_km = VXE_FWMSG_ACK;
			ui32Data_km = F_ENCODE(VXE_COMMAND_DEACTIVATE_CONTEXT, FW_FEEDBACK_COMMAND_TYPE);
			ui32ExtraInfo_km = 0xbaadf00d; /*UM shall never try to dereference/extract something from it*/

			/* Copy back data from KM to UM */
			eRet = SYSOSKM_CopyToUser(peMessage, &eMessage_km, sizeof(eMessage_km));
			eRet |= SYSOSKM_CopyToUser(pui32Data, &ui32Data_km, sizeof(ui32Data_km));
			eRet |= SYSOSKM_CopyToUser(pui32ExtraInfo, &ui32ExtraInfo_km, sizeof(ui32ExtraInfo_km));
			/* eRet is expected to be (0 | 0 | 0) = 0 == IMG_SUCCESS */

			DEBUG_PRINT("%s() - Mocking-up deactivate unlock message for context %d\n", __FUNCTION__, psSocket->ui8FWCtxtId);

			/* Giving a try to the workqueue is not expensive and since it could be locked-up we will do it */
			DMANKM_ActivateKmHisr(psDevContext->hDMANDevHandle);
			/* UM will treat this ack as normal completion */
			return eRet;
		}
		else
		{
#if defined(IMG_KERNEL_MODULE) // This code _should_ work with or without the module, defining it out of non-kernel module to get pdump playback matching
			// See if we need to mock up a fake node or header message for low latency mode (a non-zero ctx field in this register signifies a new message)
			if (F_DECODE(psSocket->ui32PrevHeaderNodeInfo, FW_PIPELOWLATENCYINFO_SEND))
			{
				if (KM_SendLowLatencyCommand_API(psSocket, peMessage, pui32Data, pui32ExtraInfo) == IMG_SUCCESS)
				{
					return IMG_SUCCESS; // Low Latency Command has been inserted, return so we don't overwrite it with FIFO commands.
				}
			}
#endif
		}

#if !defined(IMG_KERNEL_MODULE) 
		/* When idle, we want the UM to wait a bit more */
		return IMG_ERROR_COMM_RETRY;
#endif
	}


#if defined (OUTPUT_COMM_STATS)
	Output_COMM_Stats_To_File(psSocket, "COMM_Recv", -1, "COMM_Track.txt");
#endif

#if defined (POLL_FOR_INTERRUPT)
	/* This socket issued a command, it will expect some feedback */
	psSocket->b8StreamWaiting = IMG_TRUE;
#endif

	DEBUG_PRINT("%s() - Context %d waiting for message return\n\n", __FUNCTION__, psSocket->ui8FWCtxtId);

	while (km_SocketFBfifoIsEmpty(psSocket))
	{
		/* Wait for the message to arrive */
		eRet = SYSOSKM_WaitEventObject(psSocket->hFWMessageAvailable_Sem, IMG_FALSE);

#if defined(IMG_KERNEL_MODULE) // This code _should_ work with or without the module, defining it out of non-kernel module to get pdump playback matching
		// See if we need to mock up a fake node or header message for low latency mode (a non-zero ctx field in this register signifies a new message)
		if (F_DECODE(psSocket->ui32PrevHeaderNodeInfo, FW_PIPELOWLATENCYINFO_SEND))
		{
			if (KM_SendLowLatencyCommand_API(psSocket, peMessage, pui32Data, pui32ExtraInfo) == IMG_SUCCESS)
			{
				return IMG_SUCCESS; // Low Latency Command has been inserted, return so we don't overwrite it with FIFO commands.
			}
		}
#endif

		/* We can be interrupted during the wait */
		if (eRet != IMG_SUCCESS)
		{
			DEBUG_VERBOSE_PRINT("%s() - Global wait queue has been signaled but not for FW feedback\n", __FUNCTION__);
#if defined (POLL_FOR_INTERRUPT)
			/* We do not want to stall the poller in case we have been interrupted */
			psSocket->b8StreamWaiting = IMG_FALSE;
#endif

			eRet = km_handle_abnornal_abort(psSocket);
			if (IMG_ERROR_GENERIC_FAILURE == eRet)
			{
				/* Abnormal abort, step out of the while loop */
				break;
			}


			/* This is not an error */
			return IMG_ERROR_COMM_RETRY;
		}

		eRet = km_handle_abnornal_abort(psSocket);
		if (IMG_ERROR_GENERIC_FAILURE == eRet)
		{
			/* Abnormal abort, step out of the while loop */
			break;
		}
	}

	eRet = km_handle_abnornal_abort(psSocket);
	if (IMG_SUCCESS == eRet)
	{

		// See if we need to mock up a fake node or header message for low latency mode (a non-zero ctx field in this register signifies a new message)
		if (F_DECODE(psSocket->ui32PrevHeaderNodeInfo, FW_PIPELOWLATENCYINFO_SEND))
		{
			if (KM_SendLowLatencyCommand_API(psSocket, peMessage, pui32Data, pui32ExtraInfo) == IMG_SUCCESS)
			{
				return IMG_SUCCESS; // Low Latency Command has been inserted, return so we don't overwrite it with FIFO commands.
			}
		}
	}

#if defined (POLL_FOR_INTERRUPT)
	/* One some feedback has been received, so we are not waiting anymore because we want to process it */
	psSocket->b8StreamWaiting = IMG_FALSE;
#endif

	/* The socket feedback FIFO is not empty */
	if (psSocket->ui8OutgoingFIFOConsumer != psSocket->ui8OutgoingFIFOProducer)
	{
		IMG_UINT32* pui32SocketFIFOSlot = &psSocket->aui32OutgoingFIFO[psSocket->ui8OutgoingFIFOConsumer * FEEDBACK_FIFO_WORD_PER_COMMANDS];

		/* Access the content of the device memory */
		if (pui32SocketFIFOSlot)
		{
			/* Fetch the message type first (further decoding is not the duty of the KM layer) */
			eMessage_km			= (VXE_FWMESSAGE_TYPE)F_EXTRACT(pui32SocketFIFOSlot[0], FW_FEEDBACK_MSG_TYPE);
			ui32Data_km			= pui32SocketFIFOSlot[0];
			ui32ExtraInfo_km	= pui32SocketFIFOSlot[1];
			bActivateHISR = psDevContext->bCommandsWaiting;

			/* Command successfully read */
			psSocket->ui8OutgoingFIFOConsumer++;
			/* Eventually wrap around the feedback FIFO */
			if (psSocket->ui8OutgoingFIFOConsumer == FEEDBACK_FIFO_MAX_COMMANDS)
			{
				psSocket->ui8OutgoingFIFOConsumer = 0;
			}

			if (eMessage_km == VXE_FWMSG_ACK)
			{
				switch (F_EXTRACT(ui32Data_km, FW_FEEDBACK_COMMAND_TYPE))
				{
				case VXE_COMMAND_ENCODE_FRAME:
					/* If proper feedback has been extracted, update the socket counter */
					psSocket->ui32EncCmdCount--;

#ifndef REMOVE_LL_COUNTERS
					DEBUG_PRINT("KM_WaitForMessageFW() - End of Frame Low Latency Results - (Sent from KM %i, Received %i)\n", psSocket->ui32LowLatencyMsgsSentFromKM, psSocket->ui32LowLatencyMsgsReceivedAndSentToAPI);
					psSocket->ui32LowLatencyMsgsSentFromKM = psSocket->ui32LowLatencyMsgsReceivedAndSentToAPI = 0;
#endif

					/* Signal that we have seen this encode command comming back (slot can be recycled) */
					psSocket->asEncCmdHistory[psSocket->ui8EncCmdHistoryCons].bEncodeHasBeenSeen = IMG_TRUE;
					psSocket->ui8EncCmdHistoryCons++;
					if (psSocket->ui8EncCmdHistoryCons >= VXE_KM_MAX_ENCODE_ISSUED)
					{
						psSocket->ui8EncCmdHistoryCons = 0;
					}

					// If we receive an encode complete we should always check the HISR (CheckAndSchedule) thread in case an encode command is waiting to be sent to HW 
					bActivateHISR = IMG_TRUE;
					break;
				case VXE_COMMAND_ABORT_CONTEXT:
					/* Signal that this stream has been aborted to the whole kernel layer */
					psSocket->b8StreamAborted = IMG_TRUE;

					km_Lock(psDevContext, COMM_LOCK_TX);
					/* The abort on flight came back, it is not expected to see another abort fr this stream before reactivation */
					psSocket->sPendingAbort.bAbortSent = IMG_FALSE;
					psSocket->sPendingAbort.bAbortPending = IMG_FALSE;
					km_Unlock(psDevContext, COMM_LOCK_TX);
					break;
				case VXE_COMMAND_DEACTIVATE_CONTEXT:
					/* A deactivate command being received means the context is inactive unless other commands are in flight after that */
					km_Lock(psDevContext, COMM_LOCK_TX);
					if (km_SocketIsIdle(psSocket) && (psSocket->ui8OutgoingFIFOConsumer == psSocket->ui8OutgoingFIFOProducer))
					{
						/* there are no commands in the firmware and no queued responses waiting for us */
						psDevContext->sFWSoftImage.ui16ActiveContextMask &= ~(1 << psSocket->ui8FWCtxtId);
					}
					km_Unlock(psDevContext, COMM_LOCK_TX);
					break;
				default:
					/* Any other commands (much less frequent than encode commands) */
					break;
				}
			}

			else if (eMessage_km == VXE_FWMSG_CODED_BUFFER)
			{
				if (F_EXTRACT(ui32ExtraInfo_km, FW_FEEDBACK_FULLHEADERRETURN) && 
					F_EXTRACT(ui32ExtraInfo_km, FW_FEEDBACK_FINALCODEDOUTPUTFLAG))
				{
					// Final End Of Tile Header - deactivate low latency mode for this context
					psSocket->ui32CurCmdId = IDX_LOWLATENCY_NOT_STARTED; // No frame encoding - no low latency output possible
				}
			}

			else if (eMessage_km == VXE_FWMSG_FRAME_LOWLATENCY_INIT)
			{
				// New low latency activation, reset our stored register value
 				psSocket->ui32PrevHeaderNodeInfo = 0;
				psSocket->ui32PrevNodeCnt = 0;
				// Low latency setup information for KM only (not to be passed on to API)
				psSocket->ui32CurCmdId = F_EXTRACT(ui32Data_km, FW_FEEDBACK_COMMAND_ID);

				DEBUG_PRINT("KM_WaitForMessageFW() - Low Latency activation message received for context %d (Frame CmdId: %i)\n", psSocket->ui8FWCtxtId, psSocket->ui32CurCmdId);

#ifndef REMOVE_LL_COUNTERS
				psSocket->ui32LowLatencyMsgsSentFromKM = psSocket->ui32LowLatencyMsgsReceivedAndSentToAPI = 0;
#endif

				// Return without needing to pass this message on to the API
				eRet = IMG_ERROR_COMM_RETRY;
			}
			else if (eMessage_km == VXE_FWMSG_ERROR)
			{
				PRINT("%s() - Firmware reported error %04x for context %i\n", __FUNCTION__,
					F_EXTRACT(ui32Data_km, FW_FEEDBACK_COMMAND_ID),
					F_EXTRACT(ui32Data_km, FW_FEEDBACK_CONTEXT_ID));
			}

			//TALPDUMP_Comment(hLTPDataRam, "KM: FIFO COMMAND SENT TO API");

			if (IMG_SUCCESS == eRet)
			{
				/* Copy back data from KM to UM */
				eRet = SYSOSKM_CopyToUser(peMessage, &eMessage_km, sizeof(eMessage_km));
				eRet |= SYSOSKM_CopyToUser(pui32Data, &ui32Data_km, sizeof(ui32Data_km));
				eRet |= SYSOSKM_CopyToUser(pui32ExtraInfo, &ui32ExtraInfo_km, sizeof(ui32ExtraInfo_km));
				/* eRet is expected to be 0 after the above 3 calls (0 | 0 | 0) = 0 == IMG_SUCCESS */

				DEBUG_PRINT("%s() - Message %i received for context %d\n", __FUNCTION__, eMessage_km, psSocket->ui8FWCtxtId);

				/* It is after dequeuing some feedback (eventually an encode command) that the workqueue should be given a try */
				// Only check the workqueue if there is the possibility of something to do (FIFO has commands waiting or an encode frame command was waiting for an encode complete acknowledgment)
				if (bActivateHISR)
					DMANKM_ActivateKmHisr(psDevContext->hDMANDevHandle);

#if defined (OUTPUT_COMM_STATS)
				Output_COMM_Stats_To_File(psSocket, "COMM_Recv Exit", F_DECODE(ui32Data_km, FW_FEEDBACK_COMMAND_TYPE), "COMM_Track.txt");
#endif
			}
		}

		/* Print a message to kernel ring buffer, missing feedback will have side effects later on. */
		if (VXE_KM_STREAM_EVENTS_FEEDBACK_LOST & psSocket->ui32StreamStateFlags)
		{
			PRINT("%s() - Stream [%i] feedback could not be queued by ISR and has been lost. Clearing this event.\n", __FUNCTION__, psSocket->ui8FWCtxtId);
			psSocket->ui32StreamStateFlags &= ~VXE_KM_STREAM_EVENTS_FEEDBACK_LOST;
		}
	}

#if defined (DEBUG_REG_OUTPUT)
	// Dump some registers
	//DBG_dump_reg();
#endif

	/* The feedback has been dequeued but the stream may have been aborted because of internal problems */
	if (IMG_SUCCESS == km_handle_abnornal_abort(psSocket))
	{
		/* It might be IMG_SUCCESS or IMG_ERROR_COMM_RETRY if there was no feedback */
		return eRet;
	}

	/* Error condition */
	return IMG_ERROR_GENERIC_FAILURE;
}


/********************************************* QUARTZ SPECIFIC FUNCTIONS ***************************************************/


/**
* \fn QUARTZ_KM_GetNumberOfPipes
* \brief Access the register holding the number of pipe that the hardware supports
* \param psDevContext Device we want to read register from
* \return The number of pipes read from the multipipe registers bank
**/
IMG_UINT32 QUARTZ_KM_GetNumberOfPipes(VXE_KM_DEVCONTEXT *psDevContext)
{
	if (!psDevContext)
	{
		/* If we can't find a device context then we can't access the banks */
		return 0;
	}

	if (0 == psDevContext->sDevSpecs.ui32NumberOfPipes)
	{
		km_populate_hw_config(psDevContext);

		/* Bit 2:0 contains the number of pipes supported by the hardware */
		psDevContext->sDevSpecs.ui32NumberOfPipes = F_EXTRACT(psDevContext->sDevSpecs.sHWConfig.ui32CoreConfig, QUARTZ_TOP_QUARTZ_NUM_ENCODER_PIPES);

		IMG_ASSERT(0 != psDevContext->sDevSpecs.ui32NumberOfPipes);

		/* We should never come back here to read the register again */
	}

	return psDevContext->sDevSpecs.ui32NumberOfPipes;
}

/**
* \fn QUARTZ_KM_GetCoreConfig
* \brief Access the three register containing the features supported by the HW
* \param [in] ui32ConnId Unique identifier for the connection KM => device
* \param [out] psHwConfig Set of hardware configuration register values
* \return	- IMG_SUCCESS on normal completion
**/
IMG_RESULT QUARTZ_KM_GetCoreConfig(IMG_UINT32 ui32ConnId, SYSBRG_POINTER_ARG(VXE_HW_CONFIG) psHwConfig)
{
	VXE_KM_DEVCONTEXT *psDevContext = NULL;
	IMG_HANDLE hConnHandle = NULL, hDMANDevHandle = NULL;
	IMG_RESULT eRet = IMG_SUCCESS;

	eRet = DMANKM_GetConnHandleFromId(ui32ConnId, &hConnHandle);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(IMG_SUCCESS == eRet);
		return eRet;
	}
	hDMANDevHandle = DMANKM_GetDevHandleFromConn(hConnHandle);
	IMG_ASSERT(NULL != hDMANDevHandle);
	if (NULL != hDMANDevHandle)
	{
		psDevContext = (VXE_KM_DEVCONTEXT*)DMANKM_GetDevInstanceData(hDMANDevHandle);
	}
	IMG_ASSERT(NULL != psDevContext && "Core config registers cannot be accessed");

	if (!psDevContext)
	{
		/* If we can't find a device context then we can't access the banks */
		return IMG_ERROR_FATAL;
	}

	eRet = km_populate_hw_config(psDevContext);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(IMG_SUCCESS == eRet);
		return eRet;
	}


	/* Copy the data back to user */
	eRet = SYSOSKM_CopyToUser(psHwConfig, &psDevContext->sDevSpecs.sHWConfig, sizeof(psDevContext->sDevSpecs.sHWConfig));

	IMG_ASSERT(eRet == IMG_SUCCESS); 

	return eRet;
}


/**
* \fn QUARTZ_KM_GetConnIdFromSockId
* \brief Fetches the connection id from an already openned stream
* \param [in] ui32SockId Unique stream identifier (UM => KM) [obtained when calling #KM_OpenSocket()]
* \param [out] pui32ConnId Global device connection id to which this stream is attached (KM => device)
* \return	- IMG_SUCCESS on normal completion
*			- IMG_ERROR_FATAL if the socket is not connected to any device context
**/
IMG_RESULT QUARTZ_KM_GetConnIdFromSockId(IMG_UINT32 ui32SockId, SYSBRG_POINTER_ARG(IMG_UINT32) pui32ConnId)
{
	VXE_KM_COMM_SOCKET *psSocket = NULL;
	VXE_KM_DEVCONTEXT *psDevContext = NULL;
	IMG_RESULT eRet;

	/* Find the socket object */
	eRet = RMAN_GetResource(ui32SockId, RMAN_SOCKETS_ID, (void**)&psSocket, NULL);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

	/* Access the device context */
	psDevContext = psSocket->psDevContext;
	if (!psDevContext)
	{
		/* If the context is not part of the socket object, there is nothing we can do */
		return IMG_ERROR_FATAL;
	}

	/* device context (=> connection handle) => connection id */
	eRet = SYSOSKM_CopyToUser(pui32ConnId, &psDevContext->ui32ConnId, sizeof(psDevContext->ui32ConnId));
	
	return eRet;
}


/**
* \fn km_applyFeaturesWeight
* \brief Based on the flag given as parameter, apply the pre-defined weights depending on features' presence
* \param ui32FeaturesFlag Bit flag on the features this context uses
* \return Combined weight of the independant features
**/
static IMG_UINT16 km_applyFeaturesWeight(IMG_UINT32 ui32FeaturesFlag)
{
	IMG_UINT32 ui32Final;
	IMG_UINT32 tmp;

	if (F_DECODE(ui32FeaturesFlag, VXEKMAPI_HWINPUT_FEATURE))
	{
		return VXEKMAPI_HWINPUT_FEATURE_WEIGHT;
	}

	tmp = F_DECODE(ui32FeaturesFlag, VXEKMAPI_ENCDIM_FEATURE) + F_DECODE(ui32FeaturesFlag, VXEKMAPI_ENCRES_FEATURE) + F_DECODE(ui32FeaturesFlag, VXEKMAPI_FRAMERATE_FEATURE);
	
	ui32Final = ((tmp > 0 ? tmp : 1) * (VXEKMAPI_ENCDIM_FEATURE_WEIGHT + VXEKMAPI_ENCRES_FEATURE_WEIGHT + VXEKMAPI_FRAMERATE_FEATURE_WEIGHT));
	ui32Final += (F_DECODE(ui32FeaturesFlag, VXEKMAPI_LOWLATENCY_FEATURE) * VXEKMAPI_LOWLATENCY_FEATURE_WEIGHT);

	return ui32Final > VXEKMAPI_MAX_FEATURE_WEIGHT ? VXEKMAPI_MAX_FEATURE_WEIGHT : ((IMG_UINT16)ui32Final);
}


/**
* \fn QUARTZ_KM_RequestPipes
* \brief Query the kernel module to know which pipe(s) a context may use
* \params [in] psSocket Reference on socket, connected to a target device from which we will get the pipes
* \params [in] ui8Ideal UM requested that many pipes
* \params [out] pui8FirstPipe First pipe index to use
* \params [out] pui8LastPipe Last pipe index to use
* \return The number of pipes KM gave to this UM context
**/
IMG_UINT8 QUARTZ_KM_RequestPipes(VXE_KM_COMM_SOCKET *psSocket, IMG_UINT8 ui8Ideal, IMG_UINT8 *pui8FirstPipe, IMG_UINT8 *pui8LastPipe)
{
	IMG_UINT8 ui8Idx;
	IMG_UINT16 ui16WeightToApply = 0;
	IMG_UINT8 ui8FirstPipe_km, ui8LastPipe_km, ui8AllocatedPipes_km;
	/* Get the hardware info, hardly more than 255 */
	IMG_UINT8 ui8HWPipes = QUARTZ_KM_GetNumberOfPipes(psSocket->psDevContext) & 0xff;
	if (0 == ui8HWPipes)
	{
		/* Error condition if the device could not be found */
		return 0;
	}

	/* 
	* More advanced pipe selection can only happen if there is more than one pipe.
	* With only one hardware pipe, each context gets pipe0.
	*/
	if (ui8HWPipes > 1)
	{
		if (psSocket->psDevContext->sSchedModel.eSchedModel != e_NO_SCHEDULING_SCENARIO && NULL != psSocket->psDevContext->sSchedModel.pvAllocation)
		{
			/* Shortening the lines */
			VXE_KM_DEVCONTEXT *psDevContext = psSocket->psDevContext;
			IMG_UINT32 i;

			/* Compilation warning about uninitialized variables */
			ui8FirstPipe_km = 0; ui8LastPipe_km = 0; ui8AllocatedPipes_km = 0;

			if (ui8HWPipes < psDevContext->sSchedModel.ui32NumberOfPipes || psDevContext->ui32UsedSockets > psDevContext->sSchedModel.ui32NumberOfContexts)
			{
				/* Can't deal with the situation */
				return 0;
			}

			for (i = 0; i < psDevContext->sSchedModel.ui32NumberOfContexts; i++)
			{
				if ((psSocket->ui32FeaturesFlag == psDevContext->sSchedModel.pui32CtxFeatures[i]) && (IMG_FALSE == psDevContext->sSchedModel.pb8ContextAllocated[i]))
				{
					ui8FirstPipe_km = psDevContext->sSchedModel.pui8FirstPipeIdx[i];
					ui8LastPipe_km = psDevContext->sSchedModel.pui8LastPipeIdx[i];
					ui8AllocatedPipes_km = ui8LastPipe_km - ui8FirstPipe_km + 1;

					psSocket->ui8RoundRobinThresh = psDevContext->sSchedModel.pui8RoundRobinThresh[i];
					psSocket->ui16CtxIdxInSchedModel = i;

					psDevContext->aui32RoundRobinWeights[psSocket->ui8FWCtxtId] = psDevContext->sSchedModel.pui32RoundRobinWeight[i];
					psDevContext->sSchedModel.pb8ContextAllocated[i] = IMG_TRUE;

					psDevContext->sSchedModel.pui32SchedulingOrderToFWCtxtId[i] = psSocket->ui8FWCtxtId;

					/* This will lock down the pipe completely */
					ui16WeightToApply = VXEKMAPI_MAX_FEATURE_WEIGHT;

					/* Found it */
					break;
				}
			}
			 
			if (i >= psDevContext->sSchedModel.ui32NumberOfContexts)
			{
				PRINT("\nThis context does not fit in the kernel scheduling model.\n");
				return 0;
			}
		}
		else
		{
			IMG_UINT8 ui8MaxBound;
			IMG_UINT8 ui8SmallestIndex = 0xff;
			IMG_UINT16 ui16MinAlloc = VXEKMAPI_MAX_FEATURE_WEIGHT;

			ui8MaxBound = ui8HWPipes;
			if (ui8HWPipes > 1)
			{
				// Can't use final HW pipe for 10 bit single pipe mode encoding or due to it not having a column store
				// Can't use final HW pipe for multi-tile encode in singlepipeperctxt mode due to it not having a column store
				if (psSocket->ui32FeaturesFlag & MASK_VXEKMAPI_COLUMN_STORE_ON && ui8Ideal == 1)
				{
					/* Column store restriction (since they are pipes - 1 stores). The number of pipe is always at least one so we can safely decrement */
					ui8MaxBound--;
				}
			}

			/* Find the least allocated pipe */
			for (ui8Idx = 0; ui8Idx < ui8MaxBound; ui8Idx++)
			{
				if (psSocket->psDevContext->aui16PipesAllocation[ui8Idx] <= ui16MinAlloc)
				{
					ui16MinAlloc = psSocket->psDevContext->aui16PipesAllocation[ui8Idx];
					ui8SmallestIndex = ui8Idx;
				}
			}

			if (0xff == ui8SmallestIndex)
			{
				/* Could not found suitable pipe allocation */
				return 0;
			}

			ui8AllocatedPipes_km = (ui8Ideal < ui8HWPipes ? ui8Ideal : ui8HWPipes);
			/* We want this "golden" pipe to be within the allocated ones */
			if (ui8SmallestIndex >= ui8AllocatedPipes_km - 1)
			{
				/* Underflow protection */
				ui8FirstPipe_km = ui8SmallestIndex - ui8AllocatedPipes_km + 1;
			}
			else
			{
				ui8FirstPipe_km = 0;
			}

			ui8LastPipe_km = ui8FirstPipe_km + ui8AllocatedPipes_km - 1;
			psSocket->ui8RoundRobinThresh = VXE_KM_DEFAULT_SCHED_THRESHOLD;
			ui16WeightToApply = km_applyFeaturesWeight(psSocket->ui32FeaturesFlag);
		}

		for (ui8Idx = ui8FirstPipe_km; ui8Idx <= ui8LastPipe_km; ui8Idx++)
		{
			if (psSocket->psDevContext->aui16PipesAllocation[ui8Idx] + ui16WeightToApply > VXEKMAPI_MAX_FEATURE_WEIGHT)
			{
				psSocket->psDevContext->aui16PipesAllocation[ui8Idx] = VXEKMAPI_MAX_FEATURE_WEIGHT;
			}
			else
			{
				psSocket->psDevContext->aui16PipesAllocation[ui8Idx] += ui16WeightToApply;
			}
		}
	}
	else
	{
		/* One pipe in hardware */
		ui8FirstPipe_km = 0;
		ui8AllocatedPipes_km = 1;
		ui8LastPipe_km = ui8AllocatedPipes_km - 1;
	}

	*pui8FirstPipe = ui8FirstPipe_km;
	*pui8LastPipe = ui8LastPipe_km;

	return ui8AllocatedPipes_km;
}


/************************************************* REAL FIRMWARE SETUP *****************************************************/

/*!
* @fn quartz_SetupFirmware
* @brief Setup the device memory, and the firmware representation before loading it onto the hardware
* @param psDevContext Pointer on the device context allocated previously in #quartzkm_fnDevInit
* @param eCodec Codec to be used for this firmware (comes from the codec selected when opening the socket)
*/
static IMG_RESULT quartz_SetupFirmware(VXE_KM_DEVCONTEXT* psDevContext, VXE_CODEC eCodec)
{
	IMG_RESULT eRet;

	/* Fetch the firmware context from the device context */
	VXE_KM_FW_SOFT_IMAGE* psFWContext = &(psDevContext->sFWSoftImage);

	DEBUG_PRINT("Setting up firmware for device %x\n", psDevContext->sDevSpecs.ui32CoreDevIdx);

	if (psFWContext->bInitialized || psFWContext->bPopulated)
	{
		PRINT("Failed to populate the firmware context {was initialised already? %i, was populated already? %i\n", psFWContext->bInitialized, psFWContext->bPopulated);
		return IMG_ERROR_ALREADY_INITIALISED;
	}

	/* We are going to initialise the firmware representation of the loaded firmware, so it is not initialised */
	psFWContext->bInitialized = IMG_FALSE;

	/* Set some required information for the firmware code to be loaded and select which build should be uploaded */
	eRet = LTP_PopulateFirmwareContext((IMG_HANDLE)psDevContext, eCodec);
	if (eRet != IMG_SUCCESS)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS);
		return eRet;
	}

	/* According to the populated information, we can now allocate the device memory to host the firmware code */
	eRet = LTP_Initialize(psFWContext);
	if (eRet != IMG_SUCCESS)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS);
		return eRet;
	}

	/* Clear some registers used for the firmware <=> KM output */
	/* The firmware has not booted yet, we wouldn't want to read garbage value inside the register so we clear it */
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_REG_FEEDBACK_PRODUCER, 0x0);
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_REG_FEEDBACK_CONSUMER, 0x0);
	/* The firmware informs the host about to booting progress through one register (the same we'll poll for the magic number) */
#if ! defined (IMG_KERNEL_MODULE)
	/* in a test environment we call tell the firmware to only use the specified number of pipes, regardless of how many pipes it can see */
	TALPDUMP_Comment(psFWContext->hLTPDataRam, "Tell Firmware how many pipes to expect");
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_REG_FW_BOOTSTATUS,psFWContext->ui8QuartzHwPipes);
#else
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_REG_FW_BOOTSTATUS, 0x0);
#endif
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_SCRATCHREG_IDLE, 0x0); // idle state is this point, known state
 
	/* The next read/write in the command FIFO will be @FW_FEEDBACK_FIFO_START : we reset consumer/producer */
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_HW_FIFO_READER, 0x0);
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_HW_FIFO_WRITER, 0x0);

	{
		IMG_UINT32 ui32RegOffset;
		// Reset low latency header/node information registers
		for (ui32RegOffset = FW_PIPELOWLATENCYINFO_START; ui32RegOffset < FW_PIPELOWLATENCYINFO_END; ui32RegOffset += 4)
		{
			TALREG_WriteWord32(psFWContext->hLTPDataRam, ui32RegOffset, 0x0);
		}
	}

#if SECURE_MMU
	TALPDUMP_Comment(psFWContext->hLTPDataRam, "Put MMU setup data into firmware command fifo");

	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_COMMAND_FIFO_START + 0x00, VXE_COMMAND_CONFIGURE_MMU);
#if defined (IMG_KERNEL_MODULE)
		TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_COMMAND_FIFO_START + 0x04, psDevContext->sDevSpecs.sMMURegConfig.DIR_BASE_ADDR0);
#else
		/* in nonbridging case we dont know the physical address of the page tables but we stored it in a TAL internal register earlier */
		TALINTVAR_WriteToReg32(psFWContext->hLTPDataRam, FW_COMMAND_FIFO_START + 0x04, psDevContext->sDevSpecs.hQuartzMultipipeBank, 1);
#endif
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_COMMAND_FIFO_START + 0x08, psDevContext->sDevSpecs.sMMURegConfig.ADDRESS_CONTROL);
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_COMMAND_FIFO_START + 0x0c, psDevContext->sDevSpecs.sMMURegConfig.MMU_CONTROL0);
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_COMMAND_FIFO_START + 0x10, psDevContext->sDevSpecs.sMMURegConfig.TILE_CFG0);
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_COMMAND_FIFO_START + 0x14, psDevContext->sDevSpecs.sMMURegConfig.TILE_MAX_ADDR0);
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_COMMAND_FIFO_START + 0x18, psDevContext->sDevSpecs.sMMURegConfig.TILE_MIN_ADDR0);
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_COMMAND_FIFO_START + 0x1c, psDevContext->sDevSpecs.sMMURegConfig.DIR_BASE_ADDR0);
	TALREG_WriteWord32(psFWContext->hLTPDataRam, FW_HW_FIFO_WRITER, FW_MMU_CONFIG_SIZE);
#endif

	/* Perform a soft reset on the embedded processor and cores */
	eRet = LTP_EnableDisable(psFWContext, IMG_FALSE);
	if (eRet != IMG_SUCCESS)
	{
		PRINT("%s() - Could not disable LTP core\n", __FUNCTION__);
		return eRet;
	}
	TALREG_WriteWord32(psFWContext->hQuartzMultipipeMemSpace, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, MASK_QUARTZ_TOP_PROC_SOFT_RESET);
	TALREG_WriteWord32(psFWContext->hQuartzMultipipeMemSpace, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, 0x0);
	TALREG_WriteWord32(psFWContext->hQuartzMultipipeMemSpace, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, 0xF0);
	TALREG_WriteWord32(psFWContext->hQuartzMultipipeMemSpace, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, 0x0);
	/* MMU soft reset required here? */

	if (psFWContext->bInitialized)
	{
#if defined (USE_FW_TRACE)
		if (psDevContext->hFwTraceBuffer)
		{
			IMG_RESULT eRet;
			IMG_UINT32 ui32DevVirtAddr;
			KM_DEVICE_BUFFER *psFwTraceBuffer = (KM_DEVICE_BUFFER *)psDevContext->hFwTraceBuffer;

			/* write details to firmware */
			eRet = TALMMU_GetDevVirtAddress(psFwTraceBuffer->talmmuHandle, &ui32DevVirtAddr);
			IMG_ASSERT(eRet == IMG_SUCCESS);

			TALPDUMP_Comment(psFWContext->hLTPDataRam, "Tell FW about trace buffer");
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_TRACE_BASEADDR, ui32DevVirtAddr);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_TRACE_SIZE, psDevContext->ui32FwTraceSize);

		}
#endif


		{
			/* Performs a soft reset of the embedded processor only */
			eRet = ltp_reset(psFWContext);
			IMG_ASSERT(eRet == IMG_SUCCESS && "LTP reset failed");
			if (eRet != IMG_SUCCESS)
			{
				return eRet;
			}

			eRet = LTP_LoadFirmware(psDevContext, psFWContext, g_eLoadMethod);
			if (eRet != IMG_SUCCESS)
			{
				IMG_ASSERT(eRet == IMG_SUCCESS && "Firmware load failed");
				return eRet;
			}

			/* Turn on the LTP core */
			eRet = LTP_Start(psFWContext);
			if (eRet != IMG_SUCCESS)
			{
				IMG_ASSERT(eRet == IMG_SUCCESS && "Firmware start failed");
				return eRet;
			}
		}


		/* Issue a kick to the firmware */

		{
			eRet = LTP_Kick(psFWContext, 1);
			if (eRet != IMG_SUCCESS)
			{
				PRINT("%s() - Issuing kick to un-initialised firmware\n", __FUNCTION__);
				return eRet;
			}
		}

		/* Wait for the firmware to have actually booted (polling its state) */
		TALPDUMP_Comment(psFWContext->hLTPDataRam, "Wait for firmware to boot");
		eRet = TALREG_Poll32(psFWContext->hLTPDataRam, FW_REG_FW_BOOTSTATUS, TAL_CHECKFUNC_ISEQUAL, 0x12345678, 0xffffffff, VXE_TIMEOUT_RETRIES, VXE_TIMEOUT_WAIT_FOR_FW_BOOT);
		IMG_ASSERT(eRet == IMG_SUCCESS && "Time out waiting for firmware to boot");

		return eRet;
	}

	return IMG_ERROR_NOT_INITIALISED;
}


/************************************************* POWER MANAGEMENT ********************************************************/

#if defined(IMG_KERNEL_MODULE)
#define WAIT_COMMAND_FIFO_SPACE_RETRIES 100
#define WAIT_COMMAND_FIFO_SPACE_TIMEOUT 1
#else
#define WAIT_COMMAND_FIFO_SPACE_RETRIES 100
#define WAIT_COMMAND_FIFO_SPACE_TIMEOUT 100
#endif

#if defined (POLL_FOR_INTERRUPT)
/**
* \fn KM_AnyFeedbackIsWaiting
* \brief Check if any command has been issued inducing some feedback may be on the way
* \param apsSockets Array of socket pointers
* \return	- IMG_TRUE if at least one socket has been found active.
*			- IMG_FALSE if no sockets are active
**/
static void MarkNonIdleSocketAsWaiting(VXE_KM_COMM_SOCKET **apsSockets)
{
	IMG_UINT8 ui8SocketNum = 0;
	VXE_KM_COMM_SOCKET *psSocket = IMG_NULL;

	/* Cycle through all sockets to see if any have outstanding activity */
	while (ui8SocketNum < VXE_MAX_SOCKETS)
	{
		psSocket = apsSockets[ui8SocketNum++];
		if (psSocket && !km_SocketIsIdle(psSocket))
		{
			/* We found someone willing to do some work */
			psSocket->b8StreamWaiting = IMG_TRUE;
		}
	}
	
}

#endif
/**
* \fn KM_TurnOffHW
* \brief Wraps the hardware turning off for the HISR poller
* \param psDevContext Pointer on the device KM context
* \details
* When doing Active Power Management, we want to keep track of the firmware progress in order
* to turn it off when appropriate. If #POLL_FOR_INTERRUPT is enabled, #KM_LISRThread() will handle
* this. Otherwise, the workqueue will power off the device.
* \return
*	- IMG_SUCCESS on normal completion
*	- IMG_ERROR_UNEXPECTED_STATE if not every stream is idle
**/
IMG_RESULT KM_TurnOffHW(VXE_KM_DEVCONTEXT *psDevContext)
{
	/* After we sent all commands, the firmware will acknowledge all of them , we then only have to wait for it to see the last one to complete in order to guarantee the total deactivation */
	IMG_UINT32 ui32FWProgress;
	IMG_RESULT eRet;
#if ! defined (IMG_KERNEL_MODULE)
	IMG_UINT32 ui32Reg;
#endif
	IMG_BOOL bRet;

	/* No feedback can be left unprocessed, because it will be lost */
	bRet = km_CommIsIdle(psDevContext->apsDeviceSockets);
	if (!bRet)
	{
#if defined (POLL_FOR_INTERRUPT)
		/* if there is a socket that isn't idle then mark it as waiting so that the LISR thread processes it */
		MarkNonIdleSocketAsWaiting(psDevContext->apsDeviceSockets);
#endif
		return IMG_ERROR_UNEXPECTED_STATE;
	}

#if ! defined (IMG_KERNEL_MODULE)
	/* Now that software has guarantee'd the idle state of the comm layer, we need to make sure pdump will do the same */
	TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_CONSUMER, &ui32Reg);
	TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Wait for feedback consumer to match generated value");
	eRet = TALREG_Poll32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_CONSUMER, TAL_CHECKFUNC_ISEQUAL, ui32Reg, 0xffffffff, POLL_COUNT, POLL_TIMEOUT);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Timeout waiting for KM to consume all feedback");
		return IMG_ERROR_TIMEOUT;
	}
	TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_PRODUCER, &ui32Reg);
	TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Wait for feedback producer to match generated value");
	eRet = TALREG_Poll32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FEEDBACK_PRODUCER, TAL_CHECKFUNC_ISEQUAL, ui32Reg, 0xffffffff, POLL_COUNT, POLL_TIMEOUT);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Timeout waiting for FW to issue all feedback");
		return IMG_ERROR_TIMEOUT;
	}
#endif

	/* Read the content of the global firmware tracking register */
	TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FW_FEEDBACK, &ui32FWProgress);

	/* Wait for the low power entrance command id */
	if (ui32FWProgress == psDevContext->ui32LastLowPowerCmdId)
	{
		PRINT("\nSuspending LTP\n\n");

#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Sync point to turn off hardware");
		/* For pdump replay, we insert a poll here to guarantee that we will wait long enough */
		eRet = TALREG_Poll32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FW_FEEDBACK, TAL_CHECKFUNC_ISEQUAL, ui32FWProgress, 0xffffffff, POLL_COUNT, POLL_TIMEOUT);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "Timeout waiting for FW to be ready for low power");
			return IMG_ERROR_TIMEOUT;
		}
#endif

#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_ConsoleMessage(psDevContext->sDevSpecs.hLTPDataRam, "Seen feedback to go low power");
#endif

		/* Now that firmware signalled us its deactivation, we can save its state */
		eRet = LTP_SaveState(&psDevContext->sFWSoftImage);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}


		DEBUG_PRINT("Firmware saved\n");
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psDevContext->sDevSpecs.hLTPDataRam, "---- Firmware saved");
		TALPDUMP_ConsoleMessage(psDevContext->sDevSpecs.hLTPDataRam, "Firmware saved");
#endif
		/* Now actually switch off the hardware */
		DMANKM_SuspendDevice(psDevContext->hDMANDevHandle);

		psDevContext->eLowPowerState = e_HW_IDLE;

	}

	return IMG_SUCCESS;
}


/**
* \fn KM_InformLowPower
* \brief Inform a device to enter low power mode (pre S5)
* \params psDevContext Device context which shall go low power
* \returns		- IMG_SUCCESS on normal completion
*				- IMG_ERROR_CANCELLED if no stream were found active
**/
IMG_RESULT KM_InformLowPower(VXE_KM_DEVCONTEXT *psDevContext)
{
	VXE_KM_COMM_SOCKET *psSocket = IMG_NULL;
	IMG_UINT32 uiContext;
	IMG_UINT32 ui32LastUniqueCommandId = 0;
	IMG_BOOL bAtLeastOneCmdSent = IMG_FALSE;

	IMG_UINT32 ui32CommandFIFOProducer, ui32CommandFIFOConsumer, ui32NewFIFOCommandProducer, ui32OffsetToWriteTo;
	IMG_INT32 i32MaxTries = WAIT_COMMAND_FIFO_SPACE_RETRIES;
#if ! defined(IMG_KERNEL_MODULE)
	IMG_RESULT eRet;
#endif

	
#ifndef REMOVE_4K1080PARALLEL_SCHEDULING
	if (psDevContext->sSchedModel.eSchedModel != e_NO_SCHEDULING_SCENARIO)
	{
		DEBUG_PRINT("HISR INFO - Entering low power mode - KM scheduling model deactivated (low power with scheduling mode not supported).\n");
		// Override any existing scheduling code so that all encodes currently queued can complete without scheduling restrictions before low power mode
		psDevContext->sSchedModel.eSchedModel = e_NO_SCHEDULING_SCENARIO;
		if (NULL != psDevContext->sSchedModel.pvAllocation)
		{
			IMG_FREE(psDevContext->sSchedModel.pvAllocation);
			psDevContext->sSchedModel.pvAllocation = NULL;
		}	
	}
#endif

	PRINT("\nInforming LTP to enter low-power mode\n\n");

	/* Get control of the comm layer to deactivate the workqueue in order to bypass it */
	km_Lock(psDevContext, COMM_LOCK_TX);
	/* Pause the workqueue after being sure it is not processing a command */
	psDevContext->bSuspendHISR = IMG_TRUE;
	/* Release the comm layer after deactivation, this function is now the only one to write to the command FIFO, so we can perform the insertion */
	km_Unlock(psDevContext, COMM_LOCK_TX);

	/* To be 100% sure that HISR does not have control on the comm layer, let's take/release the mutex (it might be a non-required overhead) */
	km_Lock(psDevContext, COMM_LOCK_TX);
	km_Unlock(psDevContext, COMM_LOCK_TX);

	/* Send a DEACTIVATE_CONTEXT command to all active contexts, it will be dropped if the firmware does not recognised the context it has been sent to */
	for (uiContext = 0; uiContext < VXE_MAX_SOCKETS; ++uiContext)
	{
		/* We are only interested in stream sending commands (if they don't, no need to wake them up to tell them to go to sleep) */
		if (psDevContext->apsDeviceSockets[uiContext] && (psDevContext->sFWSoftImage.ui16ActiveContextMask & (1 << uiContext)))
		{
			psSocket = psDevContext->apsDeviceSockets[uiContext];

			TALPDUMP_Comment(psDevContext->sDevSpecs.hLTPDataRam, "Tell FW to de-activate context (issue command)");

			TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_WRITER, &ui32CommandFIFOProducer);
			TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_READER, &ui32CommandFIFOConsumer);
			ui32NewFIFOCommandProducer = (ui32CommandFIFOProducer + 1) % HW_FIFO_SIZE;

#if ! defined(IMG_KERNEL_MODULE)
			/* Should provide more safety for pdump reprobucibility */
			TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Check that content of writer register is the same as recorded");
			eRet = TALREG_Poll32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_WRITER, TAL_CHECKFUNC_ISEQUAL, ui32CommandFIFOProducer, 0xffffffff, 8000, WAIT_COMMAND_FIFO_SPACE_TIMEOUT);
			if (IMG_SUCCESS != eRet)
			{
				IMG_ASSERT(eRet == IMG_SUCCESS && "Time out waiting for firmware to catch up ");
				return eRet;
			}
#endif

			/* HW FIFO content cannot be overriden, we need some space available */
			while (ui32NewFIFOCommandProducer == ui32CommandFIFOConsumer && i32MaxTries)
			{
#if defined(IMG_KERNEL_MODULE)
				msleep(WAIT_COMMAND_FIFO_SPACE_TIMEOUT);
#else
				OSA_ThreadSleep(WAIT_COMMAND_FIFO_SPACE_TIMEOUT);
#endif
				i32MaxTries--;

				/* Check the new reader value */
				TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_READER, &ui32CommandFIFOConsumer);
			}

			/* Command has not been placed in the hardware FIFO */
			if (i32MaxTries <= 0)
			{
				PRINT("%s: Timeout waiting for space in the command FIFO\n", __FUNCTION__);
				continue;
			}

#if ! defined(IMG_KERNEL_MODULE)
			/* Should provide more safety for pdump reprobucibility */
			TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Command can be inserted in the HW FIFO");
			eRet = TALREG_Poll32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_READER, TAL_CHECKFUNC_NOTEQUAL, ui32NewFIFOCommandProducer, 0xffffffff, WAIT_COMMAND_FIFO_SPACE_RETRIES, WAIT_COMMAND_FIFO_SPACE_TIMEOUT);
			if (IMG_SUCCESS != eRet)
			{
				IMG_ASSERT(eRet == IMG_SUCCESS && "Time out waiting for space in command FIFO");
				return eRet;
			}
#endif

			/* We are updating variables that user-space bridging call may try to update at the same time */
			km_Lock(psDevContext, COMM_LOCK_TX);

			/* Keep the last command unique id that was sent */
			ui32LastUniqueCommandId = psDevContext->ui32LastCmdID;
			psDevContext->ui32LastCmdID = (psDevContext->ui32LastCmdID + 1) & CMD_ID_MASK; /*fence is a new command*/

			/* Place the command in the HW FIFO */
			ui32OffsetToWriteTo = FW_COMMAND_FIFO_START + (ui32CommandFIFOProducer * HW_FIFO_WORDS_PER_COMMANDS) * 4;
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo, F_ENCODE(VXE_COMMAND_DEACTIVATE_CONTEXT, FW_COMMAND_COMMAND_TYPE) | F_ENCODE(psSocket->ui8FWCtxtId, FW_COMMAND_SOCKET_ID) | MASK_FW_COMMAND_WB_INTERRUPT);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo + 0x4, 0);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo + 0x8, 0);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo + 0xc, ui32LastUniqueCommandId);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_WRITER, ui32NewFIFOCommandProducer);
			/* We issued a command for this context even though it is not the regular way */
			psSocket->ui32CmdSent++;

#if defined (OUTPUT_COMM_STATS)
			Output_COMM_Stats_Msg_To_File(psSocket, "MSG-TX", 
				F_ENCODE(VXE_COMMAND_DEACTIVATE_CONTEXT, FW_COMMAND_COMMAND_TYPE) | 
				F_ENCODE(psSocket->ui8FWCtxtId, FW_COMMAND_SOCKET_ID) | 
				MASK_FW_COMMAND_WB_INTERRUPT, 
				0, ui32LastUniqueCommandId, "COMM_Track.txt");
#endif
			DEBUG_PRINT("\n[preS5] Deactivate command sent with unique id %i\n", ui32LastUniqueCommandId);
			
			TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Deactivate command issued");

			/* We will have at least one command for which we will wait feedback */
			bAtLeastOneCmdSent = IMG_TRUE;

			/* We decouple the last command id from the last DEACTIVATE_COMMAND id, so we can sync on what we really look for */
			psDevContext->ui32LastLowPowerCmdId = ui32LastUniqueCommandId;

			/* User space might eventually try inserting a new command concurently to us turning the hardware off */
			km_Unlock(psDevContext, COMM_LOCK_TX);
		}
	}

	/* None of these paths is really an error but it gives more information to the caller */
	return (bAtLeastOneCmdSent ? IMG_SUCCESS : IMG_ERROR_CANCELLED);
}


/*!
******************************************************************************
*
* @function quartzkm_fnPowerSave
* @brief Store the state of the device
* @params hDevHandle Handle on the device context in the DMAN layer
* @params pvDevInstanceData Handle on the KM level device context
* See definition of #DMANKM_pfnDevPowerPreS5.
*
******************************************************************************/
IMG_VOID quartzkm_fnPowerSave(IMG_HANDLE hDevHandle, IMG_VOID *pvDevInstanceData)
{
	IMG_RESULT eRet;
	VXE_KM_DEVCONTEXT *psDevContext = (VXE_KM_DEVCONTEXT*)pvDevInstanceData;

#if defined (SYSBRG_NO_BRIDGING)
	IMG_ASSERT(IMG_FALSE && "Device management callback should not be called");
#endif

	eRet = KM_InformLowPower(psDevContext);
	if (IMG_SUCCESS == eRet)
	{
		/* After we sent all commands, the firmware will acknowledge all of them , we then only have to wait for it to see the last one to complete in order to guarantee the total deactivation */
		IMG_UINT32 ui32FWProgress;

		/* Wait for the low power entrance command id */
		eRet = TALREG_Poll32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FW_FEEDBACK, TAL_CHECKFUNC_ISEQUAL, psDevContext->ui32LastLowPowerCmdId, 0xffffffff, 100, 10);
		if (IMG_ERROR_TIMEOUT == eRet)
		{
			TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_REG_FW_FEEDBACK, &ui32FWProgress);
			PRINT("Device is locked-up waiting for command %i to complete (last command to complete was %i).\n", psDevContext->ui32LastLowPowerCmdId, ui32FWProgress);
		}
	}

	/* Turn off the hardware (possible situation: ack received, hw lockup or no active stream in hardware) */
	eRet = KM_TurnOffHW(psDevContext);
	if (IMG_SUCCESS != eRet)
	{
		/* Signal the error in kernel logs */
		PRINT("Device could not be turned off (%i).\n", eRet);
	}
}


/*!
******************************************************************************
*
* @function quartzkm_fnPowerRestore
* @brief Restore the state of the device
* @params hDevHandle Handle on the device context in the DMAN layer
* @params pvDevInstanceData Handle on the KM level device context
* See definition of #DMANKM_pfnDevPowerPostS0.
*
******************************************************************************/
IMG_VOID quartzkm_fnPowerRestore(IMG_HANDLE hDevHandle, IMG_VOID *pvDevInstanceData)
{
	IMG_UINT32 uiContext;
	IMG_UINT32 ui32LastUniqueCommandId = 0;
	IMG_BOOL bAtLeastOneCmdSent = IMG_FALSE;
	IMG_INT32 i32MaxTries = WAIT_COMMAND_FIFO_SPACE_RETRIES;
	IMG_UINT32 ui32CommandFIFOProducer, ui32CommandFIFOConsumer, ui32NewFIFOCommandProducer, ui32OffsetToWriteTo;
	VXE_KM_COMM_SOCKET *psSocket = IMG_NULL;
	VXE_KM_DEVCONTEXT *psDevContext = (VXE_KM_DEVCONTEXT*)pvDevInstanceData;
	IMG_RESULT eRet;

	if (psDevContext->eLowPowerState == e_HW_ACTIVE)
	{
		DEBUG_PRINT("\nHW was already up, not restored!\n\n");
		/* No need to restore an already active HW */
		return;
	}

	/*
	* Before trying to restore LTP, check if it serves a purpose
	* The check is performed here because the MMU has just been
	* reset and #LTP_LoadFirmware could cause a page fault.
	*/
	if (0 == psDevContext->sFWSoftImage.ui16ActiveContextMask && 0 == psDevContext->ui32IdleSockets)
	{
		/* Check if we missed something */
		uiContext = 0;
		do
		{
			psSocket = psDevContext->apsDeviceSockets[uiContext];
			if (psSocket && !km_SocketCmdFIFOIsEmpty(psSocket))
			{
				IMG_ASSERT(uiContext < VXE_MAX_SOCKETS && "Socket index corrupted");
				psDevContext->sFWSoftImage.ui16ActiveContextMask |= (1 << uiContext);
				break;
			}
			uiContext++;
		} while (uiContext < VXE_MAX_SOCKETS);

		if (uiContext >= VXE_MAX_SOCKETS)
		{
			PRINT("\nThere are no more streams active. Skipping HW restore\n\n");
			/* Re-enable the workqueue (otherwise, it will lockup) */
			psDevContext->bSuspendHISR = IMG_FALSE;
			/* Will not restore HW for nothing */
			return;
		}
	}

	if (psDevContext->eLowPowerState == e_HW_IDLE)
	{
		/* Switch on the hardware */
		DMANKM_ResumeDevice(psDevContext->hDMANDevHandle, IMG_TRUE);

		PRINT("\nResuming LTP\n\n");

		/* Restore firmware memory and registers before kicking it */
		eRet = LTP_RestoreState(pvDevInstanceData);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "Power restore failed");
			psDevContext->sFWSoftImage.bInitialized = IMG_FALSE; /*mark the device as de-initialised will prevent its usage until complete de-init*/
			return;
		}
	}

	/* Wake up the firmware by re-activating all contexts (socket was openned) */
	for (uiContext = 0; uiContext < VXE_MAX_SOCKETS; ++uiContext)
	{
		psSocket = psDevContext->apsDeviceSockets[uiContext];
		/* We are only interested in stream sending commands (if they don't, no need to wake them up to tell them to go to sleep) */
		if (psSocket && ((psDevContext->sFWSoftImage.ui16ActiveContextMask & (1 << uiContext)) || !km_SocketCmdFIFOIsEmpty(psSocket)))
		{
			TALPDUMP_Comment(psDevContext->sDevSpecs.hLTPDataRam, "Tells FW to re-activate context");

			/* HISR has been deactivated when we entered low power state, so we have total control on the HW FIFO (it has been cleared by #LTP_RestoreState) */
			TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_WRITER, &ui32CommandFIFOProducer);
			TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_READER, &ui32CommandFIFOConsumer);
			ui32NewFIFOCommandProducer = (ui32CommandFIFOProducer + 1) % HW_FIFO_SIZE;

			/* HW FIFO content cannot be overriden, we need some space available (this is superfluous as long as we don't go over 32 contexts since there are 32 slots in the HW FIFO) */
			while (ui32NewFIFOCommandProducer == ui32CommandFIFOConsumer && i32MaxTries)
			{
#if defined(IMG_KERNEL_MODULE)
				msleep(WAIT_COMMAND_FIFO_SPACE_TIMEOUT);
#else
				OSA_ThreadSleep(WAIT_COMMAND_FIFO_SPACE_TIMEOUT);
#endif
				i32MaxTries--;

				TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_READER, &ui32CommandFIFOConsumer);
			}

			/* Command has not been placed in the hardware FIFO */
			if (i32MaxTries <= 0)
			{
				PRINT("%s: Command FIFO was full for too long", __FUNCTION__);
				continue;
			}

#if ! defined(IMG_KERNEL_MODULE)
			/* Should provide more safety for pdump reprobucibility */
			TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Command can be inserted in the HW FIFO");
			eRet = TALREG_Poll32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_READER, TAL_CHECKFUNC_NOTEQUAL, ui32NewFIFOCommandProducer, 0xffffffff, WAIT_COMMAND_FIFO_SPACE_RETRIES, WAIT_COMMAND_FIFO_SPACE_TIMEOUT);
			if (IMG_SUCCESS != eRet)
			{
				IMG_ASSERT(eRet == IMG_SUCCESS && "Time out waiting for space in command FIFO");
				return;
			}
#endif

			/* Keep the last command unique id that was sent */
			ui32LastUniqueCommandId = psDevContext->ui32LastCmdID;
			psDevContext->ui32LastCmdID = (psDevContext->ui32LastCmdID + 1) & CMD_ID_MASK; /*fence is a new command*/

			/* Place the command in the HW FIFO */
			ui32OffsetToWriteTo = FW_COMMAND_FIFO_START + (ui32CommandFIFOProducer * HW_FIFO_WORDS_PER_COMMANDS) * 4;
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo, F_ENCODE(VXE_COMMAND_ACTIVATE_CONTEXT, FW_COMMAND_COMMAND_TYPE) | F_ENCODE(psSocket->ui8FWCtxtId, FW_COMMAND_SOCKET_ID) | MASK_FW_COMMAND_WB_INTERRUPT);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo + 0x4, MASK_VXE_ACTIVATE_CONTEXT_ALREADY_ACTIVATED);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo + 0x8, psSocket->ui32ContextMemory);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, ui32OffsetToWriteTo + 0xc, ui32LastUniqueCommandId);
			TALREG_WriteWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_HW_FIFO_WRITER, ui32NewFIFOCommandProducer);
			/* We issued a command for this context even though it is not the regular way */
			psSocket->ui32CmdSent++;

#if defined (OUTPUT_COMM_STATS)
			Output_COMM_Stats_Msg_To_File(psSocket, "MSG-TX", 
				F_ENCODE(VXE_COMMAND_ACTIVATE_CONTEXT, FW_COMMAND_COMMAND_TYPE) | 
				F_ENCODE(psSocket->ui8FWCtxtId, FW_COMMAND_SOCKET_ID) | 
				MASK_FW_COMMAND_WB_INTERRUPT, 
				MASK_VXE_ACTIVATE_CONTEXT_ALREADY_ACTIVATED, 
				ui32LastUniqueCommandId, "COMM_Track.txt");
#endif
			/* We have just issued a command to restore this stream, it is not idle anymore */
			psSocket->bStreamIdle = IMG_FALSE;
			/* Check that this socket has not yet been marked active (protect the global idle counter) */
			if (psDevContext->ui32IdleSocketsFlag & (1 << psSocket->ui8FWCtxtId))
			{
				/* Clear the flag before decrementing the counter (acts as a simily mutex) */
				psDevContext->ui32IdleSocketsFlag &= ~(1 << psSocket->ui8FWCtxtId);
				/* One socket has been woken up (the one used for the command sending) */
				psDevContext->ui32IdleSockets--;
			}

			DEBUG_PRINT("\n[postS0] (Re-)Activate command sent with unique id %i\n", ui32LastUniqueCommandId);

			TALPDUMP_VerboseComment(psDevContext->sDevSpecs.hLTPDataRam, "Activate command issued");

			/* We will have at least one command for which we will wait feedback */
			bAtLeastOneCmdSent = IMG_TRUE;
		}
	}

	/* HW is now fully active */
	psDevContext->eLowPowerState = e_HW_ACTIVE;

	/* Re-enable the workqueue */
	psDevContext->bSuspendHISR = IMG_FALSE;

	/* We inserted some command in the HW FIFO, we cannot guarantee that it will be known to the firmware so we explicitely kick it here */
	eRet = LTP_Kick(&psDevContext->sFWSoftImage, 1);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "LTP kick on power restore failed");
		psDevContext->sFWSoftImage.bInitialized = IMG_FALSE; /*mark the device as de-initialised will prevent its usage until complete de-init*/
		return;
	}


	/* We just performed a power transition */
	TALPDUMP_Comment(psDevContext->sDevSpecs.hLTPDataRam, "---- Firmware restored");
}


#if defined (SYSBRG_NO_BRIDGING)
/* NOTE: We do not want this scheduling mode outside of the kernel but we need a backdoor way to set it up from the command line */
IMG_UINT32 backdoor_KM_getSchedulingModel(IMG_CHAR *pszSchedName)
{
	if (!strcmp(pszSchedName, "4K422_60_1080p420_30"))
	{
		return e_4K422_60__1080p420_30;
	}

	if (!strcmp(pszSchedName, "4K422_60_1080p422_30"))
	{
		return e_4K422_60__1080p422_30;
	}

	/* If not found, then it will default to a balanced round-robin */
	return e_NO_SCHEDULING_SCENARIO;
}
#endif

#if defined (OUTPUT_COMM_STATS)
IMG_UINT32 OUTPUT_COMM_STATS_ui32Calls = 0;

void Output_COMM_Stats_To_File(VXE_KM_COMM_SOCKET *psSocket, unsigned char *ucLabel, IMG_INT id, unsigned char *FileName)
{
	/* With a higher level of COMM output */
#if defined (OUTPUT_COMM_STATS) && defined (OUTPUT_COMM_STATS_EXTENDED)
	FILE *fp = NULL;
	VXE_KM_COMM_SOCKET *sp;
	IMG_UINT32 f;

	if (OUTPUT_COMM_STATS_ui32Calls++ == 0)
		fp = fopen(FileName, "w");
	else
		fp = fopen(FileName, "a");

	sp = psSocket;

	FPRINT(fp, "\nCOM Interface (Call %i)	- %s ", OUTPUT_COMM_STATS_ui32Calls, ucLabel);
	if (id > -1)
	{
		FPRINT(fp, "COMMAND[%d]: %s\n", sp->ui8FWCtxtId, apszCmd[F_DECODE(id, FW_COMMAND_COMMAND_TYPE)]);
	}
	else
	{
		FPRINT(fp, "COMMAND[%d]: NA\n", sp->ui8FWCtxtId);
	}

	FPRINT(fp, "	ui8SockedID: %i\n", sp->ui8FWCtxtId);
	FPRINT(fp, "	ui8CmdQueueConsumer: %i\n", sp->ui8CmdQueueConsumer);
	FPRINT(fp, "	ui8CmdQueueProducer: %i\n", sp->ui8CmdQueueProducer);
	FPRINT(fp, "	ui32EncCmdCount: %i\n", sp->ui32EncCmdCount);
	FPRINT(fp, "	ui32LastCmdID: %i\n", sp->psDevContext->ui32LastCmdID);
	FPRINT(fp, "	asIncomingFifo->\n");

	for (f = 0; f < (2 * FEEDBACK_FIFO_MAX_COMMANDS); f += 2)
	{
		if (F_DECODE(sp->aui32OutgoingFIFO[f], FW_FEEDBACK_MSG_TYPE) == VXE_FWMSG_ACK)
		{
			FPRINT(fp, "		VXE_MSG_ACK:	0x%08x		0x%08x\n", sp->aui32OutgoingFIFO[f], sp->aui32OutgoingFIFO[f + 1]);
		}
		else
		{
			FPRINT(fp, "		VXE_MSG_CODED_BUFFER:	0x%08x		0x%08x\n", sp->aui32OutgoingFIFO[f], sp->aui32OutgoingFIFO[f + 1]);
		}
	}

	FPRINT(fp, "\n");
	FCLOSE(fp);
#endif
}

void Output_COMM_General_Line(unsigned char *ucLabel, const char *FileName)
{
#if ! defined (IMG_KERNEL_MODULE)
	FILE *fp = NULL;
	if (OUTPUT_COMM_STATS_ui32Calls++ == 0)
		fp = fopen(FileName, "w");
	else
		fp = fopen(FileName, "a");
#endif

	FPRINT(fp, "%s\n", ucLabel);

	FCLOSE(fp);
}

void Output_COMM_Stats_Line_To_File(unsigned char *ucLabel, IMG_UINT32 ui32FirstWord, IMG_UINT32 ui32SecondWord, const char *FileName, IMG_UINT32 ui32HwFifoConsumer)
{
	VXE_FWMESSAGE_TYPE eMsgType = (VXE_FWMESSAGE_TYPE)F_DECODE(ui32FirstWord, FW_FEEDBACK_MSG_TYPE);
	IMG_BOOL bAck = (eMsgType == VXE_FWMSG_ACK);

#if ! defined (IMG_KERNEL_MODULE)
	FILE *fp = NULL;

	if (OUTPUT_COMM_STATS_ui32Calls++ == 0)
		fp = fopen(FileName, "w");
	else
		fp = fopen(FileName, "a");
#endif

	if (bAck)
	{
		if(F_DECODE(ui32FirstWord, FW_FEEDBACK_COMMAND_TYPE) == VXE_COMMAND_ENCODE_FRAME)
		{
			FPRINT(fp, "%s[%d]: 0x%03X %s (WB 0x%x) (ACK)\n", ucLabel, F_DECODE(ui32FirstWord, FW_FEEDBACK_CONTEXT_ID), ui32HwFifoConsumer & 0x1f, apszCmd[F_DECODE(ui32FirstWord, FW_FEEDBACK_COMMAND_TYPE)], F_DECODE(ui32FirstWord, FW_FEEDBACK_COMMAND_ID));
		}
		else
		{
			FPRINT(fp, "%s[%d]: 0x%03X %s (ACK)\n", ucLabel, F_DECODE(ui32FirstWord, FW_FEEDBACK_CONTEXT_ID), ui32HwFifoConsumer & 0x1f, apszCmd[F_DECODE(ui32FirstWord, FW_FEEDBACK_COMMAND_TYPE)]);
		}
	}
	else
	{
		FPRINT(fp, "%s[%d]: 0x%03X CODED_BUFFER %d \n", ucLabel, F_DECODE(ui32FirstWord, FW_FEEDBACK_CONTEXT_ID), ui32HwFifoConsumer & 0x1f, F_DECODE(ui32SecondWord, FW_FEEDBACK_CBLISTINDEX));
	}

	FCLOSE(fp);
}

void Output_COMM_Stats_Msg_To_File(VXE_KM_COMM_SOCKET *psSocket, unsigned char *ucLabel, IMG_UINT32 ui32CmdInfo, IMG_UINT32 ui32CmdData, IMG_UINT32 ui32WBValue, const char *FileName)
{
	VXE_COMMAND_TYPE eCmdId = (VXE_COMMAND_TYPE)F_DECODE(ui32CmdInfo, FW_COMMAND_COMMAND_TYPE);
#if ! defined (IMG_KERNEL_MODULE)
	FILE *fp = NULL;

	if (OUTPUT_COMM_STATS_ui32Calls++ == 0)
		fp = fopen(FileName, "w");
	else
		fp = fopen(FileName, "a");
#endif

	if ((eCmdId >= VXE_COMMAND_ENCODE_FRAME && eCmdId <= VXE_COMMAND_UPDATE_PARAMETERS))
	{
		/* we have a valid command */

		switch (eCmdId)
		{
			// In case we would need additional information for a specific command, add it here
			//case MTX_CMDID_PROVIDE_CODEDPACKAGE_BUFFER:
			//{
			//	IMG_UINT32 ui32Slot;
			//	ui32Slot = F_DECODE(pMsg->ui32Data, MTX_MSG_PROVIDE_CODEDPACKAGE_BUFFER_SLOT);
			//	FPRINT(fp, "%s[%d]: %s(%d) %s %s\n", ucLabel, psSocket->ui8SocketId, szCommandString[eCmdId], ui32Slot, (pMsg->eCmdId & 0x80 ? "(PRIORITY)" : "(NORMAL)"), (pMsg->eCmdId & 0x8000 ? "(Interrupt)" : "(NO Interrupt)"));
			//	break;
			//}
		default:
			FPRINT(fp, "%s[%d]: %s %s WB 0x%0X\n", ucLabel, psSocket->ui8FWCtxtId, apszCmd[eCmdId], (ui32CmdInfo & MASK_FW_COMMAND_WB_INTERRUPT ? "(Interrupt)" : "(NO Interrupt)"), ui32WBValue);
			break;
		}
	}
	else
		FPRINT(fp, "%s[%d]: NA\n", ucLabel, psSocket->ui8FWCtxtId);

	FCLOSE(fp);
}
#endif


#if ! defined (INCLUDE_DEBUG_FEATURES)
#else
/* Debug facilities */
#include "vxekm_debug.c"
#endif

/************************************************* THREAD ROUTINES *********************************************************/

