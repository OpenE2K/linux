/*************************************************************************/ /*!
@File
@Title          core services functions
@Copyright      Copyright (c) Imagination Technologies Ltd. All Rights Reserved
@Description    Main APIs for core services functions
@License        Dual MIT/GPLv2

The contents of this file are subject to the MIT license as set out below.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

Alternatively, the contents of this file may be used under the terms of
the GNU General Public License Version 2 ("GPL") in which case the provisions
of GPL are applicable instead of those above.

If you wish to allow use of your version of this file only under the terms of
GPL, and not to allow others to use your version of this file under the terms
of the MIT license, indicate your decision by deleting the provisions above
and replace them with the notice and other provisions required by GPL as set
out in the file called "GPL-COPYING" included in this distribution. If you do
not delete the provisions above, a recipient may use your version of this file
under the terms of either the MIT license or GPL.

This License is also included in this distribution in the file called
"MIT-COPYING".

EXCEPT AS OTHERWISE STATED IN A NEGOTIATED AGREEMENT: (A) THE SOFTWARE IS
PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT; AND (B) IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/ /**************************************************************************/

#include "rgxdebug.h"
#include "handle.h"
#include "connection_server.h"
#include "osconnection_server.h"
#include "pdump_km.h"
#include "ra.h"
#include "allocmem.h"
#include "pmr.h"
#include "pvrsrv.h"
#include "srvcore.h"
#include "services_km.h"
#include "pvrsrv_device.h"
#include "pvr_debug.h"
#include "pvr_notifier.h"
#include "sync.h"
#include "sync_server.h"
#include "sync_checkpoint.h"
#include "sync_fallback_server.h"
#include "sync_checkpoint_init.h"
#include "devicemem.h"
#include "cache_km.h"
#include "pvrsrv_pool.h"
#include "info_page.h"

#include "log2.h"

#include "lists.h"
#include "dllist.h"
#include "syscommon.h"
#include "sysvalidation.h"

#include "physmem_lma.h"
#include "physmem_osmem.h"
#include "physmem_hostmem.h"

#include "tlintern.h"
#include "htbserver.h"

#if defined (SUPPORT_RGX)
#include "rgxinit.h"
#include "rgxhwperf.h"
#include "rgxfwutils.h"
#endif

#if defined(PVR_RI_DEBUG)
#include "ri_server.h"
#endif

#if defined(PVRSRV_ENABLE_PROCESS_STATS)
#include "process_stats.h"
#endif

#if defined(SUPPORT_GPUVIRT_VALIDATION)
	#if !defined(GPUVIRT_SIZEOF_ARENA0)
		#define GPUVIRT_SIZEOF_ARENA0	64 * 1024 * 1024 //Giving 64 megs of LMA memory to arena 0 for firmware and other allocations
	#endif
#endif

#if defined(SUPPORT_PAGE_FAULT_DEBUG)
#include "devicemem_history_server.h"
#endif

#if defined(PVR_DVFS)
#include "pvr_dvfs_device.h"
#endif

#if defined(SUPPORT_DISPLAY_CLASS)
#include "dc_server.h"
#endif

#include "rgx_options.h"
#include "srvinit.h"
#include "rgxutils.h"

#include "oskm_apphint.h"
#include "pvrsrv_apphint.h"

#include "rgx_bvnc_defs_km.h"

#include "pvrsrv_tlstreams.h"
#include "tlstream.h"

#if defined (SUPPORT_GPUTRACE_EVENTS)
#include "pvr_gputrace.h"
#endif

/*! Wait 100ms before retrying deferred clean-up again */
#define CLEANUP_THREAD_WAIT_RETRY_TIMEOUT 100000ULL

/*! Wait 8hrs when no deferred clean-up required. Allows a poll several times
 * a day to check for any missed clean-up. */
#define CLEANUP_THREAD_WAIT_SLEEP_TIMEOUT 28800000000ULL

/*! When unloading try a few times to free everything remaining on the list */
#define CLEANUP_THREAD_UNLOAD_RETRY 4

#define PVRSRV_PROC_HANDLE_BASE_INIT 10

#define PVRSRV_TL_CTLR_STREAM_SIZE 4096

#define PVRSRV_MAX_POOLED_BRIDGE_BUFFERS 16 /*!< Max number of pooled bridge buffers */

static PVRSRV_DATA	*gpsPVRSRVData = NULL;
static IMG_UINT32 g_ui32InitFlags;

/* mark which parts of Services were initialised */
#define		INIT_DATA_ENABLE_PDUMPINIT	0x1U

static IMG_UINT32 g_aui32DebugOrderTable[] = {
	DEBUG_REQUEST_SYS,
	DEBUG_REQUEST_APPHINT,
	DEBUG_REQUEST_HTB,
	DEBUG_REQUEST_DC,
	DEBUG_REQUEST_SYNCCHECKPOINT,
	DEBUG_REQUEST_SERVERSYNC,
	DEBUG_REQUEST_ANDROIDSYNC,
	DEBUG_REQUEST_FALLBACKSYNC,
	DEBUG_REQUEST_LINUXFENCE
};

/* Add work to the cleanup thread work list.
 * The work item will be executed by the cleanup thread
 */
void PVRSRVCleanupThreadAddWork(PVRSRV_CLEANUP_THREAD_WORK *psData)
{
	PVRSRV_DATA *psPVRSRVData;
	PVRSRV_ERROR eError;

	psPVRSRVData = PVRSRVGetPVRSRVData();

	PVR_ASSERT(psData != NULL);
#if defined(PVRSRV_FORCE_UNLOAD_IF_BAD_STATE)
	if (psPVRSRVData->eServicesState != PVRSRV_SERVICES_STATE_OK || psPVRSRVData->bUnload)
#else
	if (psPVRSRVData->bUnload)
#endif
	{
		CLEANUP_THREAD_FN pfnFree = psData->pfnFree;

		PVR_DPF((PVR_DBG_MESSAGE, "Cleanup thread has already quit: doing work immediately"));

		eError = pfnFree(psData->pvData);

		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR, "Failed to free resource "
						"(callback " IMG_PFN_FMTSPEC "). "
						"Immediate free will not be retried.",
						pfnFree));
		}
	}
	else
	{
		/* add this work item to the list */
		OSLockAcquire(psPVRSRVData->hCleanupThreadWorkListLock);
		dllist_add_to_tail(&psPVRSRVData->sCleanupThreadWorkList, &psData->sNode);
		OSLockRelease(psPVRSRVData->hCleanupThreadWorkListLock);

		/* signal the cleanup thread to ensure this item gets processed */
		eError = OSEventObjectSignal(psPVRSRVData->hCleanupEventObject);
		PVR_LOG_IF_ERROR(eError, "OSEventObjectSignal");
	}
}

/* Pop an item from the head of the cleanup thread work list */
static INLINE DLLIST_NODE *_CleanupThreadWorkListPop(PVRSRV_DATA *psPVRSRVData)
{
	DLLIST_NODE *psNode;

	OSLockAcquire(psPVRSRVData->hCleanupThreadWorkListLock);
	psNode = dllist_get_next_node(&psPVRSRVData->sCleanupThreadWorkList);
	if (psNode != NULL)
	{
		dllist_remove_node(psNode);
	}
	OSLockRelease(psPVRSRVData->hCleanupThreadWorkListLock);

	return psNode;
}

/* Process the cleanup thread work list */
static IMG_BOOL _CleanupThreadProcessWorkList(PVRSRV_DATA *psPVRSRVData,
                                              IMG_BOOL *pbUseGlobalEO)
{
	DLLIST_NODE *psNodeIter, *psNodeLast;
	PVRSRV_ERROR eError;
	IMG_BOOL bNeedRetry = IMG_FALSE;

	/* any callback functions which return error will be
	 * moved to the back of the list, and additional items can be added
	 * to the list at any time so we ensure we only iterate from the
	 * head of the list to the current tail (since the tail may always
	 * be changing)
	 */

	OSLockAcquire(psPVRSRVData->hCleanupThreadWorkListLock);
	psNodeLast = psPVRSRVData->sCleanupThreadWorkList.psPrevNode;
	OSLockRelease(psPVRSRVData->hCleanupThreadWorkListLock);

	do
	{
		PVRSRV_CLEANUP_THREAD_WORK *psData;

		psNodeIter = _CleanupThreadWorkListPop(psPVRSRVData);

		if (psNodeIter != NULL)
		{
			CLEANUP_THREAD_FN pfnFree;

			psData = IMG_CONTAINER_OF(psNodeIter, PVRSRV_CLEANUP_THREAD_WORK, sNode);

			/* get the function pointer address here so we have access to it
			 * in order to report the error in case of failure, without having
			 * to depend on psData not having been freed
			 */
			pfnFree = psData->pfnFree;

			*pbUseGlobalEO = psData->bDependsOnHW;
			eError = pfnFree(psData->pvData);

			if (eError != PVRSRV_OK)
			{
				/* move to back of the list, if this item's
				 * retry count hasn't hit zero.
				 */
				if (psData->ui32RetryCount-- > 0)
				{
					OSLockAcquire(psPVRSRVData->hCleanupThreadWorkListLock);
					dllist_add_to_tail(&psPVRSRVData->sCleanupThreadWorkList, psNodeIter);
					OSLockRelease(psPVRSRVData->hCleanupThreadWorkListLock);
					bNeedRetry = IMG_TRUE;
				}
				else
				{
					PVR_DPF((PVR_DBG_ERROR, "Failed to free resource "
								"(callback " IMG_PFN_FMTSPEC "). "
								"Retry limit reached",
								pfnFree));
				}
			}
		}
	} while((psNodeIter != NULL) && (psNodeIter != psNodeLast));

	return bNeedRetry;
}

// #define CLEANUP_DPFL PVR_DBG_WARNING
#define CLEANUP_DPFL    PVR_DBG_MESSAGE

/* Create/initialise data required by the cleanup thread,
 * before the cleanup thread is started
 */
static PVRSRV_ERROR _CleanupThreadPrepare(PVRSRV_DATA *psPVRSRVData)
{
	PVRSRV_ERROR eError;

	/* Create the clean up event object */

	eError = OSEventObjectCreate("PVRSRV_CLEANUP_EVENTOBJECT", &gpsPVRSRVData->hCleanupEventObject);
	PVR_LOGG_IF_ERROR(eError, "OSEventObjectCreate", Exit);

	/* initialise the mutex and linked list required for the cleanup thread work list */

	eError = OSLockCreate(&psPVRSRVData->hCleanupThreadWorkListLock, LOCK_TYPE_PASSIVE);
	PVR_LOGG_IF_ERROR(eError, "OSLockCreate", Exit);

	dllist_init(&psPVRSRVData->sCleanupThreadWorkList);

Exit:
	return eError;
}

static void CleanupThread(void *pvData)
{
	PVRSRV_DATA *psPVRSRVData = pvData;
	IMG_BOOL     bRetryWorkList = IMG_FALSE;
	IMG_HANDLE	 hGlobalEvent;
	IMG_HANDLE	 hOSEvent;
	PVRSRV_ERROR eRc;
	IMG_BOOL bUseGlobalEO = IMG_FALSE;
	IMG_UINT32 uiUnloadRetry = 0;

	/* Store the process id (pid) of the clean-up thread */
	psPVRSRVData->cleanupThreadPid = OSGetCurrentProcessID();

	PVR_DPF((CLEANUP_DPFL, "CleanupThread: thread starting... "));

	/* Open an event on the clean up event object so we can listen on it,
	 * abort the clean up thread and driver if this fails.
	 */
	eRc = OSEventObjectOpen(psPVRSRVData->hCleanupEventObject, &hOSEvent);
	PVR_ASSERT(eRc == PVRSRV_OK);

	eRc = OSEventObjectOpen(psPVRSRVData->hGlobalEventObject, &hGlobalEvent);
	PVR_ASSERT(eRc == PVRSRV_OK);

	/* While the driver is in a good state and is not being unloaded
	 * try to free any deferred items when signalled
	 */
	while (psPVRSRVData->eServicesState == PVRSRV_SERVICES_STATE_OK)
	{
		IMG_HANDLE hEvent;

		if (psPVRSRVData->bUnload)
		{
			if (dllist_is_empty(&psPVRSRVData->sCleanupThreadWorkList) ||
					uiUnloadRetry > CLEANUP_THREAD_UNLOAD_RETRY)
			{
				break;
			}
			uiUnloadRetry++;
		}

		/* Wait until signalled for deferred clean up OR wait for a
		 * short period if the previous deferred clean up was not able
		 * to release all the resources before trying again.
		 * Bridge lock re-acquired on our behalf before the wait call returns.
		 */

		if (bRetryWorkList && bUseGlobalEO)
		{
			hEvent = hGlobalEvent;
		}
		else
		{
			hEvent = hOSEvent;
		}

		eRc = OSEventObjectWaitKernel(hEvent,
				bRetryWorkList ?
				CLEANUP_THREAD_WAIT_RETRY_TIMEOUT :
				CLEANUP_THREAD_WAIT_SLEEP_TIMEOUT);
		if (eRc == PVRSRV_ERROR_TIMEOUT)
		{
			PVR_DPF((CLEANUP_DPFL, "CleanupThread: wait timeout"));
		}
		else if (eRc == PVRSRV_OK)
		{
			PVR_DPF((CLEANUP_DPFL, "CleanupThread: wait OK, signal received"));
		}
		else
		{
			PVR_DPF((PVR_DBG_ERROR, "CleanupThread: wait error %d", eRc));
		}

		bRetryWorkList = _CleanupThreadProcessWorkList(psPVRSRVData, &bUseGlobalEO);
	}

	OSLockDestroy(psPVRSRVData->hCleanupThreadWorkListLock);

	eRc = OSEventObjectClose(hOSEvent);
	PVR_LOG_IF_ERROR(eRc, "OSEventObjectClose");

	eRc = OSEventObjectClose(hGlobalEvent);
	PVR_LOG_IF_ERROR(eRc, "OSEventObjectClose");

	PVR_DPF((CLEANUP_DPFL, "CleanupThread: thread ending... "));
}

static IMG_BOOL DevicesWatchdogThread_Powered_Any(PVRSRV_DEVICE_NODE *psDeviceNode)
{
	PVRSRV_DEV_POWER_STATE ePowerState = PVRSRV_DEV_POWER_STATE_ON;
	PVRSRV_ERROR eError;

	eError = PVRSRVPowerLock(psDeviceNode);
	if (eError != PVRSRV_OK)
	{
		if (eError == PVRSRV_ERROR_RETRY)
		{
			/* Power lock cannot be acquired at this time (sys power is off) */
			return IMG_FALSE;
		}

		/* Any other error is unexpected so we assume the device is on */
		PVR_DPF((PVR_DBG_ERROR,
				 "DevicesWatchdogThread: Failed to acquire power lock for device %p (%s)",
				 psDeviceNode, PVRSRVGetErrorStringKM(eError)));
		return IMG_TRUE;
	}

	(void) PVRSRVGetDevicePowerState(psDeviceNode, &ePowerState);

	PVRSRVPowerUnlock(psDeviceNode);

	return (ePowerState == PVRSRV_DEV_POWER_STATE_ON) ? IMG_TRUE : IMG_FALSE;
}

static void DevicesWatchdogThread_ForEachVaCb(PVRSRV_DEVICE_NODE *psDeviceNode,
											  va_list va)
{
	PVRSRV_RGXDEV_INFO *psDevInfo = (PVRSRV_RGXDEV_INFO *) psDeviceNode->pvDevice;
	PVRSRV_DEVICE_HEALTH_STATUS *pePreviousHealthStatus, eHealthStatus;
	PVRSRV_ERROR eError;

	pePreviousHealthStatus = va_arg(va, PVRSRV_DEVICE_HEALTH_STATUS *);

	if (psDeviceNode->pfnUpdateHealthStatus != NULL)
	{
		eError = psDeviceNode->pfnUpdateHealthStatus(psDeviceNode, IMG_TRUE);
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_WARNING, "DevicesWatchdogThread: "
					 "Could not check for fatal error (%d)!",
					 eError));
		}
	}
	eHealthStatus = OSAtomicRead(&psDeviceNode->eHealthStatus);

	if (eHealthStatus != PVRSRV_DEVICE_HEALTH_STATUS_OK)
	{
		if (eHealthStatus != *pePreviousHealthStatus)
		{
			if (!(psDevInfo->ui32DeviceFlags &
				  RGXKM_DEVICE_STATE_DISABLE_DW_LOGGING_EN))
			{
				PVR_DPF((PVR_DBG_ERROR, "DevicesWatchdogThread: "
						 "Device not responding!!!"));
				PVRSRVDebugRequest(psDeviceNode, DEBUG_REQUEST_VERBOSITY_MAX,
								   NULL, NULL);
			}
		}
	}

	*pePreviousHealthStatus = eHealthStatus;
}

static void DevicesWatchdogThread(void *pvData)
{
	PVRSRV_DATA *psPVRSRVData = pvData;
	PVRSRV_DEVICE_HEALTH_STATUS ePreviousHealthStatus = PVRSRV_DEVICE_HEALTH_STATUS_OK;
	IMG_HANDLE hOSEvent;
	PVRSRV_ERROR  eError;
	IMG_UINT32 ui32Timeout = DEVICES_WATCHDOG_POWER_ON_SLEEP_TIMEOUT;

	PVR_DPF((PVR_DBG_MESSAGE, "DevicesWatchdogThread: Power off sleep time: %d.",
			DEVICES_WATCHDOG_POWER_OFF_SLEEP_TIMEOUT));

	/* Open an event on the devices watchdog event object so we can listen on it
	   and abort the devices watchdog thread. */
	eError = OSEventObjectOpen(psPVRSRVData->hDevicesWatchdogEvObj, &hOSEvent);
	PVR_LOGRN_IF_ERROR(eError, "OSEventObjectOpen");

	/* Loop continuously checking the device status every few seconds. */
#if defined(PVRSRV_FORCE_UNLOAD_IF_BAD_STATE)
	while ((psPVRSRVData->eServicesState == PVRSRV_SERVICES_STATE_OK) &&
			!psPVRSRVData->bUnload)
#else
	while (!psPVRSRVData->bUnload)
#endif
	{
		IMG_BOOL bPwrIsOn = IMG_FALSE;

		/* Wait time between polls (done at the start of the loop to allow devices
		   to initialise) or for the event signal (shutdown or power on). */
		eError = OSEventObjectWaitKernel(hOSEvent, (IMG_UINT64)ui32Timeout * 1000);
#ifdef PVR_TESTING_UTILS
		psPVRSRVData->ui32DevicesWdWakeupCounter++;
#endif
		if (eError == PVRSRV_OK)
		{
			if (psPVRSRVData->bUnload)
			{
				PVR_DPF((PVR_DBG_MESSAGE, "DevicesWatchdogThread: Shutdown event received."));
				break;
			}
			else
			{
				PVR_DPF((PVR_DBG_MESSAGE, "DevicesWatchdogThread: Power state change event received."));
			}
		}
		else if (eError != PVRSRV_ERROR_TIMEOUT)
		{
			/* If timeout do nothing otherwise print warning message. */
			PVR_DPF((PVR_DBG_ERROR, "DevicesWatchdogThread: "
					"Error (%d) when waiting for event!", eError));
		}

		bPwrIsOn = List_PVRSRV_DEVICE_NODE_IMG_BOOL_Any(psPVRSRVData->psDeviceNodeList,
														DevicesWatchdogThread_Powered_Any);
		if (bPwrIsOn || psPVRSRVData->ui32DevicesWatchdogPwrTrans)
		{
			psPVRSRVData->ui32DevicesWatchdogPwrTrans = 0;
			ui32Timeout = psPVRSRVData->ui32DevicesWatchdogTimeout = DEVICES_WATCHDOG_POWER_ON_SLEEP_TIMEOUT;
		}
		else
		{
			ui32Timeout = psPVRSRVData->ui32DevicesWatchdogTimeout = DEVICES_WATCHDOG_POWER_OFF_SLEEP_TIMEOUT;
		}

		List_PVRSRV_DEVICE_NODE_ForEach_va(psPVRSRVData->psDeviceNodeList,
										   DevicesWatchdogThread_ForEachVaCb,
										   &ePreviousHealthStatus);

#if defined(SUPPORT_GPUVIRT_VALIDATION) && defined(EMULATOR)
		SysPrintAndResetFaultStatusRegister();
#endif
	}

	eError = OSEventObjectClose(hOSEvent);
	PVR_LOG_IF_ERROR(eError, "OSEventObjectClose");
}


PVRSRV_DATA *PVRSRVGetPVRSRVData()
{
	return gpsPVRSRVData;
}

static PVRSRV_ERROR _HostMemDeviceCreate(void)
{
	PVRSRV_ERROR eError;
	PVRSRV_DEVICE_NODE *psDeviceNode;
	PVRSRV_DEVICE_CONFIG *psDevConfig = HostMemGetDeviceConfig();
	PVRSRV_DATA *psPVRSRVData = PVRSRVGetPVRSRVData();

	/* Assert ensures HostMemory device isn't already created and
	 * that data is initialized */
	PVR_ASSERT(psPVRSRVData->psHostMemDeviceNode == NULL);

	/* for now, we only know a single heap (UMA) config for host device */
	PVR_ASSERT(psDevConfig->ui32PhysHeapCount == 1 &&
				psDevConfig->pasPhysHeaps[0].eType == PHYS_HEAP_TYPE_UMA);

	/* N.B.- In case of any failures in this function, we just return error to
	   the caller, as clean-up is taken care by _HostMemDeviceDestroy function */

	psDeviceNode = OSAllocZMem(sizeof(*psDeviceNode));
	PVR_LOGR_IF_NOMEM(psDeviceNode, "OSAllocZMem");

	/* early save return pointer to aid clean-up */
	psPVRSRVData->psHostMemDeviceNode = psDeviceNode;

	psDeviceNode->psDevConfig = psDevConfig;
	psDeviceNode->papsRegisteredPhysHeaps =
		OSAllocZMem(sizeof(*psDeviceNode->papsRegisteredPhysHeaps) *
					psDevConfig->ui32PhysHeapCount);
	PVR_LOGR_IF_NOMEM(psDeviceNode->papsRegisteredPhysHeaps, "OSAllocZMem");

	eError = PhysHeapRegister(&psDevConfig->pasPhysHeaps[0],
								  &psDeviceNode->papsRegisteredPhysHeaps[0]);
	PVR_LOGR_IF_ERROR(eError, "PhysHeapRegister");
	psDeviceNode->ui32RegisteredPhysHeaps = 1;

	/* Only CPU local heap is valid on host-mem DevNode, so enable minimal callbacks */
	eError = PhysHeapAcquire(psDevConfig->aui32PhysHeapID[PVRSRV_DEVICE_PHYS_HEAP_CPU_LOCAL],
							 &psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_CPU_LOCAL]);
	PVR_LOGR_IF_ERROR(eError, "PhysHeapAcquire");
	
	psDeviceNode->pfnCreateRamBackedPMR[PVRSRV_DEVICE_PHYS_HEAP_CPU_LOCAL] = PhysmemNewOSRamBackedPMR;

	return PVRSRV_OK;
}

static void _HostMemDeviceDestroy(void)
{
	PVRSRV_DATA *psPVRSRVData = PVRSRVGetPVRSRVData();
	PVRSRV_DEVICE_NODE *psDeviceNode = psPVRSRVData->psHostMemDeviceNode;

	if (!psDeviceNode)
	{
		return;
	}

	psPVRSRVData->psHostMemDeviceNode = NULL;
	if (psDeviceNode->papsRegisteredPhysHeaps)
	{
		if (psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_CPU_LOCAL])
		{
			PhysHeapRelease(psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_CPU_LOCAL]);
		}
	
		if (psDeviceNode->papsRegisteredPhysHeaps[0])
		{
			/* clean-up function as well is aware of only one heap */
			PVR_ASSERT(psDeviceNode->ui32RegisteredPhysHeaps == 1);
			PhysHeapUnregister(psDeviceNode->papsRegisteredPhysHeaps[0]);
		}

		OSFreeMem(psDeviceNode->papsRegisteredPhysHeaps);
	}
	OSFreeMem(psDeviceNode);
}

static PVRSRV_ERROR _BridgeBufferAlloc(void *pvPrivData, void **pvOut)
{
	PVR_UNREFERENCED_PARAMETER(pvPrivData);

	*pvOut = OSAllocZMem(PVRSRV_MAX_BRIDGE_IN_SIZE +
						PVRSRV_MAX_BRIDGE_OUT_SIZE);

	if(*pvOut == NULL)
	{
		return PVRSRV_ERROR_OUT_OF_MEMORY;
	}

	return PVRSRV_OK;
}

static void _BridgeBufferFree(void *pvPrivData, void *pvFreeData)
{
	PVR_UNREFERENCED_PARAMETER(pvPrivData);

	OSFreeMem(pvFreeData);
}

PVRSRV_ERROR IMG_CALLCONV
PVRSRVDriverInit(void)
{
	PVRSRV_ERROR eError;
	PVRSRV_DATA	*psPVRSRVData = NULL;

	IMG_UINT32 ui32AppHintCleanupThreadPriority;
	IMG_UINT32 ui32AppHintCleanupThreadWeight;
	IMG_UINT32 ui32AppHintWatchdogThreadPriority;
	IMG_UINT32 ui32AppHintWatchdogThreadWeight;

	void *pvAppHintState = NULL;
	IMG_UINT32 ui32AppHintDefault;

	/*
	 * As this function performs one time driver initialisation, use the
	 * Services global device-independent data to determine whether or not
	 * this function has already been called.
	 */
	if (gpsPVRSRVData)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Driver already initialised", __func__));
		return PVRSRV_ERROR_ALREADY_EXISTS;
	}

	eError = PhysHeapInit();
	if (eError != PVRSRV_OK)
	{
		goto Error;
	}

	/*
	 * Allocate the device-independent data
	 */
	psPVRSRVData = OSAllocZMem(sizeof(*gpsPVRSRVData));
	if (psPVRSRVData == NULL)
	{
		eError = PVRSRV_ERROR_OUT_OF_MEMORY;
		goto Error;
	}

	/* Now it is set up, point gpsPVRSRVData to the actual data */
	gpsPVRSRVData = psPVRSRVData;

	eError = PVRSRVPoolCreate(_BridgeBufferAlloc,
							_BridgeBufferFree,
							PVRSRV_MAX_POOLED_BRIDGE_BUFFERS,
							"Bridge buffer pool",
							NULL,
							&psPVRSRVData->psBridgeBufferPool);

	if(eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed to create bridge buffer pool: %s",
										__func__,
										PVRSRVGetErrorStringKM(eError)));
		goto Error;
	}

	/* Init any OS specific's */
	eError = OSInitEnvData();
	if (eError != PVRSRV_OK)
	{
		goto Error;
	}

	/* Early init. server cache maintenance */
	eError = CacheOpInit();
	if (eError != PVRSRV_OK)
	{
		goto Error;
	}

#if defined(PVR_RI_DEBUG)
	RIInitKM();
#endif

#if defined(SUPPORT_PAGE_FAULT_DEBUG)
	eError = DevicememHistoryInitKM();

	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
				 "%s: Failed to initialise DevicememHistoryInitKM", __func__));
		goto Error;
	}
#endif

	eError = BridgeInit();
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed to initialise bridge",
				 __func__));
		goto Error;
	}

	eError = PMRInit();
	if (eError != PVRSRV_OK)
	{
		goto Error;
	}

#if defined(SUPPORT_DISPLAY_CLASS)
	eError = DCInit();
	if (eError != PVRSRV_OK)
	{
		goto Error;
	}
#endif

	/* Initialise overall system state */
	gpsPVRSRVData->eServicesState = PVRSRV_SERVICES_STATE_OK;

	/* Create an event object */
	eError = OSEventObjectCreate("PVRSRV_GLOBAL_EVENTOBJECT", &gpsPVRSRVData->hGlobalEventObject);
	if (eError != PVRSRV_OK)
	{
		goto Error;
	}
	gpsPVRSRVData->ui32GEOConsecutiveTimeouts = 0;

	eError = PVRSRVCmdCompleteInit();
	if (eError != PVRSRV_OK)
	{
		goto Error;
	}

	/* Initialise pdump */
	eError = PDUMPINIT();
	if (eError != PVRSRV_OK)
	{
		goto Error;
	}

	g_ui32InitFlags |= INIT_DATA_ENABLE_PDUMPINIT;

	eError = PVRSRVHandleInit();
	if (eError != PVRSRV_OK)
	{
		goto Error;
	}
	
	eError = _CleanupThreadPrepare(gpsPVRSRVData);
	PVR_LOGG_IF_ERROR(eError, "_CleanupThreadPrepare", Error);

	/* Create a thread which is used to do the deferred cleanup */
	eError = OSThreadCreatePriority(&gpsPVRSRVData->hCleanupThread,
							"pvr_defer_free",
							CleanupThread,
							gpsPVRSRVData,
							OS_THREAD_LOWEST_PRIORITY);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed to create deferred cleanup thread",
				 __func__));
		goto Error;
	}

	OSCreateKMAppHintState(&pvAppHintState);
	ui32AppHintDefault = PVRSRV_APPHINT_CLEANUPTHREADPRIORITY;
	OSGetKMAppHintUINT32(pvAppHintState, CleanupThreadPriority,
	                     &ui32AppHintDefault, &ui32AppHintCleanupThreadPriority);
	ui32AppHintDefault = PVRSRV_APPHINT_CLEANUPTHREADWEIGHT;
	OSGetKMAppHintUINT32(pvAppHintState, CleanupThreadWeight,
	                     &ui32AppHintDefault, &ui32AppHintCleanupThreadWeight);
	ui32AppHintDefault = PVRSRV_APPHINT_WATCHDOGTHREADPRIORITY;
	OSGetKMAppHintUINT32(pvAppHintState, WatchdogThreadPriority,
	                     &ui32AppHintDefault, &ui32AppHintWatchdogThreadPriority);
	ui32AppHintDefault = PVRSRV_APPHINT_WATCHDOGTHREADWEIGHT;
	OSGetKMAppHintUINT32(pvAppHintState, WatchdogThreadWeight,
	                     &ui32AppHintDefault, &ui32AppHintWatchdogThreadWeight);
	OSFreeKMAppHintState(pvAppHintState);
	pvAppHintState = NULL;

	eError = OSSetThreadPriority(gpsPVRSRVData->hCleanupThread,
								 ui32AppHintCleanupThreadPriority,
								 ui32AppHintCleanupThreadWeight);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed to set thread priority of deferred cleanup thread.",
				 __func__));
		goto Error;
	}

	/* Create the devices watchdog event object */
	eError = OSEventObjectCreate("PVRSRV_DEVICESWATCHDOG_EVENTOBJECT", &gpsPVRSRVData->hDevicesWatchdogEvObj);
	PVR_LOGG_IF_ERROR(eError, "OSEventObjectCreate", Error);

	/* Create a thread which is used to detect fatal errors */
	eError = OSThreadCreate(&gpsPVRSRVData->hDevicesWatchdogThread,
							"pvr_device_wdg",
							DevicesWatchdogThread,
							gpsPVRSRVData);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed to create devices watchdog thread",
				 __func__));
		goto Error;
	}

	eError = OSSetThreadPriority(gpsPVRSRVData->hDevicesWatchdogThread,
								 ui32AppHintWatchdogThreadPriority,
								 ui32AppHintWatchdogThreadWeight);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed to set thread priority of the watchdog thread.",
				 __func__));
		goto Error;
	}

	gpsPVRSRVData->psProcessHandleBase_Table = HASH_Create(PVRSRV_PROC_HANDLE_BASE_INIT);

	if (gpsPVRSRVData->psProcessHandleBase_Table == NULL)
	{
		PVR_DPF((PVR_DBG_ERROR,
				"%s: Failed to create hash table for process handle base.",
				__func__));
		eError = PVRSRV_ERROR_UNABLE_TO_CREATE_HASH_TABLE;
		goto Error;
	}

	eError = OSLockCreate(&gpsPVRSRVData->hProcessHandleBase_Lock, LOCK_TYPE_PASSIVE);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
				"%s: Failed to create lock for process handle base.",
				__func__));
		goto Error;
	}

	eError = _HostMemDeviceCreate();
	if (eError != PVRSRV_OK)
	{
		goto Error;
	}

	eError = InfoPageCreate(psPVRSRVData);
	PVR_LOGG_IF_ERROR(eError, "InfoPageCreate", Error);

	/* Initialise the Transport Layer */
	eError = TLInit();
	if (eError != PVRSRV_OK)
	{
		goto Error;
	}

	/* Initialise TL control stream */
	eError = TLStreamCreate(&psPVRSRVData->hTLCtrlStream,
	                        psPVRSRVData->psHostMemDeviceNode,
	                        PVRSRV_TL_CTLR_STREAM, PVRSRV_TL_CTLR_STREAM_SIZE,
	                        TL_OPMODE_DROP_OLDEST, NULL, NULL, NULL,
                            NULL);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "Failed to create TL control plane stream"
		        " (%d).", eError));
		psPVRSRVData->hTLCtrlStream = NULL;
	}

#if defined (SUPPORT_GPUTRACE_EVENTS)
	eError = PVRGpuTraceSupportInit();
	if (eError != PVRSRV_OK)
	{
		goto Error;
	}
#endif

	RGXHWPerfClientInitAppHintCallbacks();

	/* Late init. client cache maintenance via info. page */
	eError = CacheOpInit2();
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
				"%s: failed to initialise the CacheOp framework (%d)",
				__func__, eError));
		goto Error;
	}

	eError = ServerSyncInitOnce(psPVRSRVData);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
				"%s: Failed to initialise sync server",
				__func__));
		goto Error;
	}

	dllist_init(&psPVRSRVData->sConnections);
	eError = OSLockCreate(&psPVRSRVData->hConnectionsLock, LOCK_TYPE_PASSIVE);
	PVR_LOGG_IF_ERROR(eError, "OSLockCreate", Error);

	return 0;

Error:
	PVRSRVDriverDeInit();
	return eError;
}

void IMG_CALLCONV
PVRSRVDriverDeInit(void)
{
	PVRSRV_ERROR eError = PVRSRV_OK;

	if (gpsPVRSRVData == NULL)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: missing device-independent data",
				 __func__));
		return;
	}

	gpsPVRSRVData->bUnload = IMG_TRUE;

	if (gpsPVRSRVData->hProcessHandleBase_Lock)
	{
		OSLockDestroy(gpsPVRSRVData->hProcessHandleBase_Lock);
		gpsPVRSRVData->hProcessHandleBase_Lock = NULL;
	}

	if (gpsPVRSRVData->psProcessHandleBase_Table)
	{
		HASH_Delete(gpsPVRSRVData->psProcessHandleBase_Table);
		gpsPVRSRVData->psProcessHandleBase_Table = NULL;
	}

	if (gpsPVRSRVData->hGlobalEventObject)
	{
		OSEventObjectSignal(gpsPVRSRVData->hGlobalEventObject);
	}

	/* Stop and cleanup the devices watchdog thread */
	if (gpsPVRSRVData->hDevicesWatchdogThread)
	{
		if (gpsPVRSRVData->hDevicesWatchdogEvObj)
		{
			eError = OSEventObjectSignal(gpsPVRSRVData->hDevicesWatchdogEvObj);
			PVR_LOG_IF_ERROR(eError, "OSEventObjectSignal");
		}
		LOOP_UNTIL_TIMEOUT(OS_THREAD_DESTROY_TIMEOUT_US)
		{
			eError = OSThreadDestroy(gpsPVRSRVData->hDevicesWatchdogThread);
			if (PVRSRV_OK == eError)
			{
				gpsPVRSRVData->hDevicesWatchdogThread = NULL;
				break;
			}
			OSWaitus(OS_THREAD_DESTROY_TIMEOUT_US/OS_THREAD_DESTROY_RETRY_COUNT);
		} END_LOOP_UNTIL_TIMEOUT();
		PVR_LOG_IF_ERROR(eError, "OSThreadDestroy");
	}

	if (gpsPVRSRVData->hDevicesWatchdogEvObj)
	{
		eError = OSEventObjectDestroy(gpsPVRSRVData->hDevicesWatchdogEvObj);
		gpsPVRSRVData->hDevicesWatchdogEvObj = NULL;
		PVR_LOG_IF_ERROR(eError, "OSEventObjectDestroy");
	}

	/* Stop and cleanup the deferred clean up thread, event object and
	 * deferred context list.
	 */
	if (gpsPVRSRVData->hCleanupThread)
	{
		if (gpsPVRSRVData->hCleanupEventObject)
		{
			eError = OSEventObjectSignal(gpsPVRSRVData->hCleanupEventObject);
			PVR_LOG_IF_ERROR(eError, "OSEventObjectSignal");
		}
		LOOP_UNTIL_TIMEOUT(OS_THREAD_DESTROY_TIMEOUT_US)
		{
			eError = OSThreadDestroy(gpsPVRSRVData->hCleanupThread);
			if (PVRSRV_OK == eError)
			{
				gpsPVRSRVData->hCleanupThread = NULL;
				break;
			}
			OSWaitus(OS_THREAD_DESTROY_TIMEOUT_US/OS_THREAD_DESTROY_RETRY_COUNT);
		} END_LOOP_UNTIL_TIMEOUT();
		PVR_LOG_IF_ERROR(eError, "OSThreadDestroy");
	}

	if (gpsPVRSRVData->hCleanupEventObject)
	{
		eError = OSEventObjectDestroy(gpsPVRSRVData->hCleanupEventObject);
		gpsPVRSRVData->hCleanupEventObject = NULL;
		PVR_LOG_IF_ERROR(eError, "OSEventObjectDestroy");
	}

	/* Tear down the HTB before PVRSRVHandleDeInit() removes its TL handle */
	/* HTB De-init happens in device de-registration currently */
	eError = HTBDeInit();
	PVR_LOG_IF_ERROR(eError, "HTBDeInit");

#if defined (SUPPORT_GPUTRACE_EVENTS)
	PVRGpuTraceSupportDeInit();
#endif

	/* Tear down CacheOp framework information page first */
	CacheOpDeInit2();

	ServerSyncDeinitOnce(gpsPVRSRVData);

	/* Close the TL control plane stream. */
	TLStreamClose(gpsPVRSRVData->hTLCtrlStream);

	/* Clean up Transport Layer resources that remain */
	TLDeInit();

	/* Clean up information page */
	InfoPageDestroy(gpsPVRSRVData);

	_HostMemDeviceDestroy();

	eError = PVRSRVHandleDeInit();
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: PVRSRVHandleDeInit failed", __func__));
	}

	/* deinitialise pdump */
	if ((g_ui32InitFlags & INIT_DATA_ENABLE_PDUMPINIT) > 0)
	{
		PDUMPDEINIT();
	}
	
	/* destroy event object */
	if (gpsPVRSRVData->hGlobalEventObject)
	{
		OSEventObjectDestroy(gpsPVRSRVData->hGlobalEventObject);
		gpsPVRSRVData->hGlobalEventObject = NULL;
	}

	PVRSRVCmdCompleteDeinit();

#if defined(SUPPORT_DISPLAY_CLASS)
	eError = DCDeInit();
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: DCDeInit failed", __func__));
	}
#endif

	eError = PMRDeInit();
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: PMRDeInit failed", __func__));
	}

	BridgeDeinit();

#if defined(PVR_RI_DEBUG)
	RIDeInitKM();
#endif

#if defined(SUPPORT_PAGE_FAULT_DEBUG)
	DevicememHistoryDeInitKM();
#endif

	CacheOpDeInit();

	PVRSRVPoolDestroy(gpsPVRSRVData->psBridgeBufferPool);

	OSDeInitEnvData();

	eError = PhysHeapDeinit();
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: PhysHeapDeinit failed", __func__));
	}

	OSFreeMem(gpsPVRSRVData);
	gpsPVRSRVData = NULL;
}

#if defined(SUPPORT_GPUVIRT_VALIDATION)
static PVRSRV_ERROR CreateLMASubArenas(PVRSRV_DEVICE_NODE *psDeviceNode)
{
	IMG_UINT	uiCounter=0;

	for (uiCounter = 0; uiCounter < GPUVIRT_VALIDATION_NUM_OS; uiCounter++)
	{
		psDeviceNode->psOSidSubArena[uiCounter] =
			RA_Create(psDeviceNode->apszRANames[0],
					  OSGetPageShift(),			/* Use host page size, keeps things simple */
					  RA_LOCKCLASS_0,			/* This arena doesn't use any other arenas. */
					  NULL,					/* No Import */
					  NULL,					/* No free import */
					  NULL,					/* No import handle */
					  IMG_FALSE);

		if (psDeviceNode->psOSidSubArena[uiCounter] == NULL)
		{
			return PVRSRV_ERROR_OUT_OF_MEMORY;
		}
	}

	PVR_DPF((PVR_DBG_MESSAGE,"\n(GPU Virtualization Validation): Calling RA_Add with base %u and size %u \n",0, GPUVIRT_SIZEOF_ARENA0));

	/* Arena creation takes place earlier than when the client side reads the apphints and transfers them over the bridge. Since we don't
	 * know how the memory is going to be partitioned and since we already need some memory for all the initial allocations that take place,
	 * we populate the first sub-arena (0) with a span of 64 megabytes. This has been shown to be enough even for cases where EWS is allocated
	 * memory in this sub arena and then a multi app example is executed. This pre-allocation also means that consistency must be maintained
	 * between apphints and reality. That's why in the Apphints, the OSid0 region must start from 0 and end at 3FFFFFF. */

	if (!RA_Add(psDeviceNode->psOSidSubArena[0], 0, GPUVIRT_SIZEOF_ARENA0, 0 , NULL))
	{
		RA_Delete(psDeviceNode->psOSidSubArena[0]);
		return PVRSRV_ERROR_OUT_OF_MEMORY;
	}

	psDeviceNode->apsLocalDevMemArenas[0] = psDeviceNode->psOSidSubArena[0];

	return PVRSRV_OK;
}

void PopulateLMASubArenas(PVRSRV_DEVICE_NODE *psDeviceNode,
						  IMG_UINT32 aui32OSidMin[GPUVIRT_VALIDATION_NUM_REGIONS][GPUVIRT_VALIDATION_NUM_OS],
						  IMG_UINT32 aui32OSidMax[GPUVIRT_VALIDATION_NUM_REGIONS][GPUVIRT_VALIDATION_NUM_OS])
{
	IMG_UINT	uiCounter;

	/* Since Sub Arena[0] has been populated already, now we populate the rest starting from 1*/

	for (uiCounter = 1; uiCounter < GPUVIRT_VALIDATION_NUM_OS; uiCounter++)
	{
		PVR_DPF((PVR_DBG_MESSAGE,"\n[GPU Virtualization Validation]: Calling RA_Add with base %u and size %u \n",aui32OSidMin[0][uiCounter], aui32OSidMax[0][uiCounter]-aui32OSidMin[0][uiCounter]+1));

		if (!RA_Add(psDeviceNode->psOSidSubArena[uiCounter], aui32OSidMin[0][uiCounter], aui32OSidMax[0][uiCounter]-aui32OSidMin[0][uiCounter]+1, 0, NULL))
		{
			goto error;
		}
	}

	#if defined(EMULATOR)
	{
		SysSetOSidRegisters(aui32OSidMin, aui32OSidMax);
	}
	#endif

	return;

error:
	for (uiCounter = 0; uiCounter < GPUVIRT_VALIDATION_NUM_OS; uiCounter++)
	{
		RA_Delete(psDeviceNode->psOSidSubArena[uiCounter]);
	}

	return;
}

#endif

static void _SysDebugRequestNotify(PVRSRV_DBGREQ_HANDLE hDebugRequestHandle,
					IMG_UINT32 ui32VerbLevel,
					DUMPDEBUG_PRINTF_FUNC *pfnDumpDebugPrintf,
					void *pvDumpDebugFile)
{
	/* Only dump info once */
	if (ui32VerbLevel == DEBUG_REQUEST_VERBOSITY_LOW)
	{
		PVRSRV_DEVICE_NODE *psDeviceNode =
			(PVRSRV_DEVICE_NODE *) hDebugRequestHandle;

		switch (psDeviceNode->eCurrentSysPowerState)
		{
			case PVRSRV_SYS_POWER_STATE_OFF:
				PVR_DUMPDEBUG_LOG("Device System Power State: OFF");
				break;
			case PVRSRV_SYS_POWER_STATE_ON:
				PVR_DUMPDEBUG_LOG("Device System Power State: ON");
				break;
			default:
				PVR_DUMPDEBUG_LOG("Device System Power State: UNKNOWN (%d)",
								   psDeviceNode->eCurrentSysPowerState);
				break;
		}

		SysDebugInfo(psDeviceNode->psDevConfig, pfnDumpDebugPrintf, pvDumpDebugFile);
	}
}

PVRSRV_ERROR IMG_CALLCONV PVRSRVDeviceCreate(void *pvOSDevice,
											 IMG_INT32 i32UMIdentifier,
											 PVRSRV_DEVICE_NODE **ppsDeviceNode)
{
	PVRSRV_DATA				*psPVRSRVData = PVRSRVGetPVRSRVData();
	PVRSRV_ERROR			eError;
	PVRSRV_DEVICE_CONFIG	*psDevConfig;
	PVRSRV_DEVICE_NODE		*psDeviceNode;
	PVRSRV_RGXDEV_INFO		*psDevInfo;
	PVRSRV_DEVICE_PHYS_HEAP	physHeapIndex;
	IMG_UINT32				i;
	IMG_UINT32				ui32AppHintDefault;
	IMG_UINT32				ui32AppHintDriverMode;
	void *pvAppHintState    = NULL;
#if defined(PVRSRV_ENABLE_PROCESS_STATS) && !defined(PVRSRV_DEBUG_LINUX_MEMORY_STATS)
	IMG_HANDLE				hProcessStats;
#endif

	psDeviceNode = OSAllocZMemNoStats(sizeof(*psDeviceNode));
	if (!psDeviceNode)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed to allocate device node",
				 __func__));
		return PVRSRV_ERROR_OUT_OF_MEMORY;
	}

	/* Allocate process statistics */
#if defined(PVRSRV_ENABLE_PROCESS_STATS) && !defined(PVRSRV_DEBUG_LINUX_MEMORY_STATS)
	eError = PVRSRVStatsRegisterProcess(&hProcessStats);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
			 "%s: Couldn't register process statistics (%d)",
			 __func__, eError));
		goto ErrorFreeDeviceNode;
	}
#endif

	psDeviceNode->sDevId.i32UMIdentifier = i32UMIdentifier;

	eError = SysDevInit(pvOSDevice, &psDevConfig);
	if (eError)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed to get device config (%s)",
				 __func__, PVRSRVGetErrorStringKM(eError)));

		goto ErrorDeregisterStats;
	}

	PVR_ASSERT(psDevConfig);
	PVR_ASSERT(psDevConfig->pvOSDevice == pvOSDevice);
	PVR_ASSERT(!psDevConfig->psDevNode);

	/* Store the device node in the device config for the system layer to use */
	psDevConfig->psDevNode = psDeviceNode;

	psDeviceNode->eDevState = PVRSRV_DEVICE_STATE_INIT;
	psDeviceNode->psDevConfig = psDevConfig;
	psDeviceNode->eCurrentSysPowerState = PVRSRV_SYS_POWER_STATE_ON;
	psDevInfo = (PVRSRV_RGXDEV_INFO *) psDeviceNode->pvDevice;

	/* Read driver mode (i.e. native, host or guest) AppHint */
	ui32AppHintDefault = PVRSRV_APPHINT_DRIVERMODE;
	OSCreateKMAppHintState(&pvAppHintState);
	OSGetKMAppHintUINT32(pvAppHintState, DriverMode,
						 &ui32AppHintDefault, &ui32AppHintDriverMode);
	OSFreeKMAppHintState(pvAppHintState);
	pvAppHintState = NULL;

	/*
	 * Driver mode AppHint comes in override and (default) non-override
	 * values. Override values always take priority else if the system
	 * layer provides a callback use it. If both of these are absent, use
	 * the supplied (or default) non-override value.
	 */
	if (PVRSRV_VZ_APPHINT_MODE_IS_OVERRIDE(ui32AppHintDriverMode))
	{
		psPVRSRVData->eDriverMode = PVRSRV_VZ_APPHINT_MODE(ui32AppHintDriverMode);
	}
	else if (psDeviceNode->psDevConfig->pfnSysDriverMode)
	{
		psPVRSRVData->eDriverMode = psDeviceNode->psDevConfig->pfnSysDriverMode();
	}
	else
	{
		psPVRSRVData->eDriverMode = PVRSRV_VZ_APPHINT_MODE(ui32AppHintDriverMode);
	}

	/*
	 * Ensure that the supplied driver execution mode is consistent with the number
	 * of OSIDs the firmware can support. Any failure here is (should be) fatal as
	 * the requested for driver mode cannot be supported by the firmware.
	 */
	switch (psPVRSRVData->eDriverMode)
	{
		case DRIVER_MODE_NATIVE:
		/* Always supported mode */
			break;

		case DRIVER_MODE_HOST:
		case DRIVER_MODE_GUEST:
#if (RGXFW_NUM_OS == 1)
			PVR_DPF((PVR_DBG_ERROR, "The number of firmware supported OSID(s) is 1"));
			PVR_DPF((PVR_DBG_ERROR,	"Halting initialisation, cannot transition to %s mode",
					psPVRSRVData->eDriverMode == DRIVER_MODE_HOST ? "host" : "guest"));
			eError = PVRSRV_ERROR_NOT_SUPPORTED;
			goto ErrorDeregisterStats;
#endif
			break;

		default:
			if (psDevInfo->sDevFeatureCfg.ui64Features & RGX_FEATURE_GPU_VIRTUALISATION_BIT_MASK)
			{
				/* Running on VZ capable BVNC, invalid driver mode enumeration integer value */
				PVR_DPF((PVR_DBG_ERROR, "Halting initialisation due to invalid driver mode %d",
						(IMG_INT32)psPVRSRVData->eDriverMode));
				eError = PVRSRV_ERROR_NOT_SUPPORTED;
				goto ErrorDeregisterStats;
			}
			else if ((IMG_INT32)psPVRSRVData->eDriverMode <  (IMG_INT32)DRIVER_MODE_NATIVE ||
					 (IMG_INT32)psPVRSRVData->eDriverMode >= (IMG_INT32)RGXFW_NUM_OS)
			{
				/* Running on non-VZ capable BVNC so simulating OSID using eDriverMode but
				   value is outside of permitted range */
				PVR_DPF((PVR_DBG_ERROR,
						"Halting initialisation, OSID %d is outside of range [0:%d] supported",
						(IMG_INT)psPVRSRVData->eDriverMode, RGXFW_NUM_OS-1));
				eError = PVRSRV_ERROR_NOT_SUPPORTED;
				goto ErrorDeregisterStats;
			}
			break;
	}

	/* Perform additional VZ system initialisation */
	eError = SysVzDevInit(psDevConfig);
	if (eError)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed system virtualization initialisation (%s)",
				 __func__, PVRSRVGetErrorStringKM(eError)));
		goto ErrorDeregisterStats;
	}

	eError = PVRSRVRegisterDbgTable(psDeviceNode,
									g_aui32DebugOrderTable,
									IMG_ARR_NUM_ELEMS(g_aui32DebugOrderTable));
	if (eError != PVRSRV_OK)
	{
		goto ErrorSysDevDeInit;
	}

	eError = OSLockCreate(&psDeviceNode->hPowerLock, LOCK_TYPE_PASSIVE);
	if (eError != PVRSRV_OK)
	{
		goto ErrorUnregisterDbgTable;
	}

	/* Register the physical memory heaps */
	psDeviceNode->papsRegisteredPhysHeaps =
		OSAllocZMem(sizeof(*psDeviceNode->papsRegisteredPhysHeaps) *
					psDevConfig->ui32PhysHeapCount);
	if (!psDeviceNode->papsRegisteredPhysHeaps)
	{
		goto ErrorPowerLockDestroy;
	}

	for (i = 0; i < psDevConfig->ui32PhysHeapCount; i++)
	{
		/* No real device should register a heap with ID same as host device's heap ID */
		PVR_ASSERT(psDevConfig->pasPhysHeaps[i].ui32PhysHeapID != PHYS_HEAP_ID_HOSTMEM);

		eError = PhysHeapRegister(&psDevConfig->pasPhysHeaps[i],
								  &psDeviceNode->papsRegisteredPhysHeaps[i]);
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR,
					 "%s: Failed to register physical heap %d (%s)",
					 __func__, psDevConfig->pasPhysHeaps[i].ui32PhysHeapID,
					 PVRSRVGetErrorStringKM(eError)));
			goto ErrorPhysHeapsUnregister;
		}

		psDeviceNode->ui32RegisteredPhysHeaps++;
	}

	/*
	 * The physical backing storage for the following physical heaps
	 * [CPU,GPU,FW] may or may not come from the same underlying source
	 */
	eError = PhysHeapAcquire(psDevConfig->aui32PhysHeapID[PVRSRV_DEVICE_PHYS_HEAP_GPU_LOCAL],
							 &psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_GPU_LOCAL]);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
				 "%s: Failed to acquire PVRSRV_DEVICE_PHYS_HEAP_GPU_LOCAL physical memory heap",
				 __func__));
		goto ErrorPhysHeapsUnregister;
	}

	eError = PhysHeapAcquire(psDevConfig->aui32PhysHeapID[PVRSRV_DEVICE_PHYS_HEAP_CPU_LOCAL],
							 &psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_CPU_LOCAL]);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
				 "%s: Failed to acquire PVRSRV_DEVICE_PHYS_HEAP_CPU_LOCAL physical memory heap",
				 __func__));
		goto ErrorPhysHeapsRelease;
	}

	eError = PhysHeapAcquire(psDevConfig->aui32PhysHeapID[PVRSRV_DEVICE_PHYS_HEAP_FW_LOCAL],
							 &psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_FW_LOCAL]);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
				 "%s: Failed to acquire PVRSRV_DEVICE_PHYS_HEAP_FW_LOCAL physical memory heap",
				 __func__));
		goto ErrorPhysHeapsRelease;
	}

	eError = PhysHeapAcquire(psDevConfig->aui32PhysHeapID[PVRSRV_DEVICE_PHYS_HEAP_EXTERNAL],
							 &psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_EXTERNAL]);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
				 "%s: Failed to acquire PVRSRV_DEVICE_PHYS_HEAP_EXTERNAL physical memory heap",
				 __func__));
		goto ErrorPhysHeapsRelease;
	}

	/* Do we have card memory? If so create RAs to manage it */
	if (PhysHeapGetType(psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_GPU_LOCAL]) == PHYS_HEAP_TYPE_LMA)
	{
		RA_BASE_T uBase;
		RA_LENGTH_T uSize;
		IMG_UINT64 ui64Size;
		IMG_CPU_PHYADDR sCpuPAddr;
		IMG_DEV_PHYADDR sDevPAddr;

		IMG_UINT32 ui32NumOfLMARegions;
		IMG_UINT32 ui32RegionId;
		PHYS_HEAP* psLMAHeap;

		psLMAHeap = psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_GPU_LOCAL];
		ui32NumOfLMARegions = PhysHeapNumberOfRegions(psLMAHeap);

		if (ui32NumOfLMARegions == 0)
		{
			PVR_DPF((PVR_DBG_ERROR,
					 "%s: LMA heap has no memory regions defined.", __func__));
			eError = PVRSRV_ERROR_DEVICEMEM_INVALID_LMA_HEAP;
			goto ErrorPhysHeapsRelease;
		}

		/* Allocate memory for RA pointers and name strings */
		psDeviceNode->apsLocalDevMemArenas = OSAllocMem(sizeof(RA_ARENA*) * ui32NumOfLMARegions);
		psDeviceNode->ui32NumOfLocalMemArenas = ui32NumOfLMARegions;
		psDeviceNode->apszRANames = OSAllocMem(ui32NumOfLMARegions * sizeof(IMG_PCHAR));

		for (ui32RegionId = 0; ui32RegionId < ui32NumOfLMARegions; ui32RegionId++)
		{
			eError = PhysHeapRegionGetSize(psLMAHeap, ui32RegionId, &ui64Size);
			if (eError != PVRSRV_OK)
			{
				/* We can only get here if there is a bug in this module */
				PVR_ASSERT(IMG_FALSE);
				return eError;
			}

			eError = PhysHeapRegionGetCpuPAddr(psLMAHeap, ui32RegionId, &sCpuPAddr);
			if (eError != PVRSRV_OK)
			{
				/* We can only get here if there is a bug in this module */
				PVR_ASSERT(IMG_FALSE);
				return eError;
			}

			eError = PhysHeapRegionGetDevPAddr(psLMAHeap, ui32RegionId, &sDevPAddr);
			if (eError != PVRSRV_OK)
			{
				/* We can only get here if there is a bug in this module */
				PVR_ASSERT(IMG_FALSE);
				return eError;
			}

			PVR_DPF((PVR_DBG_MESSAGE,
					"Creating RA for card memory - region %d - 0x%016"
					IMG_UINT64_FMTSPECx"-0x%016" IMG_UINT64_FMTSPECx,
					 ui32RegionId, (IMG_UINT64) sCpuPAddr.uiAddr,
					 sCpuPAddr.uiAddr + ui64Size));

			psDeviceNode->apszRANames[ui32RegionId] =
				OSAllocMem(PVRSRV_MAX_RA_NAME_LENGTH);
			OSSNPrintf(psDeviceNode->apszRANames[ui32RegionId],
					   PVRSRV_MAX_RA_NAME_LENGTH,
					   "%s card mem",
					   psDevConfig->pszName);

			uBase = sDevPAddr.uiAddr;
			uSize = (RA_LENGTH_T) ui64Size;
			PVR_ASSERT(uSize == ui64Size);

			/* Use host page size, keeps things simple */
			psDeviceNode->apsLocalDevMemArenas[ui32RegionId] =
				RA_Create(psDeviceNode->apszRANames[ui32RegionId],
						  OSGetPageShift(), RA_LOCKCLASS_0, NULL, NULL, NULL,
						  IMG_FALSE);

			if (psDeviceNode->apsLocalDevMemArenas[ui32RegionId] == NULL)
			{
				PVR_DPF((PVR_DBG_ERROR, "%s: Failed to create LMA memory arena",
						 __func__));
				eError = PVRSRV_ERROR_OUT_OF_MEMORY;
				goto ErrorRAsDelete;
			}

			if (!RA_Add(psDeviceNode->apsLocalDevMemArenas[ui32RegionId],
						uBase, uSize, 0, NULL))
			{
				PVR_DPF((PVR_DBG_ERROR,
						 "%s: Failed to add memory to LMA memory arena",
						 __func__));
				eError = PVRSRV_ERROR_OUT_OF_MEMORY;
				goto ErrorRAsDelete;
			}
		}

#if defined(SUPPORT_GPUVIRT_VALIDATION)
		eError = CreateLMASubArenas(psDeviceNode);
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR,
					 "%s: Failed to create LMA memory sub-arenas", __func__));
			goto ErrorRAsDelete;
		}
#endif

		/* If additional psDeviceNode->pfnDevPx* callbacks are added,
		   update the corresponding virtualization-specific override
		   in pvrsrv_vz.c:PVRSRVVzDeviceCreate() */
		psDeviceNode->pfnDevPxAlloc = LMA_PhyContigPagesAlloc;
		psDeviceNode->pfnDevPxFree = LMA_PhyContigPagesFree;
		psDeviceNode->pfnDevPxMap = LMA_PhyContigPagesMap;
		psDeviceNode->pfnDevPxUnMap = LMA_PhyContigPagesUnmap;
		psDeviceNode->pfnDevPxClean = LMA_PhyContigPagesClean;
		psDeviceNode->pfnCreateRamBackedPMR[PVRSRV_DEVICE_PHYS_HEAP_GPU_LOCAL] = PhysmemNewLocalRamBackedPMR;
	}
	else
	{
		PVR_DPF((PVR_DBG_MESSAGE, "===== OS System memory only, no local card memory"));

		/* else we only have OS system memory */
		psDeviceNode->pfnDevPxAlloc = OSPhyContigPagesAlloc;
		psDeviceNode->pfnDevPxFree = OSPhyContigPagesFree;
		psDeviceNode->pfnDevPxMap = OSPhyContigPagesMap;
		psDeviceNode->pfnDevPxUnMap = OSPhyContigPagesUnmap;
		psDeviceNode->pfnDevPxClean = OSPhyContigPagesClean;
		psDeviceNode->pfnCreateRamBackedPMR[PVRSRV_DEVICE_PHYS_HEAP_GPU_LOCAL] = PhysmemNewOSRamBackedPMR;
	}

	if (PhysHeapGetType(psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_CPU_LOCAL]) == PHYS_HEAP_TYPE_LMA)
	{
		PVR_DPF((PVR_DBG_MESSAGE, "===== Local card memory only, no OS system memory"));
		psDeviceNode->pfnCreateRamBackedPMR[PVRSRV_DEVICE_PHYS_HEAP_CPU_LOCAL] = PhysmemNewLocalRamBackedPMR;
	}
	else
	{
		PVR_DPF((PVR_DBG_MESSAGE, "===== OS System memory, 2nd phys heap"));
		psDeviceNode->pfnCreateRamBackedPMR[PVRSRV_DEVICE_PHYS_HEAP_CPU_LOCAL] = PhysmemNewOSRamBackedPMR;
	}

	if (PhysHeapGetType(psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_FW_LOCAL]) == PHYS_HEAP_TYPE_LMA)
	{
		PVR_DPF((PVR_DBG_MESSAGE, "===== Local card memory only, no OS system memory"));
		psDeviceNode->pfnCreateRamBackedPMR[PVRSRV_DEVICE_PHYS_HEAP_FW_LOCAL] = PhysmemNewLocalRamBackedPMR;
	}
	else
	{
		PVR_DPF((PVR_DBG_MESSAGE, "===== OS System memory, 3rd phys heap"));
		psDeviceNode->pfnCreateRamBackedPMR[PVRSRV_DEVICE_PHYS_HEAP_FW_LOCAL] = PhysmemNewOSRamBackedPMR;
	}

	psDeviceNode->uiMMUPxLog2AllocGran = OSGetPageShift();

	eError = ServerSyncInit(psDeviceNode);
	if (eError != PVRSRV_OK)
	{
		goto ErrorRAsDelete;
	}

	eError = SyncCheckpointInit(psDeviceNode);
	PVR_LOG_IF_ERROR(eError, "SyncCheckpointInit");

	/* Perform additional vz initialization */
	eError = PVRSRVVzDeviceCreate(psDeviceNode);
	PVR_LOG_IF_ERROR(eError, "PVRSRVVzDeviceCreate");

	/*
	 * This is registered before doing device specific initialisation to ensure
	 * generic device information is dumped first during a debug request.
	 */
	eError = PVRSRVRegisterDbgRequestNotify(&psDeviceNode->hDbgReqNotify,
											psDeviceNode,
											_SysDebugRequestNotify,
											DEBUG_REQUEST_SYS,
											psDeviceNode);
	PVR_LOG_IF_ERROR(eError, "PVRSRVRegisterDbgRequestNotify");

	eError = HTBDeviceCreate(psDeviceNode);
	PVR_LOG_IF_ERROR(eError, "HTBDeviceCreate");

	psPVRSRVData->ui32RegisteredDevices++;

#if defined(SUPPORT_RGX)
	eError = RGXRegisterDevice(psDeviceNode);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed to register device", __func__));
		eError = PVRSRV_ERROR_DEVICE_REGISTER_FAILED;
		goto ErrorDecrementDeviceCount;
	}
#endif

#if defined(PVR_DVFS)
	eError = InitDVFS(psDeviceNode);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed to start DVFS", __func__));
#if defined(SUPPORT_RGX)
		DevDeInitRGX(psDeviceNode);
#endif
		goto ErrorDecrementDeviceCount;
	}
#endif

	OSAtomicWrite(&psDeviceNode->iNumClockSpeedChanges, 0);

#if defined(PVR_TESTING_UTILS)
	TUtilsInit(psDeviceNode);
#endif

	dllist_init(&psDeviceNode->sMemoryContextPageFaultNotifyListHead);

	PVR_DPF((PVR_DBG_MESSAGE, "Registered device %p", psDeviceNode));
	PVR_DPF((PVR_DBG_MESSAGE, "Register bank address = 0x%08lx",
			 (unsigned long)psDevConfig->sRegsCpuPBase.uiAddr));
	PVR_DPF((PVR_DBG_MESSAGE, "IRQ = %d", psDevConfig->ui32IRQ));

	/* Finally insert the device into the dev-list and set it as active */
	List_PVRSRV_DEVICE_NODE_InsertTail(&psPVRSRVData->psDeviceNodeList,
									   psDeviceNode);

	*ppsDeviceNode = psDeviceNode;

#if defined(PVRSRV_ENABLE_PROCESS_STATS) && !defined(PVRSRV_DEBUG_LINUX_MEMORY_STATS)
	/* Close the process statistics */
	PVRSRVStatsDeregisterProcess(hProcessStats);
#endif

	return PVRSRV_OK;

#if defined(SUPPORT_RGX) || defined(PVR_DVFS)
ErrorDecrementDeviceCount:
	psPVRSRVData->ui32RegisteredDevices--;

	if (psDeviceNode->hDbgReqNotify)
	{
		PVRSRVUnregisterDbgRequestNotify(psDeviceNode->hDbgReqNotify);
	}

	/* Perform vz deinitialization */
	PVRSRVVzDeviceDestroy(psDeviceNode);

	ServerSyncDeinit(psDeviceNode);
#endif
ErrorRAsDelete:
	{
		IMG_UINT32 ui32RegionId;

		for (ui32RegionId = 0;
			 ui32RegionId < psDeviceNode->ui32NumOfLocalMemArenas;
			 ui32RegionId++)
		{
			if (psDeviceNode->apsLocalDevMemArenas[ui32RegionId])
			{
				RA_Delete(psDeviceNode->apsLocalDevMemArenas[ui32RegionId]);
			}
		}
	}

ErrorPhysHeapsRelease:
	for (physHeapIndex = 0;
		 physHeapIndex < IMG_ARR_NUM_ELEMS(psDeviceNode->apsPhysHeap);
		 physHeapIndex++)
	{
		if (psDeviceNode->apsPhysHeap[physHeapIndex])
		{
			PhysHeapRelease(psDeviceNode->apsPhysHeap[physHeapIndex]);
		}
	}
ErrorPhysHeapsUnregister:
	for (i = 0; i < psDeviceNode->ui32RegisteredPhysHeaps; i++)
	{
		PhysHeapUnregister(psDeviceNode->papsRegisteredPhysHeaps[i]);
	}

	OSFreeMem(psDeviceNode->papsRegisteredPhysHeaps);
ErrorPowerLockDestroy:
	OSLockDestroy(psDeviceNode->hPowerLock);
ErrorUnregisterDbgTable:
	PVRSRVUnregisterDbgTable(psDeviceNode);
ErrorSysDevDeInit:
	psDevConfig->psDevNode = NULL;
	SysVzDevDeInit(psDevConfig);
	SysDevDeInit(psDevConfig);
ErrorDeregisterStats:
#if defined(PVRSRV_ENABLE_PROCESS_STATS) && !defined(PVRSRV_DEBUG_LINUX_MEMORY_STATS)
	/* Close the process statistics */
	PVRSRVStatsDeregisterProcess(hProcessStats);
ErrorFreeDeviceNode:
#endif
	OSFreeMemNoStats(psDeviceNode);

	return eError;
}

static PVRSRV_ERROR _SetDeviceFlag(const PVRSRV_DEVICE_NODE *psDevice,
                                  const void *psPrivate, IMG_BOOL bValue)
{
	PVRSRV_ERROR eResult = PVRSRV_OK;
	IMG_UINT32 ui32Flag = (IMG_UINT32)((uintptr_t)psPrivate);

	if (!ui32Flag)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	eResult = RGXSetDeviceFlags((PVRSRV_RGXDEV_INFO *)psDevice->pvDevice,
	                            ui32Flag, bValue);

	return eResult;
}

static PVRSRV_ERROR _ReadDeviceFlag(const PVRSRV_DEVICE_NODE *psDevice,
                                   const void *psPrivate, IMG_BOOL *pbValue)
{
	PVRSRV_ERROR eResult = PVRSRV_OK;
	IMG_UINT32 ui32Flag = (IMG_UINT32)((uintptr_t)psPrivate);
	IMG_UINT32 ui32State;

	if (!ui32Flag)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	eResult = RGXGetDeviceFlags((PVRSRV_RGXDEV_INFO *)psDevice->pvDevice,
	                            &ui32State);

	if (PVRSRV_OK == eResult)
	{
		*pbValue = (ui32State & ui32Flag)? IMG_TRUE: IMG_FALSE;
	}

	return eResult;
}
static PVRSRV_ERROR _SetStateFlag(const PVRSRV_DEVICE_NODE *psDevice,
                                  const void *psPrivate, IMG_BOOL bValue)
{
	PVRSRV_ERROR eResult = PVRSRV_OK;
	IMG_UINT32 ui32Flag = (IMG_UINT32)((uintptr_t)psPrivate);

	if (!ui32Flag)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	/* EnableHWR is a special case
	 * only possible to disable after FW is running
	 */
	if (bValue && RGXFWIF_INICFG_HWR_EN == ui32Flag)
	{
		return PVRSRV_ERROR_NOT_SUPPORTED;
	}

	eResult = RGXStateFlagCtrl((PVRSRV_RGXDEV_INFO *)psDevice->pvDevice,
	                           ui32Flag, NULL, bValue);

	return eResult;
}

static PVRSRV_ERROR _ReadStateFlag(const PVRSRV_DEVICE_NODE *psDevice,
                                   const void *psPrivate, IMG_BOOL *pbValue)
{
	IMG_UINT32 ui32Flag = (IMG_UINT32)((uintptr_t)psPrivate);
	IMG_UINT32 ui32State;
	PVRSRV_RGXDEV_INFO *psDevInfo = (PVRSRV_RGXDEV_INFO *)psDevice->pvDevice;

	if (!ui32Flag)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	ui32State = psDevInfo->psFWIfOSConfig->ui32ConfigFlags;

	if(pbValue)
	{
		*pbValue = (ui32State & ui32Flag)? IMG_TRUE: IMG_FALSE;
	}

	return PVRSRV_OK;
}

PVRSRV_ERROR PVRSRVDeviceInitialise(PVRSRV_DEVICE_NODE *psDeviceNode)
{
	IMG_BOOL bInitSuccesful = IMG_FALSE;
#if defined(PVRSRV_ENABLE_PROCESS_STATS) && !defined(PVRSRV_DEBUG_LINUX_MEMORY_STATS)
	IMG_HANDLE hProcessStats;
#endif
	PVRSRV_ERROR eError;

	if (psDeviceNode->eDevState != PVRSRV_DEVICE_STATE_INIT)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Device already initialised", __func__));
		return PVRSRV_ERROR_INIT_FAILURE;
	}

	/* Allocate process statistics */
#if defined(PVRSRV_ENABLE_PROCESS_STATS) && !defined(PVRSRV_DEBUG_LINUX_MEMORY_STATS)
	eError = PVRSRVStatsRegisterProcess(&hProcessStats);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
			 "%s: Couldn't register process statistics (%d)",
			 __func__, eError));
		return eError;
	}
#endif

#if defined(SUPPORT_RGX)
	eError = RGXInit(psDeviceNode);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
				 "%s: Initialisation of Rogue device failed (%s)",
				 __func__, PVRSRVGetErrorStringKM(eError)));
		goto Exit;
	}
#endif

	bInitSuccesful = IMG_TRUE;

#if defined(SUPPORT_RGX)
Exit:
#endif
	eError = PVRSRVDeviceFinalise(psDeviceNode, bInitSuccesful);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
				 "%s: Services failed to finalise the device (%s)",
				 __func__, PVRSRVGetErrorStringKM(eError)));
	}


	PVRSRVAppHintRegisterHandlersBOOL(APPHINT_ID_DisableClockGating,
	                                  _ReadStateFlag, _SetStateFlag,
	                                  psDeviceNode,
	                                  (void*)((uintptr_t)RGXFWIF_INICFG_DISABLE_CLKGATING_EN));
	PVRSRVAppHintRegisterHandlersBOOL(APPHINT_ID_DisableDMOverlap,
	                                  _ReadStateFlag, _SetStateFlag,
	                                  psDeviceNode,
	                                  (void*)((uintptr_t)RGXFWIF_INICFG_DISABLE_DM_OVERLAP));
	PVRSRVAppHintRegisterHandlersBOOL(APPHINT_ID_AssertOnHWRTrigger,
	                                  _ReadStateFlag, _SetStateFlag,
	                                  psDeviceNode,
	                                  (void*)((uintptr_t)RGXFWIF_INICFG_ASSERT_ON_HWR_TRIGGER));
	PVRSRVAppHintRegisterHandlersBOOL(APPHINT_ID_AssertOutOfMemory,
	                                  _ReadStateFlag, _SetStateFlag,
	                                  psDeviceNode,
	                                  (void*)((uintptr_t)RGXFWIF_INICFG_ASSERT_ON_OUTOFMEMORY));
	PVRSRVAppHintRegisterHandlersBOOL(APPHINT_ID_CheckMList,
	                                  _ReadStateFlag, _SetStateFlag,
	                                  psDeviceNode,
	                                  (void*)((uintptr_t)RGXFWIF_INICFG_CHECK_MLIST_EN));
	PVRSRVAppHintRegisterHandlersBOOL(APPHINT_ID_EnableHWR,
	                                  _ReadStateFlag, _SetStateFlag,
	                                  psDeviceNode,
	                                  (void*)((uintptr_t)RGXFWIF_INICFG_HWR_EN));

	PVRSRVAppHintRegisterHandlersBOOL(APPHINT_ID_DisableFEDLogging,
	                                  _ReadDeviceFlag, _SetDeviceFlag,
	                                  psDeviceNode,
	                                  (void*)((uintptr_t)RGXKMIF_DEVICE_STATE_DISABLE_DW_LOGGING_EN));
	PVRSRVAppHintRegisterHandlersBOOL(APPHINT_ID_ZeroFreelist,
	                                  _ReadDeviceFlag, _SetDeviceFlag,
	                                  psDeviceNode,
	                                  (void*)((uintptr_t)RGXKMIF_DEVICE_STATE_ZERO_FREELIST));
	PVRSRVAppHintRegisterHandlersBOOL(APPHINT_ID_DustRequestInject,
	                                  _ReadDeviceFlag, _SetDeviceFlag,
	                                  psDeviceNode,
	                                  (void*)((uintptr_t)RGXKMIF_DEVICE_STATE_DUST_REQUEST_INJECT_EN));

	PVRSRVAppHintRegisterHandlersBOOL(APPHINT_ID_DisablePDumpPanic,
	                                  RGXQueryPdumpPanicEnable, RGXSetPdumpPanicEnable,
	                                  psDeviceNode,
	                                  NULL);

#if defined(PVRSRV_ENABLE_PROCESS_STATS) && !defined(PVRSRV_DEBUG_LINUX_MEMORY_STATS)
	/* Close the process statistics */
	PVRSRVStatsDeregisterProcess(hProcessStats);
#endif

	return eError;
}

PVRSRV_ERROR IMG_CALLCONV PVRSRVDeviceDestroy(PVRSRV_DEVICE_NODE *psDeviceNode)
{
	PVRSRV_DATA				*psPVRSRVData = PVRSRVGetPVRSRVData();
	PVRSRV_DEVICE_PHYS_HEAP ePhysHeapIdx;
	IMG_UINT32 				ui32RegionIdx;
	IMG_UINT32				i;
	PVRSRV_ERROR			eError;
#if defined(PVRSRV_FORCE_UNLOAD_IF_BAD_STATE)
	IMG_BOOL				bForceUnload = IMG_FALSE;

	if (PVRSRVGetPVRSRVData()->eServicesState != PVRSRV_SERVICES_STATE_OK)
	{
		bForceUnload = IMG_TRUE;
	}
#endif

	psPVRSRVData->ui32RegisteredDevices--;

	psDeviceNode->eDevState = PVRSRV_DEVICE_STATE_DEINIT;

#if defined(PVR_TESTING_UTILS)
	TUtilsDeinit(psDeviceNode);
#endif
#if defined(SUPPORT_FALLBACK_FENCE_SYNC)
	SyncFbDeregisterDevice(psDeviceNode);
#endif
	/* Counter part to what gets done in PVRSRVDeviceFinalise */
	if (psDeviceNode->hSyncCheckpointContext)
	{
		SyncCheckpointContextDestroy(psDeviceNode->hSyncCheckpointContext);
		psDeviceNode->hSyncCheckpointContext = NULL;
	}
	if (psDeviceNode->hSyncPrimContext)
	{
		if (psDeviceNode->psSyncPrim)
		{
			/* Free general pupose sync primitive */
			SyncPrimFree(psDeviceNode->psSyncPrim);
			psDeviceNode->psSyncPrim = NULL;
		}

		if (psDeviceNode->psMMUCacheSyncPrim)
		{
			PVRSRV_CLIENT_SYNC_PRIM *psSync = psDeviceNode->psMMUCacheSyncPrim;

			/* Important to set the device node pointer to NULL
			 * before we free the sync-prim to make sure we don't
			 * defer the freeing of the sync-prim's page tables itself.
			 * The sync is used to defer the MMU page table
			 * freeing. */
			psDeviceNode->psMMUCacheSyncPrim = NULL;

			/* Free general pupose sync primitive */
			SyncPrimFree(psSync);

		}

		SyncPrimContextDestroy(psDeviceNode->hSyncPrimContext);
		psDeviceNode->hSyncPrimContext = NULL;
	}

	eError = PVRSRVPowerLock(psDeviceNode);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed to acquire power lock", __func__));
		return eError;
	}

	LOOP_UNTIL_TIMEOUT(MAX_HW_TIME_US)
	{
#if defined(PVRSRV_FORCE_UNLOAD_IF_BAD_STATE)
		if (bForceUnload)
		{
			/*
			 * Firmware probably not responding but we still want to unload the
			 * driver.
			 */
			break;
		}
#endif
		/* Force idle device */
		eError = PVRSRVDeviceIdleRequestKM(psDeviceNode, NULL, IMG_TRUE);
		if (eError == PVRSRV_OK)
		{
			break;
		}
		else if (eError == PVRSRV_ERROR_DEVICE_IDLE_REQUEST_DENIED)
		{
			PVRSRV_ERROR eError2;

			PVRSRVPowerUnlock(psDeviceNode);

			OSWaitus(MAX_HW_TIME_US/WAIT_TRY_COUNT);

			eError2 = PVRSRVPowerLock(psDeviceNode);
			if (eError2 != PVRSRV_OK)
			{
				PVR_DPF((PVR_DBG_ERROR, "%s: Failed to acquire power lock",
						 __func__));
				return eError2;
			}
		}
		else
		{
			PVRSRVPowerUnlock(psDeviceNode);
			return eError;
		}
	} END_LOOP_UNTIL_TIMEOUT();

	if (eError == PVRSRV_ERROR_DEVICE_IDLE_REQUEST_DENIED)
	{
		PVR_DPF((PVR_DBG_ERROR, "%s: Forced idle DENIED", __func__));
		PVRSRVPowerUnlock(psDeviceNode);
		return eError;
	}

	/* Power down the device if necessary */
	eError = PVRSRVSetDevicePowerStateKM(psDeviceNode,
										 PVRSRV_DEV_POWER_STATE_OFF,
										 IMG_TRUE);
	PVRSRVPowerUnlock(psDeviceNode);

	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,
				 "%s: Failed PVRSRVSetDevicePowerStateKM call (%s). Dump debug.",
				 __func__, PVRSRVGetErrorStringKM(eError)));

		PVRSRVDebugRequest(psDeviceNode, DEBUG_REQUEST_VERBOSITY_MAX, NULL, NULL);

		/*
		 * If the driver is okay then return the error, otherwise we can ignore
		 * this error.
		 */
		if (PVRSRVGetPVRSRVData()->eServicesState == PVRSRV_SERVICES_STATE_OK)
		{
			return eError;
		}
		else
		{
			PVR_DPF((PVR_DBG_MESSAGE,
					 "%s: Will continue to unregister as driver status is not OK",
					 __func__));
		}
	}

#if defined(SUPPORT_RGX)
	DevDeInitRGX(psDeviceNode);
#endif

	HTBDeviceDestroy(psDeviceNode);

	if (psDeviceNode->hDbgReqNotify)
	{
		PVRSRVUnregisterDbgRequestNotify(psDeviceNode->hDbgReqNotify);
	}

	SyncCheckpointDeinit(psDeviceNode);

	ServerSyncDeinit(psDeviceNode);

	/* Remove RAs and RA names for local card memory */
	for (ui32RegionIdx = 0;
		 ui32RegionIdx < psDeviceNode->ui32NumOfLocalMemArenas;
		 ui32RegionIdx++)
	{
		if (psDeviceNode->apsLocalDevMemArenas[ui32RegionIdx])
		{
			RA_Delete(psDeviceNode->apsLocalDevMemArenas[ui32RegionIdx]);
			psDeviceNode->apsLocalDevMemArenas[ui32RegionIdx] = NULL;
		}

		if (psDeviceNode->apszRANames[ui32RegionIdx])
		{
			OSFreeMem(psDeviceNode->apszRANames[ui32RegionIdx]);
			psDeviceNode->apszRANames[ui32RegionIdx] = NULL;
		}
	}

	if (psDeviceNode->apsLocalDevMemArenas)
	{
		OSFreeMem(psDeviceNode->apsLocalDevMemArenas);
		psDeviceNode->apsLocalDevMemArenas = NULL;
	}
	if (psDeviceNode->apszRANames)
	{
		OSFreeMem(psDeviceNode->apszRANames);
		psDeviceNode->apszRANames = NULL;
	}

	/* Perform vz deinitialization */
	PVRSRVVzDeviceDestroy(psDeviceNode);

	List_PVRSRV_DEVICE_NODE_Remove(psDeviceNode);

	for (ePhysHeapIdx = 0;
		 ePhysHeapIdx < IMG_ARR_NUM_ELEMS(psDeviceNode->apsPhysHeap);
		 ePhysHeapIdx++)
	{
		if (psDeviceNode->apsPhysHeap[ePhysHeapIdx])
		{
			PhysHeapRelease(psDeviceNode->apsPhysHeap[ePhysHeapIdx]);
		}
	}

	for (i = 0; i < psDeviceNode->ui32RegisteredPhysHeaps; i++)
	{
		PhysHeapUnregister(psDeviceNode->papsRegisteredPhysHeaps[i]);
	}

	OSFreeMem(psDeviceNode->papsRegisteredPhysHeaps);

#if defined(PVR_DVFS)
	DeinitDVFS(psDeviceNode);
#endif

	OSLockDestroy(psDeviceNode->hPowerLock);

	PVRSRVUnregisterDbgTable(psDeviceNode);

	psDeviceNode->psDevConfig->psDevNode = NULL;
	SysVzDevDeInit(psDeviceNode->psDevConfig);
	SysDevDeInit(psDeviceNode->psDevConfig);

	OSFreeMemNoStats(psDeviceNode);

	return PVRSRV_OK;
}

PVRSRV_ERROR LMA_PhyContigPagesAlloc(PVRSRV_DEVICE_NODE *psDevNode, size_t uiSize,
							PG_HANDLE *psMemHandle, IMG_DEV_PHYADDR *psDevPAddr)
{
#if defined(SUPPORT_GPUVIRT_VALIDATION)
	IMG_UINT32  ui32OSid = 0;
#endif
	RA_BASE_T uiCardAddr;
	RA_LENGTH_T uiActualSize;
	PVRSRV_ERROR eError;

	RA_ARENA *pArena=psDevNode->apsLocalDevMemArenas[0];
	IMG_UINT32 ui32Log2NumPages = 0;

	PVR_ASSERT(uiSize != 0);
	ui32Log2NumPages = OSGetOrder(uiSize);
	uiSize = (1 << ui32Log2NumPages) * OSGetPageSize();

#if defined(SUPPORT_GPUVIRT_VALIDATION)
{
	IMG_UINT32  ui32OSidReg = 0;
	IMG_BOOL    bOSidAxiProt;

	IMG_PID     pId = OSGetCurrentClientProcessIDKM();

	RetrieveOSidsfromPidList(pId, &ui32OSid, &ui32OSidReg, &bOSidAxiProt);

	pArena = psDevNode->psOSidSubArena[ui32OSid];
}
#endif

	eError = RA_Alloc(pArena,
	                  uiSize,
	                  RA_NO_IMPORT_MULTIPLIER,
	                  0,                         /* No flags */
	                  uiSize,
	                  "LMA_PhyContigPagesAlloc",
	                  &uiCardAddr,
	                  &uiActualSize,
	                  NULL);                     /* No private handle */

	PVR_ASSERT(uiSize == uiActualSize);

#if defined(SUPPORT_GPUVIRT_VALIDATION)
{
	PVR_DPF((PVR_DBG_MESSAGE,"(GPU Virtualization Validation): LMA_PhyContigPagesAlloc: Address:%llu, size:%llu", uiCardAddr,uiActualSize));
}
#endif

	psMemHandle->u.ui64Handle = uiCardAddr;
	psDevPAddr->uiAddr = (IMG_UINT64) uiCardAddr;

	if (PVRSRV_OK == eError)
	{
#if defined(PVRSRV_ENABLE_PROCESS_STATS)
#if !defined(PVRSRV_ENABLE_MEMORY_STATS)
	    PVRSRVStatsIncrMemAllocStatAndTrack(PVRSRV_MEM_ALLOC_TYPE_ALLOC_PAGES_PT_LMA,
	                                        uiSize,
	                                        (IMG_UINT64)(uintptr_t) psMemHandle,
		                                    OSGetCurrentClientProcessIDKM());
#else
		IMG_CPU_PHYADDR sCpuPAddr;
		sCpuPAddr.uiAddr = psDevPAddr->uiAddr;

		PVRSRVStatsAddMemAllocRecord(PVRSRV_MEM_ALLOC_TYPE_ALLOC_PAGES_PT_LMA,
		                             NULL,
		                             sCpuPAddr,
		                             uiSize,
		                             NULL,
		                             OSGetCurrentClientProcessIDKM());
#endif
#endif
		psMemHandle->ui32Order = ui32Log2NumPages;
	}

	return eError;
}

void LMA_PhyContigPagesFree(PVRSRV_DEVICE_NODE *psDevNode, PG_HANDLE *psMemHandle)
{
	RA_BASE_T uiCardAddr = (RA_BASE_T) psMemHandle->u.ui64Handle;

#if defined(PVRSRV_ENABLE_PROCESS_STATS)
#if !defined(PVRSRV_ENABLE_MEMORY_STATS)
	PVRSRVStatsDecrMemAllocStatAndUntrack(PVRSRV_MEM_ALLOC_TYPE_ALLOC_PAGES_PT_LMA,
	                                      (IMG_UINT64)(uintptr_t) psMemHandle);
#else
		PVRSRVStatsRemoveMemAllocRecord(PVRSRV_MEM_ALLOC_TYPE_ALLOC_PAGES_PT_LMA,
		                                (IMG_UINT64)uiCardAddr,
		                                OSGetCurrentClientProcessIDKM());
#endif
#endif
	RA_Free(psDevNode->apsLocalDevMemArenas[0], uiCardAddr);
	psMemHandle->ui32Order = 0;
}

PVRSRV_ERROR LMA_PhyContigPagesMap(PVRSRV_DEVICE_NODE *psDevNode, PG_HANDLE *psMemHandle,
							size_t uiSize, IMG_DEV_PHYADDR *psDevPAddr,
							void **pvPtr)
{
	IMG_CPU_PHYADDR sCpuPAddr;
	IMG_UINT32 ui32NumPages = (1 << psMemHandle->ui32Order);
	PVR_UNREFERENCED_PARAMETER(psMemHandle);
	PVR_UNREFERENCED_PARAMETER(uiSize);

	PhysHeapDevPAddrToCpuPAddr(psDevNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_GPU_LOCAL], 1, &sCpuPAddr, psDevPAddr);
#ifdef CONFIG_MCST
	*pvPtr = OSMapPhysToLin(sCpuPAddr, *psDevPAddr,
							ui32NumPages * OSGetPageSize(),
							PVRSRV_MEMALLOCFLAG_CPU_WRITE_COMBINE);
#else
	*pvPtr = OSMapPhysToLin(sCpuPAddr,
							ui32NumPages * OSGetPageSize(),
							PVRSRV_MEMALLOCFLAG_CPU_WRITE_COMBINE);
#endif
	if (*pvPtr == NULL)
	{
		return PVRSRV_ERROR_OUT_OF_MEMORY;
	}
	else
	{
#if defined(PVRSRV_ENABLE_PROCESS_STATS)
#if !defined(PVRSRV_ENABLE_MEMORY_STATS)
		PVRSRVStatsIncrMemAllocStat(PVRSRV_MEM_ALLOC_TYPE_IOREMAP_PT_LMA,
		                            ui32NumPages * OSGetPageSize(),
		                            OSGetCurrentClientProcessIDKM());
#else
		{
			PVRSRVStatsAddMemAllocRecord(PVRSRV_MEM_ALLOC_TYPE_IOREMAP_PT_LMA,
										 *pvPtr,
										 sCpuPAddr,
										 ui32NumPages * OSGetPageSize(),
										 NULL,
										 OSGetCurrentClientProcessIDKM());
		}
#endif
#endif
		return PVRSRV_OK;
	}
}

void LMA_PhyContigPagesUnmap(PVRSRV_DEVICE_NODE *psDevNode, PG_HANDLE *psMemHandle,
						void *pvPtr)
{
	IMG_UINT32 ui32NumPages = (1 << psMemHandle->ui32Order);
	PVR_UNREFERENCED_PARAMETER(psMemHandle);
	PVR_UNREFERENCED_PARAMETER(psDevNode);

#if defined(PVRSRV_ENABLE_PROCESS_STATS)
#if !defined(PVRSRV_ENABLE_MEMORY_STATS)
		PVRSRVStatsDecrMemAllocStat(PVRSRV_MEM_ALLOC_TYPE_IOREMAP_PT_LMA,
		                            ui32NumPages * OSGetPageSize(),
		                            OSGetCurrentClientProcessIDKM());
#else
	PVRSRVStatsRemoveMemAllocRecord(PVRSRV_MEM_ALLOC_TYPE_IOREMAP_PT_LMA,
	                                (IMG_UINT64)(uintptr_t)pvPtr,
	                                OSGetCurrentClientProcessIDKM());
#endif
#endif

	OSUnMapPhysToLin(pvPtr, ui32NumPages * OSGetPageSize(),
					 PVRSRV_MEMALLOCFLAG_CPU_UNCACHED);
}

PVRSRV_ERROR LMA_PhyContigPagesClean(PVRSRV_DEVICE_NODE *psDevNode,
                                     PG_HANDLE *psMemHandle,
                                     IMG_UINT32 uiOffset,
                                     IMG_UINT32 uiLength)
{
	/* No need to flush because we map as uncached */
	PVR_UNREFERENCED_PARAMETER(psDevNode);
	PVR_UNREFERENCED_PARAMETER(psMemHandle);
	PVR_UNREFERENCED_PARAMETER(uiOffset);
	PVR_UNREFERENCED_PARAMETER(uiLength);

	return PVRSRV_OK;
}

/**************************************************************************/ /*!
@Function     PVRSRVDeviceFinalise
@Description  Performs the final parts of device initialisation.
@Input        psDeviceNode            Device node of the device to finish
                                      initialising
@Input        bInitSuccessful         Whether or not device specific
                                      initialisation was successful
@Return       PVRSRV_ERROR     PVRSRV_OK on success and an error otherwise
*/ /***************************************************************************/
PVRSRV_ERROR IMG_CALLCONV PVRSRVDeviceFinalise(PVRSRV_DEVICE_NODE *psDeviceNode,
											   IMG_BOOL bInitSuccessful)
{
	PVRSRV_ERROR eError;

	if (bInitSuccessful)
	{
#if defined(PVRSRV_USE_SYNC_CHECKPOINTS)
		eError = SyncCheckpointContextCreate(psDeviceNode,
											 &psDeviceNode->hSyncCheckpointContext);
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR,
					 "%s: Failed to create sync checkpoint context (%s)",
					 __func__, PVRSRVGetErrorStringKM(eError)));

			goto ErrorExit;
		}
#endif
#if defined(SUPPORT_FALLBACK_FENCE_SYNC)
		eError = SyncFbRegisterDevice(psDeviceNode);
		if (eError != PVRSRV_OK)
		{
			goto ErrorExit;
		}
#endif
		eError = SyncPrimContextCreate(psDeviceNode,
									   &psDeviceNode->hSyncPrimContext);
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR,
					 "%s: Failed to create sync prim context (%s)",
					 __func__, PVRSRVGetErrorStringKM(eError)));
			SyncCheckpointContextDestroy(psDeviceNode->hSyncCheckpointContext);
			goto ErrorExit;
		}

		/* Allocate general purpose sync primitive */
		eError = SyncPrimAlloc(psDeviceNode->hSyncPrimContext,
							   &psDeviceNode->psSyncPrim,
							   "pvrsrv dev general");
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR,
					 "%s: Failed to allocate sync primitive with error (%s)",
					 __func__, PVRSRVGetErrorStringKM(eError)));
			goto ErrorExit;
		}

		/* Allocate MMU cache invalidate sync */
		eError = SyncPrimAlloc(psDeviceNode->hSyncPrimContext,
							   &psDeviceNode->psMMUCacheSyncPrim,
							   "pvrsrv dev MMU cache");
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR,
					 "%s: Failed to allocate sync primitive with error (%s)",
					 __func__, PVRSRVGetErrorStringKM(eError)));
			goto ErrorExit;
		}

		/* Next update value will be 1 since sync prim starts with 0 */
		psDeviceNode->ui16NextMMUInvalidateUpdate = 1;

		eError = PVRSRVPowerLock(psDeviceNode);
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR, "%s: Failed to acquire power lock (%s)",
					 __func__, PVRSRVGetErrorStringKM(eError)));
			goto ErrorExit;
		}

		/*
		 * Always ensure a single power on command appears in the pdump. This
		 * should be the only power related call outside of PDUMPPOWCMDSTART
		 * and PDUMPPOWCMDEND.
		 */
		eError = PVRSRVSetDevicePowerStateKM(psDeviceNode,
											 PVRSRV_DEV_POWER_STATE_ON, IMG_TRUE);
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR,
					 "%s: Failed to set device %p power state to 'on' (%s)",
					 __func__, psDeviceNode, PVRSRVGetErrorStringKM(eError)));
			PVRSRVPowerUnlock(psDeviceNode);
			goto ErrorExit;
		}

		/* Verify firmware compatibility for device */
		eError = PVRSRVDevInitCompatCheck(psDeviceNode);
		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR,
					 "%s: Failed compatibility check for device %p (%s)",
					 __func__, psDeviceNode, PVRSRVGetErrorStringKM(eError)));
			PVRSRVPowerUnlock(psDeviceNode);
			PVRSRVDebugRequest(psDeviceNode, DEBUG_REQUEST_VERBOSITY_MAX, NULL, NULL);
			goto ErrorExit;
		}

		PDUMPPOWCMDSTART();
		LOOP_UNTIL_TIMEOUT(MAX_HW_TIME_US)
		{
			/* Force the device to idle if its default power state is off */
			eError = PVRSRVDeviceIdleRequestKM(psDeviceNode,
											   &PVRSRVDeviceIsDefaultStateOFF,
											   IMG_TRUE);
			if (eError == PVRSRV_OK)
			{
				break;
			}
			else if (eError == PVRSRV_ERROR_DEVICE_IDLE_REQUEST_DENIED)
			{
				PVRSRVPowerUnlock(psDeviceNode);
				OSWaitus(MAX_HW_TIME_US/WAIT_TRY_COUNT);

				eError = PVRSRVPowerLock(psDeviceNode);
				if (eError != PVRSRV_OK)
				{
					PVR_DPF((PVR_DBG_ERROR,
							 "%s: Failed to acquire power lock (%s)",
							 __func__, PVRSRVGetErrorStringKM(eError)));
					goto ErrorExit;
				}
			}
			else
			{
				PVR_DPF((PVR_DBG_ERROR, "%s: Failed to idle device %p (%s)",
						 __func__, psDeviceNode,
						 PVRSRVGetErrorStringKM(eError)));
				PVRSRVPowerUnlock(psDeviceNode);
				goto ErrorExit;
			}
		} END_LOOP_UNTIL_TIMEOUT();

		if (eError == PVRSRV_ERROR_DEVICE_IDLE_REQUEST_DENIED)
		{
			PVR_DPF((PVR_DBG_ERROR, "%s: Forced idle DENIED", __func__));
			PVRSRVPowerUnlock(psDeviceNode);
			goto ErrorExit;
		}

		/* Place device into its default power state. */
		eError = PVRSRVSetDevicePowerStateKM(psDeviceNode,
											 PVRSRV_DEV_POWER_STATE_DEFAULT,
											 IMG_TRUE);
		PDUMPPOWCMDEND();

		if (eError != PVRSRV_OK)
		{
			PVR_DPF((PVR_DBG_ERROR,
					 "%s: Failed to set device %p into its default power state (%s)",
					 __func__, psDeviceNode, PVRSRVGetErrorStringKM(eError)));

			PVRSRVPowerUnlock(psDeviceNode);
			goto ErrorExit;
		}

		PVRSRVPowerUnlock(psDeviceNode);

		/*
		 * If PDUMP is enabled and RGX device is supported, then initialise the
		 * performance counters that can be further modified in PDUMP. Then,
		 * before ending the init phase of the pdump, drain the commands put in
		 * the kCCB during the init phase.
		 */
#if defined(SUPPORT_RGX) && defined(PDUMP)
		{
			PVRSRV_RGXDEV_INFO *psDevInfo =
				(PVRSRV_RGXDEV_INFO *)(psDeviceNode->pvDevice);

			eError = PVRSRVRGXInitHWPerfCountersKM(psDeviceNode);
			if (eError != PVRSRV_OK)
			{
				PVR_DPF((PVR_DBG_ERROR,
						 "%s: Failed to init hwperf counters (%s)",
						 __func__, PVRSRVGetErrorStringKM(eError)));
				goto ErrorExit;
			}

			eError = RGXPdumpDrainKCCB(psDevInfo,
									   psDevInfo->psKernelCCBCtl->ui32WriteOffset);
			if (eError != PVRSRV_OK)
			{
				PVR_DPF((PVR_DBG_ERROR, "%s: Problem draining kCCB (%s)",
						 __func__, PVRSRVGetErrorStringKM(eError)));
				goto ErrorExit;
			}
		}
#endif

		/* Now that the device(s) are fully initialised set them as active */
		psDeviceNode->eDevState = PVRSRV_DEVICE_STATE_ACTIVE;
		eError = PVRSRV_OK;

#if defined(SUPPORT_RGX)
		if (PVRSRV_VZ_MODE_IS(DRIVER_MODE_GUEST))
		{
			eError = RGXFWOSConfig((PVRSRV_RGXDEV_INFO *)(psDeviceNode->pvDevice));
			if (eError != PVRSRV_OK)
			{
				PVR_DPF((PVR_DBG_ERROR, "%s: Cannot kick initialization configuration to the Device (%s)",
						 __func__, PVRSRVGetErrorStringKM(eError)));

				goto ErrorExit;
			}
		}
#endif
	}
	else
	{
		/* Initialisation failed so set the device(s) into a bad state */
		psDeviceNode->eDevState = PVRSRV_DEVICE_STATE_BAD;
		eError = PVRSRV_ERROR_NOT_INITIALISED;
	}

	/* Give PDump control a chance to end the init phase, depends on OS */
	PDumpStopInitPhase(IMG_FALSE, IMG_TRUE);

	return eError;

ErrorExit:
	/* Initialisation failed so set the device(s) into a bad state */
	psDeviceNode->eDevState = PVRSRV_DEVICE_STATE_BAD;

	return eError;
}

PVRSRV_ERROR IMG_CALLCONV PVRSRVDevInitCompatCheck(PVRSRV_DEVICE_NODE *psDeviceNode)
{
	/* Only check devices which specify a compatibility check callback */
	if (psDeviceNode->pfnInitDeviceCompatCheck)
		return psDeviceNode->pfnInitDeviceCompatCheck(psDeviceNode);
	else
		return PVRSRV_OK;
}

/*
	PollForValueKM
*/
static
PVRSRV_ERROR IMG_CALLCONV PollForValueKM (volatile IMG_UINT32*	pui32LinMemAddr,
										  IMG_UINT32			ui32Value,
										  IMG_UINT32			ui32Mask,
										  IMG_UINT32			ui32Timeoutus,
										  IMG_UINT32			ui32PollPeriodus,
										  IMG_BOOL				bAllowPreemption)
{
#if defined(NO_HARDWARE)
	PVR_UNREFERENCED_PARAMETER(pui32LinMemAddr);
	PVR_UNREFERENCED_PARAMETER(ui32Value);
	PVR_UNREFERENCED_PARAMETER(ui32Mask);
	PVR_UNREFERENCED_PARAMETER(ui32Timeoutus);
	PVR_UNREFERENCED_PARAMETER(ui32PollPeriodus);
	PVR_UNREFERENCED_PARAMETER(bAllowPreemption);
	return PVRSRV_OK;
#else
	IMG_UINT32	ui32ActualValue = 0xFFFFFFFFU; /* Initialiser only required to prevent incorrect warning */

	if (bAllowPreemption)
	{
		PVR_ASSERT(ui32PollPeriodus >= 1000);
	}

	LOOP_UNTIL_TIMEOUT(ui32Timeoutus)
	{
		ui32ActualValue = OSReadHWReg32((void *)pui32LinMemAddr, 0) & ui32Mask;

		if (ui32ActualValue == ui32Value)
		{
			return PVRSRV_OK;
		}

		if (gpsPVRSRVData->eServicesState != PVRSRV_SERVICES_STATE_OK)
		{
			return PVRSRV_ERROR_TIMEOUT;
		}

		if (bAllowPreemption)
		{
			OSSleepms(ui32PollPeriodus / 1000);
		}
		else
		{
			OSWaitus(ui32PollPeriodus);
		}
	} END_LOOP_UNTIL_TIMEOUT();

	PVR_DPF((PVR_DBG_ERROR,"PollForValueKM: Timeout. Expected 0x%x but found 0x%x (mask 0x%x).",
			ui32Value, ui32ActualValue, ui32Mask));
	
	return PVRSRV_ERROR_TIMEOUT;
#endif /* NO_HARDWARE */
}


/*
	PVRSRVPollForValueKM
*/
IMG_EXPORT
PVRSRV_ERROR IMG_CALLCONV PVRSRVPollForValueKM (volatile IMG_UINT32	*pui32LinMemAddr,
												IMG_UINT32			ui32Value,
												IMG_UINT32			ui32Mask)
{
	return PollForValueKM(pui32LinMemAddr, ui32Value, ui32Mask,
						  MAX_HW_TIME_US,
						  MAX_HW_TIME_US/WAIT_TRY_COUNT,
						  IMG_FALSE);
}

static
PVRSRV_ERROR IMG_CALLCONV WaitForValueKM(volatile IMG_UINT32  *pui32LinMemAddr,
                                         IMG_UINT32           ui32Value,
                                         IMG_UINT32           ui32Mask,
                                         IMG_BOOL             bHoldBridgeLock)
{
#if defined(NO_HARDWARE)
	PVR_UNREFERENCED_PARAMETER(pui32LinMemAddr);
	PVR_UNREFERENCED_PARAMETER(ui32Value);
	PVR_UNREFERENCED_PARAMETER(ui32Mask);
	return PVRSRV_OK;
#else

	PVRSRV_DATA *psPVRSRVData = PVRSRVGetPVRSRVData();
	IMG_HANDLE hOSEvent;
	PVRSRV_ERROR eError;
	PVRSRV_ERROR eErrorWait;
	IMG_UINT32 ui32ActualValue;

	eError = OSEventObjectOpen(psPVRSRVData->hGlobalEventObject, &hOSEvent);
	if (eError != PVRSRV_OK)
	{
		PVR_DPF((PVR_DBG_ERROR,"PVRSRVWaitForValueKM: Failed to setup EventObject with error (%d)", eError));
		goto EventObjectOpenError;
	}

	eError = PVRSRV_ERROR_TIMEOUT;
	
	LOOP_UNTIL_TIMEOUT(MAX_HW_TIME_US)
	{
		ui32ActualValue = (*pui32LinMemAddr & ui32Mask);

		if (ui32ActualValue == ui32Value)
		{
			/* Expected value has been found */
			eError = PVRSRV_OK;
			break;
		}
		else if (psPVRSRVData->eServicesState != PVRSRV_SERVICES_STATE_OK)
		{
			/* Services in bad state, don't wait any more */
			eError = PVRSRV_ERROR_NOT_READY;
			break;
		}
		else
		{
			/* wait for event and retry */
			eErrorWait = bHoldBridgeLock ? OSEventObjectWaitAndHoldBridgeLock(hOSEvent) : OSEventObjectWait(hOSEvent);
			if (eErrorWait != PVRSRV_OK  &&  eErrorWait != PVRSRV_ERROR_TIMEOUT)
			{
				PVR_DPF((PVR_DBG_WARNING,"PVRSRVWaitForValueKM: Waiting for value failed with error %d. Expected 0x%x but found 0x%x (Mask 0x%08x). Retrying",
							eErrorWait,
							ui32Value,
							ui32ActualValue,
							ui32Mask));
			}
		}
	} END_LOOP_UNTIL_TIMEOUT();

	OSEventObjectClose(hOSEvent);

	/* One last check in case the object wait ended after the loop timeout... */
	if (eError != PVRSRV_OK  &&  (*pui32LinMemAddr & ui32Mask) == ui32Value)
	{
		eError = PVRSRV_OK;
	}

	/* Provide event timeout information to aid the Device Watchdog Thread... */
	if (eError == PVRSRV_OK)
	{
		psPVRSRVData->ui32GEOConsecutiveTimeouts = 0;
	}
	else if (eError == PVRSRV_ERROR_TIMEOUT)
	{
		psPVRSRVData->ui32GEOConsecutiveTimeouts++;
	}

EventObjectOpenError:

	return eError;

#endif /* NO_HARDWARE */
}

/*
	PVRSRVWaitForValueKM
*/
IMG_EXPORT
PVRSRV_ERROR IMG_CALLCONV PVRSRVWaitForValueKM (volatile IMG_UINT32	*pui32LinMemAddr,
												IMG_UINT32			ui32Value,
												IMG_UINT32			ui32Mask)
{
	/* In this case we are NOT retaining bridge lock while waiting
	   for bridge lock. */
	return WaitForValueKM(pui32LinMemAddr, ui32Value, ui32Mask, IMG_FALSE);
}

/*
	PVRSRVWaitForValueKMAndHoldBridgeLock
*/
PVRSRV_ERROR IMG_CALLCONV PVRSRVWaitForValueKMAndHoldBridgeLockKM(volatile IMG_UINT32 *pui32LinMemAddr,
                                                                  IMG_UINT32          ui32Value,
                                                                  IMG_UINT32          ui32Mask)
{
	return WaitForValueKM(pui32LinMemAddr, ui32Value, ui32Mask, IMG_TRUE);
}

int PVRSRVGetDriverStatus(void)
{
	return PVRSRVGetPVRSRVData()->eServicesState;
}

/*!
 ******************************************************************************

 @Function		PVRSRVGetErrorStringKM

 @Description	Returns a text string relating to the PVRSRV_ERROR enum.

 @Note		case statement used rather than an indexed array to ensure text is
 			synchronised with the correct enum

 @Input		eError : PVRSRV_ERROR enum

 @Return	const IMG_CHAR * : Text string

 @Note		Must be kept in sync with servicesext.h

******************************************************************************/

IMG_EXPORT
const IMG_CHAR *PVRSRVGetErrorStringKM(PVRSRV_ERROR eError)
{
	switch(eError)
	{
		case PVRSRV_OK:
			return "PVRSRV_OK";
#define PVRE(x) \
		case x: \
			return #x;
#include "pvrsrv_errors.h"
#undef PVRE
		default:
			return "Unknown PVRSRV error number";
	}
}

/*
	PVRSRVSystemHasCacheSnooping
*/
IMG_BOOL PVRSRVSystemHasCacheSnooping(PVRSRV_DEVICE_CONFIG *psDevConfig)
{
	if ((psDevConfig->eCacheSnoopingMode != PVRSRV_DEVICE_SNOOP_NONE) &&
		(psDevConfig->eCacheSnoopingMode != PVRSRV_DEVICE_SNOOP_EMULATED))
	{
		return IMG_TRUE;
	}
	return IMG_FALSE;
}

IMG_BOOL PVRSRVSystemSnoopingIsEmulated(PVRSRV_DEVICE_CONFIG *psDevConfig)
{
	if (psDevConfig->eCacheSnoopingMode == PVRSRV_DEVICE_SNOOP_EMULATED)
	{
		return IMG_TRUE;
	}
	return IMG_FALSE;
}

IMG_BOOL PVRSRVSystemSnoopingOfCPUCache(PVRSRV_DEVICE_CONFIG *psDevConfig)
{
	if ((psDevConfig->eCacheSnoopingMode == PVRSRV_DEVICE_SNOOP_CPU_ONLY) ||
		(psDevConfig->eCacheSnoopingMode == PVRSRV_DEVICE_SNOOP_CROSS))
	{
		return IMG_TRUE;
	}
	return IMG_FALSE;
}

IMG_BOOL PVRSRVSystemSnoopingOfDeviceCache(PVRSRV_DEVICE_CONFIG *psDevConfig)
{
	if ((psDevConfig->eCacheSnoopingMode == PVRSRV_DEVICE_SNOOP_DEVICE_ONLY) ||
		(psDevConfig->eCacheSnoopingMode == PVRSRV_DEVICE_SNOOP_CROSS))
	{
		return IMG_TRUE;
	}
	return IMG_FALSE;
}

IMG_BOOL PVRSRVSystemHasNonMappableLocalMemory(PVRSRV_DEVICE_CONFIG *psDevConfig)
{
	return psDevConfig->bHasNonMappableLocalMemory;
}

/*
	PVRSRVSystemWaitCycles
*/
void PVRSRVSystemWaitCycles(PVRSRV_DEVICE_CONFIG *psDevConfig, IMG_UINT32 ui32Cycles)
{
	/* Delay in us */
	IMG_UINT32 ui32Delayus = 1;

	/* obtain the device freq */
	if (psDevConfig->pfnClockFreqGet != NULL)
	{
		IMG_UINT32 ui32DeviceFreq;

		ui32DeviceFreq = psDevConfig->pfnClockFreqGet(psDevConfig->hSysData);

		ui32Delayus = (ui32Cycles*1000000)/ui32DeviceFreq;

		if (ui32Delayus == 0)
		{
			ui32Delayus = 1;
		}
	}

	OSWaitus(ui32Delayus);
}

static void *
PVRSRVSystemInstallDeviceLISR_Match_AnyVaCb(PVRSRV_DEVICE_NODE *psDeviceNode,
											va_list va)
{
	void *pvOSDevice = va_arg(va, void *);

	if (psDeviceNode->psDevConfig->pvOSDevice == pvOSDevice)
	{
		return psDeviceNode;
	}

	return NULL;
}

PVRSRV_ERROR PVRSRVSystemInstallDeviceLISR(void *pvOSDevice,
										   IMG_UINT32 ui32IRQ,
										   const IMG_CHAR *pszName,
										   PFN_LISR pfnLISR,
										   void *pvData,
										   IMG_HANDLE *phLISRData)
{
	PVRSRV_DATA *psPVRSRVData = PVRSRVGetPVRSRVData();
	PVRSRV_DEVICE_NODE *psDeviceNode;

	psDeviceNode =
		List_PVRSRV_DEVICE_NODE_Any_va(psPVRSRVData->psDeviceNodeList,
									   &PVRSRVSystemInstallDeviceLISR_Match_AnyVaCb,
									   pvOSDevice);
	if (!psDeviceNode)
	{
		/* Device can't be found in the list so it isn't in the system */
		PVR_DPF((PVR_DBG_ERROR, "%s: device %p with irq %d is not present",
				 __func__, pvOSDevice, ui32IRQ));
		return PVRSRV_ERROR_INVALID_DEVICE;
	}

	return SysInstallDeviceLISR(psDeviceNode->psDevConfig->hSysData, ui32IRQ,
								pszName, pfnLISR, pvData, phLISRData);
}

PVRSRV_ERROR PVRSRVSystemUninstallDeviceLISR(IMG_HANDLE hLISRData)
{
	return SysUninstallDeviceLISR(hLISRData);
}

PVRSRV_ERROR
PVRSRVSystemBIFTilingHeapGetXStride(PVRSRV_DEVICE_CONFIG *psDevConfig,
									IMG_UINT32 uiHeapNum,
									IMG_UINT32 *puiXStride)
{
	PVR_ASSERT(puiXStride != NULL);

	if (uiHeapNum < 1 || uiHeapNum > psDevConfig->ui32BIFTilingHeapCount)
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}

	*puiXStride = psDevConfig->pui32BIFTilingHeapConfigs[uiHeapNum - 1];

	return PVRSRV_OK;
}

PVRSRV_ERROR
PVRSRVSystemBIFTilingGetConfig(PVRSRV_DEVICE_CONFIG  *psDevConfig,
                               RGXFWIF_BIFTILINGMODE *peBifTilingMode,
                               IMG_UINT32            *puiNumHeaps)
{
	*peBifTilingMode = psDevConfig->eBIFTilingMode;
	*puiNumHeaps = psDevConfig->ui32BIFTilingHeapCount;
	return PVRSRV_OK;
}

#if defined(SUPPORT_GPUVIRT_VALIDATION) && defined(EMULATOR)
void SetAxiProtOSid(IMG_UINT32 ui32OSid, IMG_BOOL bState)
{
    SysSetAxiProtOSid(ui32OSid, bState);
    return;
}

void SetTrustedDeviceAceEnabled(void)
{
    SysSetTrustedDeviceAceEnabled();

    return;
}
#endif

PVRSRV_ERROR IMG_CALLCONV PVRSRVVzDeviceCreate(PVRSRV_DEVICE_NODE *psDeviceNode)
{
	RA_BASE_T uBase;
	RA_LENGTH_T uSize;
	IMG_UINT ui32OSID;
	IMG_UINT64 ui64Size;
	PVRSRV_ERROR eError;
	PHYS_HEAP *psPhysHeap;
	IMG_CPU_PHYADDR sCpuPAddr;
	IMG_DEV_PHYADDR sDevPAddr;
	PHYS_HEAP_TYPE eHeapType;
	IMG_UINT32 ui32NumOfHeapRegions;
	PVRSRV_VZ_RET_IF_MODE(DRIVER_MODE_NATIVE, PVRSRV_OK);

	/* First, register device GPU physical heap based on physheap config */
	psPhysHeap = psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_GPU_LOCAL];
	ui32NumOfHeapRegions = PhysHeapNumberOfRegions(psPhysHeap);
	eHeapType = PhysHeapGetType(psPhysHeap);

	/* Normally, for GPU UMA physheap, use OS services but here we override this
	   if said physheap is DMA/UMA carve-out; for this create an RA to manage it */
	if (eHeapType == PHYS_HEAP_TYPE_UMA || eHeapType == PHYS_HEAP_TYPE_DMA)
	{
		if (ui32NumOfHeapRegions)
		{
			eError = PhysHeapRegionGetCpuPAddr(psPhysHeap, 0, &sCpuPAddr);
			if (eError != PVRSRV_OK)
			{
				PVR_ASSERT(IMG_FALSE);
				goto e0;
			}
	
			eError = PhysHeapRegionGetSize(psPhysHeap, 0, &ui64Size);
			if (eError != PVRSRV_OK)
			{
				PVR_ASSERT(IMG_FALSE);
				goto e0;
			}
	
			eError = PhysHeapRegionGetDevPAddr(psPhysHeap, 0, &sDevPAddr);
			if (eError != PVRSRV_OK)
			{
				PVR_ASSERT(IMG_FALSE);
				goto e0;
			}
		}
		else
		{
			sDevPAddr.uiAddr = (IMG_UINT64)0;
			sCpuPAddr.uiAddr = (IMG_UINT64)0;
			ui64Size = (IMG_UINT64)0;
		}

		if (sCpuPAddr.uiAddr && sDevPAddr.uiAddr && ui64Size)
		{
			psDeviceNode->ui32NumOfLocalMemArenas = ui32NumOfHeapRegions;
			PVR_ASSERT(ui32NumOfHeapRegions == 1);

			PVR_DPF((PVR_DBG_MESSAGE, "===== UMA (carve-out) memory, 1st phys heap (gpu)"));

			PVR_DPF((PVR_DBG_MESSAGE, "Creating RA for gpu memory 0x%016"IMG_UINT64_FMTSPECX"-0x%016"IMG_UINT64_FMTSPECX,
			 		(IMG_UINT64) sCpuPAddr.uiAddr, sCpuPAddr.uiAddr + ui64Size - 1));

			uBase = sDevPAddr.uiAddr;
			uSize = (RA_LENGTH_T) ui64Size;
			PVR_ASSERT(uSize == ui64Size);

			psDeviceNode->apsLocalDevMemArenas = OSAllocMem(sizeof(RA_ARENA*));
			PVR_ASSERT(psDeviceNode->apsLocalDevMemArenas);
			psDeviceNode->apszRANames = OSAllocMem(sizeof(IMG_PCHAR));
			PVR_ASSERT(psDeviceNode->apszRANames);
			psDeviceNode->apszRANames[0] = OSAllocMem(PVRSRV_MAX_RA_NAME_LENGTH);
			PVR_ASSERT(psDeviceNode->apszRANames[0]);

			OSSNPrintf(psDeviceNode->apszRANames[0], PVRSRV_MAX_RA_NAME_LENGTH,
						"%s gpu mem", psDeviceNode->psDevConfig->pszName);
	
			psDeviceNode->apsLocalDevMemArenas[0] =
				RA_Create(psDeviceNode->apszRANames[0],
							OSGetPageShift(),	/* Use OS page size, keeps things simple */
							RA_LOCKCLASS_0,		/* This arena doesn't use any other arenas. */
							NULL,				/* No Import */
							NULL,				/* No free import */
							NULL,				/* No import handle */
							IMG_FALSE);
			if (psDeviceNode->apsLocalDevMemArenas[0] == NULL)
			{
				eError = PVRSRV_ERROR_OUT_OF_MEMORY;
				goto e0;
			}
	
			if (!RA_Add(psDeviceNode->apsLocalDevMemArenas[0], uBase, uSize, 0 , NULL))
			{
				RA_Delete(psDeviceNode->apsLocalDevMemArenas[0]);
				eError = PVRSRV_ERROR_OUT_OF_MEMORY;
				goto e0;
			}

			/* Replace the UMA allocator with LMA allocator */
			psDeviceNode->pfnDevPxAlloc = LMA_PhyContigPagesAlloc;
			psDeviceNode->pfnDevPxFree = LMA_PhyContigPagesFree;
			psDeviceNode->pfnDevPxMap = LMA_PhyContigPagesMap;
			psDeviceNode->pfnDevPxUnMap = LMA_PhyContigPagesUnmap;
			psDeviceNode->pfnDevPxClean = LMA_PhyContigPagesClean;
			psDeviceNode->uiMMUPxLog2AllocGran = OSGetPageShift();
			psDeviceNode->pfnCreateRamBackedPMR[PVRSRV_DEVICE_PHYS_HEAP_GPU_LOCAL] = PhysmemNewLocalRamBackedPMR;
		}
	}
	else
	{
		/* LMA heap sanity check */
		PVR_ASSERT(ui32NumOfHeapRegions);
	}

	/* Next, register device firmware physical heap based on heap config */
	psPhysHeap = psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_FW_LOCAL];
	ui32NumOfHeapRegions = PhysHeapNumberOfRegions(psPhysHeap);
	eHeapType = PhysHeapGetType(psPhysHeap);
	PVR_ASSERT(eHeapType != PHYS_HEAP_TYPE_UNKNOWN);

	PVR_DPF((PVR_DBG_MESSAGE, "===== LMA/DMA/UMA (carve-out) memory, 2nd phys heap (fw)"));

	if (ui32NumOfHeapRegions)
	{
		eError = PhysHeapRegionGetCpuPAddr(psPhysHeap, 0, &sCpuPAddr);
		if (eError != PVRSRV_OK)
		{
			PVR_ASSERT(IMG_FALSE);
			goto e0;
		}
	
		eError = PhysHeapRegionGetSize(psPhysHeap, 0, &ui64Size);
		if (eError != PVRSRV_OK)
		{
			PVR_ASSERT(IMG_FALSE);
			goto e0;
		}
	
		eError = PhysHeapRegionGetDevPAddr(psPhysHeap, 0, &sDevPAddr);
		if (eError != PVRSRV_OK)
		{
			PVR_ASSERT(IMG_FALSE);
			goto e0;
		}
	}
	else
	{
		sDevPAddr.uiAddr = (IMG_UINT64)0;
		sCpuPAddr.uiAddr = (IMG_UINT64)0;
		ui64Size = (IMG_UINT64)0;
	}

	if (ui32NumOfHeapRegions)
	{
		PVRSRV_DEVICE_PHYS_HEAP_ORIGIN eHeapOrigin;

		SysVzGetPhysHeapOrigin(psDeviceNode->psDevConfig,
							   PVRSRV_DEVICE_PHYS_HEAP_FW_LOCAL,
							   &eHeapOrigin);

		PVR_DPF((PVR_DBG_MESSAGE, "Creating RA for  fw memory 0x%016"IMG_UINT64_FMTSPECX"-0x%016"IMG_UINT64_FMTSPECX,
				(IMG_UINT64) sCpuPAddr.uiAddr, sCpuPAddr.uiAddr + ui64Size - 1));

		/* Now we construct RA to manage FW heap */
		uBase = sDevPAddr.uiAddr;
		uSize = (RA_LENGTH_T) ui64Size;
		PVR_ASSERT(sCpuPAddr.uiAddr && uSize == ui64Size && RGX_FIRMWARE_TOTAL_HEAP_SIZE);
		if (eHeapType != PHYS_HEAP_TYPE_LMA)
		{
			/* On some LMA config, fw base starts at zero */
			PVR_ASSERT(sDevPAddr.uiAddr);
		}

		/* All vz drivers go through this motion, here the loop terminates early
		   for guest driver(s) seeing RGXFW_NUM_OS will be one */
		for (ui32OSID = 0; ui32OSID < RGXFW_NUM_OS; ui32OSID++)
		{
			RA_BASE_T	uOSIDMainBase = uBase + (ui32OSID * RGX_FIRMWARE_TOTAL_HEAP_SIZE);
			RA_LENGTH_T	uMainSize = RGX_FIRMWARE_MAIN_HEAP_SIZE;
			RA_BASE_T	uOSIDConfigBase = uOSIDMainBase + uMainSize;
			RA_LENGTH_T	uConfigSize = RGX_FIRMWARE_CONFIG_HEAP_SIZE;

			OSSNPrintf(psDeviceNode->szKernelFwMainRAName[ui32OSID], sizeof(psDeviceNode->szKernelFwMainRAName[ui32OSID]),
						"%s fw mem", psDeviceNode->psDevConfig->pszName);

			psDeviceNode->psKernelFwMainMemArena[ui32OSID] =
				RA_Create(psDeviceNode->szKernelFwMainRAName[ui32OSID],
							OSGetPageShift(),	/* Use OS page size, keeps things simple */
							RA_LOCKCLASS_0,		/* This arena doesn't use any other arenas. */
							NULL,				/* No Import */
							NULL,				/* No free import */
							NULL,				/* No import handle */
							IMG_FALSE);
			if (psDeviceNode->psKernelFwMainMemArena[ui32OSID] == NULL)
			{
				eError = PVRSRV_ERROR_OUT_OF_MEMORY;
				goto e1;
			}

			if (!RA_Add(psDeviceNode->psKernelFwMainMemArena[ui32OSID], uOSIDMainBase, uMainSize, 0 , NULL))
			{
				RA_Delete(psDeviceNode->psKernelFwMainMemArena[ui32OSID]);
				eError = PVRSRV_ERROR_OUT_OF_MEMORY;
				goto e1;
			}

			OSSNPrintf(psDeviceNode->szKernelFwConfigRAName[ui32OSID], sizeof(psDeviceNode->szKernelFwConfigRAName[ui32OSID]),
									"%s fw mem", psDeviceNode->psDevConfig->pszName);

			psDeviceNode->psKernelFwConfigMemArena[ui32OSID] =
				RA_Create(psDeviceNode->szKernelFwConfigRAName[ui32OSID],
							OSGetPageShift(),	/* Use OS page size, keeps things simple */
							RA_LOCKCLASS_0,		/* This arena doesn't use any other arenas. */
							NULL,				/* No Import */
							NULL,				/* No free import */
							NULL,				/* No import handle */
							IMG_FALSE);
			if (psDeviceNode->psKernelFwConfigMemArena[ui32OSID] == NULL)
			{
				eError = PVRSRV_ERROR_OUT_OF_MEMORY;
				goto e1;
			}

			if (!RA_Add(psDeviceNode->psKernelFwConfigMemArena[ui32OSID], uOSIDConfigBase, uConfigSize, 0 , NULL))
			{
				RA_Delete(psDeviceNode->psKernelFwConfigMemArena[ui32OSID]);
				eError = PVRSRV_ERROR_OUT_OF_MEMORY;
				goto e1;
			}

			if (eHeapOrigin != PVRSRV_DEVICE_PHYS_HEAP_ORIGIN_HOST)
			{
				break;
			}
		}

		/* Fw physheap is always managed by LMA PMR factory */
		psDeviceNode->pfnCreateRamBackedPMR[PVRSRV_DEVICE_PHYS_HEAP_FW_LOCAL] = PhysmemNewLocalRamBackedPMR;
	}

	return PVRSRV_OK;
e1:
	PVRSRVVzDeviceDestroy(psDeviceNode);
e0:
	return eError;
}

PVRSRV_ERROR IMG_CALLCONV PVRSRVVzDeviceDestroy(PVRSRV_DEVICE_NODE *psDeviceNode)
{
	IMG_UINT ui32OSID;
	IMG_UINT64 ui64Size;
	PHYS_HEAP *psPhysHeap;
	IMG_CPU_PHYADDR sCpuPAddr;
	IMG_DEV_PHYADDR sDevPAddr;
	PHYS_HEAP_TYPE eHeapType;
	IMG_UINT32 ui32NumOfHeapRegions;
	PVRSRV_ERROR eError = PVRSRV_OK;
	PVRSRV_VZ_RET_IF_MODE(DRIVER_MODE_NATIVE, PVRSRV_OK);

	/* First, unregister device firmware physical heap based on heap config */
	psPhysHeap = psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_FW_LOCAL];
	ui32NumOfHeapRegions = PhysHeapNumberOfRegions(psPhysHeap);

	if (ui32NumOfHeapRegions)
	{
		for (ui32OSID = 0; ui32OSID < RGXFW_NUM_OS; ui32OSID++)
		{
			if (psDeviceNode->psKernelFwMainMemArena[ui32OSID])
			{
				RA_Delete(psDeviceNode->psKernelFwMainMemArena[ui32OSID]);
				psDeviceNode->psKernelFwMainMemArena[ui32OSID] = NULL;
			}
			if (psDeviceNode->psKernelFwConfigMemArena[ui32OSID])
			{
				RA_Delete(psDeviceNode->psKernelFwConfigMemArena[ui32OSID]);
				psDeviceNode->psKernelFwConfigMemArena[ui32OSID] = NULL;
			}
		}
	}

	/* Next, unregister device GPU physical heap based on heap config */
	psPhysHeap = psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_GPU_LOCAL];
	ui32NumOfHeapRegions = PhysHeapNumberOfRegions(psPhysHeap);
	eHeapType = PhysHeapGetType(psPhysHeap);

	if (eHeapType == PHYS_HEAP_TYPE_UMA || eHeapType == PHYS_HEAP_TYPE_DMA)
	{
		if (ui32NumOfHeapRegions)
		{
			eError = PhysHeapRegionGetCpuPAddr(psPhysHeap, 0, &sCpuPAddr);
			if (eError != PVRSRV_OK)
			{
				PVR_ASSERT(IMG_FALSE);
				return eError;
			}
	
			eError = PhysHeapRegionGetSize(psPhysHeap, 0, &ui64Size);
			if (eError != PVRSRV_OK)
			{
				PVR_ASSERT(IMG_FALSE);
				return eError;
			}
	
			eError = PhysHeapRegionGetDevPAddr(psPhysHeap, 0, &sDevPAddr);
			if (eError != PVRSRV_OK)
			{
				PVR_ASSERT(IMG_FALSE);
				return eError;
			}
		}
		else
		{
			sDevPAddr.uiAddr = (IMG_UINT64)0;
			sCpuPAddr.uiAddr = (IMG_UINT64)0;
			ui64Size = (IMG_UINT64)0;
		}

		if (sCpuPAddr.uiAddr && sDevPAddr.uiAddr && ui64Size)
		{
			if (psDeviceNode->apsLocalDevMemArenas && psDeviceNode->apsLocalDevMemArenas[0])
			{
				RA_Delete(psDeviceNode->apsLocalDevMemArenas[0]);
				psDeviceNode->apsLocalDevMemArenas[0] = NULL;
				OSFreeMem(psDeviceNode->apsLocalDevMemArenas);
				psDeviceNode->apsLocalDevMemArenas = NULL;
			}
			if (psDeviceNode->apszRANames)
			{
				OSFreeMem(psDeviceNode->apszRANames[0]);
				psDeviceNode->apszRANames[0] = NULL;
				OSFreeMem(psDeviceNode->apszRANames);
				psDeviceNode->apszRANames = NULL;
			}
		}
	}

	return eError;
}

PVRSRV_ERROR IMG_CALLCONV PVRSRVVzRegisterFirmwarePhysHeap(PVRSRV_DEVICE_NODE *psDeviceNode,
															IMG_DEV_PHYADDR sDevPAddr,
															IMG_UINT64 ui64DevPSize,
															IMG_UINT32 uiOSID)
{
	RA_BASE_T uMainBase, uConfigBase;
	RA_LENGTH_T uMainSize, uConfigSize;
	PHYS_HEAP *psPhysHeap;
	PVRSRV_ERROR eError;

	/*
	   This is called by the host driver only, it creates an RA to manage this guest firmware
	   physheaps so we fail the call if an invalid guest OSID is supplied.
	*/
	PVRSRV_VZ_RET_IF_NOT_MODE(DRIVER_MODE_HOST, PVRSRV_ERROR_INTERNAL_ERROR);
	PVR_DPF((PVR_DBG_MESSAGE, "===== Registering OSID: %d fw physheap memory", uiOSID));
	PVR_LOGR_IF_FALSE(((uiOSID > 0)&&(uiOSID < RGXFW_NUM_OS)), "Invalid guest OSID", PVRSRV_ERROR_INVALID_PARAMS);

	/* Verify guest size with host size  (support only same sized FW heaps) */
	psPhysHeap = psDeviceNode->apsPhysHeap[PVRSRV_DEVICE_PHYS_HEAP_FW_LOCAL];

	if (ui64DevPSize != RGX_FIRMWARE_TOTAL_HEAP_SIZE)
	{
		PVR_DPF((PVR_DBG_WARNING,
				"OSID: %d fw physheap size 0x%"IMG_UINT64_FMTSPECX" differs from host fw phyheap size 0x%X",
				uiOSID,
				ui64DevPSize,
				RGX_FIRMWARE_TOTAL_HEAP_SIZE));

		PVR_DPF((PVR_DBG_WARNING,
				"Truncating OSID: %d requested fw physheap to: 0x%X\n",
				uiOSID,
				RGX_FIRMWARE_TOTAL_HEAP_SIZE));
	}

	PVR_DPF((PVR_DBG_MESSAGE, "Creating RA for fw 0x%016"IMG_UINT64_FMTSPECX"-0x%016"IMG_UINT64_FMTSPECX" [DEV/PA]",
			(IMG_UINT64) sDevPAddr.uiAddr, sDevPAddr.uiAddr + RGX_FIRMWARE_TOTAL_HEAP_SIZE - 1));

	/* Construct RA to manage FW Main heap */
	uMainBase = sDevPAddr.uiAddr;
	uMainSize = (RA_LENGTH_T) RGX_FIRMWARE_MAIN_HEAP_SIZE;
	PVR_ASSERT(uMainSize == RGX_FIRMWARE_MAIN_HEAP_SIZE);

	OSSNPrintf(psDeviceNode->szKernelFwMainRAName[uiOSID],
			   sizeof(psDeviceNode->szKernelFwMainRAName[uiOSID]),
			   "[OSID: %d]: fw mem", uiOSID);

	psDeviceNode->psKernelFwMainMemArena[uiOSID] =
		RA_Create(psDeviceNode->szKernelFwMainRAName[uiOSID],
					OSGetPageShift(),		/* Use host page size, keeps things simple */
					RA_LOCKCLASS_0,			/* This arena doesn't use any other arenas */
					NULL,				/* No Import */
					NULL,				/* No free import */
					NULL,				/* No import handle */
					IMG_FALSE);
	if (psDeviceNode->psKernelFwMainMemArena[uiOSID] == NULL)
	{
		eError = PVRSRV_ERROR_OUT_OF_MEMORY;
		goto e0;
	}

	if (!RA_Add(psDeviceNode->psKernelFwMainMemArena[uiOSID], uMainBase, uMainSize, 0 , NULL))
	{
		RA_Delete(psDeviceNode->psKernelFwMainMemArena[uiOSID]);
		eError = PVRSRV_ERROR_OUT_OF_MEMORY;
		goto e0;
	}

	/* Construct RA to manage FW Config heap */
	uConfigBase = uMainBase + uMainSize;
	uConfigSize = (RA_LENGTH_T) RGX_FIRMWARE_CONFIG_HEAP_SIZE;
	PVR_ASSERT(uConfigSize == RGX_FIRMWARE_CONFIG_HEAP_SIZE);

	OSSNPrintf(psDeviceNode->szKernelFwConfigRAName[uiOSID],
			   sizeof(psDeviceNode->szKernelFwConfigRAName[uiOSID]),
			   "[OSID: %d]: fw mem", uiOSID);

	psDeviceNode->psKernelFwConfigMemArena[uiOSID] =
		RA_Create(psDeviceNode->szKernelFwConfigRAName[uiOSID],
					OSGetPageShift(),		/* Use host page size, keeps things simple */
					RA_LOCKCLASS_0,			/* This arena doesn't use any other arenas */
					NULL,				/* No Import */
					NULL,				/* No free import */
					NULL,				/* No import handle */
					IMG_FALSE);
	if (psDeviceNode->psKernelFwConfigMemArena[uiOSID] == NULL)
	{
		eError = PVRSRV_ERROR_OUT_OF_MEMORY;
		goto e0;
	}

	if (!RA_Add(psDeviceNode->psKernelFwConfigMemArena[uiOSID], uConfigBase, uConfigSize, 0 , NULL))
	{
		RA_Delete(psDeviceNode->psKernelFwConfigMemArena[uiOSID]);
		eError = PVRSRV_ERROR_OUT_OF_MEMORY;
		goto e0;
	}

	psDeviceNode->ui64RABase[uiOSID] = uMainBase;
	return PVRSRV_OK;
e0:
	return eError;
}

PVRSRV_ERROR IMG_CALLCONV PVRSRVVzUnregisterFirmwarePhysHeap(PVRSRV_DEVICE_NODE *psDeviceNode,
																IMG_UINT32 uiOSID)
{
	RA_BASE_T uMainBase = psDeviceNode->ui64RABase[uiOSID];
	RA_BASE_T uConfigBase = uMainBase + RGX_FIRMWARE_MAIN_HEAP_SIZE;

	PVRSRV_VZ_RET_IF_NOT_MODE(DRIVER_MODE_HOST, PVRSRV_ERROR_INTERNAL_ERROR);
	PVR_DPF((PVR_DBG_MESSAGE, "===== Deregistering OSID: %d fw physheap memory", uiOSID));
	PVR_LOGR_IF_FALSE(((uiOSID > 0)&&(uiOSID < RGXFW_NUM_OS)), "Invalid guest OSID", PVRSRV_ERROR_INVALID_PARAMS);

	if (psDeviceNode->psKernelFwMainMemArena[uiOSID])
	{
		RA_Free(psDeviceNode->psKernelFwMainMemArena[uiOSID], uMainBase);
		RA_Delete(psDeviceNode->psKernelFwMainMemArena[uiOSID]);
		psDeviceNode->psKernelFwMainMemArena[uiOSID] = NULL;
	}

	if (psDeviceNode->psKernelFwConfigMemArena[uiOSID])
	{
		RA_Free(psDeviceNode->psKernelFwConfigMemArena[uiOSID], uConfigBase);
		RA_Delete(psDeviceNode->psKernelFwConfigMemArena[uiOSID]);
		psDeviceNode->psKernelFwConfigMemArena[uiOSID] = NULL;
	}

	return PVRSRV_OK;
}

/*****************************************************************************
 End of file (pvrsrv.c)
*****************************************************************************/
