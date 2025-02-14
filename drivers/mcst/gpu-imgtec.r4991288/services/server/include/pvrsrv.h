/**************************************************************************/ /*!
@File
@Title          PowerVR services server header file
@Copyright      Copyright (c) Imagination Technologies Ltd. All Rights Reserved
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
*/ /***************************************************************************/

#ifndef PVRSRV_H
#define PVRSRV_H


#include "connection_server.h"
#include "device.h"
#include "power.h"
#include "sysinfo.h"
#include "physheap.h"
#include "cache_ops.h"
#include "pvr_notifier.h"
#include "pvr_bridge.h"
#if defined(SUPPORT_RGX)
#include "rgx_bridge.h"
#endif
#if defined(__KERNEL__) && defined(LINUX) && !defined(__GENKSYMS__)
#define __pvrsrv_defined_struct_enum__
#include <services_kernel_client.h>
#endif

#include "pvrsrv_pool.h"

#if defined(SUPPORT_GPUVIRT_VALIDATION)
#include "virt_validation_defs.h"
#endif

#include "dma_support.h"
#include "vz_support.h"
#include "vz_physheap.h"

/*!
 * For OSThreadDestroy(), which may require a retry
 * Try for 100 ms to destroy an OS thread before failing
 */
#define OS_THREAD_DESTROY_TIMEOUT_US 100000ULL
#define OS_THREAD_DESTROY_RETRY_COUNT 10

typedef enum _VMM_CONF_PARAM_
{
	VMM_CONF_PRIO_OSID0 = 0,
	VMM_CONF_PRIO_OSID1 = 1,
	VMM_CONF_PRIO_OSID2 = 2,
	VMM_CONF_PRIO_OSID3 = 3,
	VMM_CONF_PRIO_OSID4 = 4,
	VMM_CONF_PRIO_OSID5 = 5,
	VMM_CONF_PRIO_OSID6 = 6,
	VMM_CONF_PRIO_OSID7 = 7,
	VMM_CONF_ISOL_THRES = 8,
	VMM_CONF_HCS_DEADLINE = 9
} VMM_CONF_PARAM;

typedef struct _BUILD_INFO_
{
	IMG_UINT32	ui32BuildOptions;
	IMG_UINT32	ui32BuildVersion;
	IMG_UINT32	ui32BuildRevision;
	IMG_UINT32	ui32BuildType;
#define BUILD_TYPE_DEBUG	0
#define BUILD_TYPE_RELEASE	1
	/*The above fields are self explanatory */
	/* B.V.N.C can be added later if required */
} BUILD_INFO;

typedef struct _DRIVER_INFO_
{
	BUILD_INFO	sUMBuildInfo;
	BUILD_INFO	sKMBuildInfo;
	IMG_UINT8	ui8UMSupportedArch;
	IMG_UINT8	ui8KMBitArch;

#define	BUILD_ARCH_64BIT			(1 << 0)
#define	BUILD_ARCH_32BIT			(1 << 1)
#define	BUILD_ARCH_BOTH		(BUILD_ARCH_32BIT | BUILD_ARCH_64BIT)
	IMG_BOOL	bIsNoMatch;
}DRIVER_INFO;

typedef struct PVRSRV_DATA_TAG
{
	PVRSRV_DRIVER_MODE			eDriverMode;				/*!< Driver mode (i.e. native, host or guest) */
	DRIVER_INFO					sDriverInfo;
	IMG_UINT32					ui32RegisteredDevices;
	PVRSRV_DEVICE_NODE			*psDeviceNodeList;			/*!< List head of device nodes */
	PVRSRV_DEVICE_NODE			*psHostMemDeviceNode;		/*!< DeviceNode to be used for device independent
	                                                             host based memory allocations where the DevMem
	                                                             framework is to be used e.g. TL */
	PVRSRV_SERVICES_STATE		eServicesState;				/*!< global driver state */

	HASH_TABLE					*psProcessHandleBase_Table; /*!< Hash table with process handle bases */
	POS_LOCK					hProcessHandleBase_Lock;	/*!< Lock for the process handle base table */

	IMG_HANDLE					hGlobalEventObject;			/*!< OS Global Event Object */
	IMG_UINT32					ui32GEOConsecutiveTimeouts;	/*!< OS Global Event Object Timeouts */

	IMG_HANDLE					hCleanupThread;				/*!< Cleanup thread */
	IMG_HANDLE					hCleanupEventObject;		/*!< Event object to drive cleanup thread */
	POS_LOCK					hCleanupThreadWorkListLock;	/*!< Lock protecting the cleanup thread work list */
	DLLIST_NODE					sCleanupThreadWorkList;		/*!< List of work for the cleanup thread */
	IMG_PID						cleanupThreadPid;			/*!< Cleanup thread process id */

	IMG_HANDLE					hDevicesWatchdogThread;		/*!< Devices watchdog thread */
	IMG_HANDLE					hDevicesWatchdogEvObj;		/*! Event object to drive devices watchdog thread */
	volatile IMG_UINT32			ui32DevicesWatchdogPwrTrans;/*! Number of off -> on power state transitions */
	volatile IMG_UINT32			ui32DevicesWatchdogTimeout; /*! Timeout for the Devices watchdog Thread */
#ifdef PVR_TESTING_UTILS
	volatile IMG_UINT32			ui32DevicesWdWakeupCounter;	/* Need this for the unit tests. */
#endif

	IMG_HANDLE					hPvzConnection;				/*!< PVZ connection used for cross-VM hyper-calls */
	POS_LOCK					hPvzConnectionLock;			/*!< Lock protecting PVZ connection */
	IMG_BOOL					abVmOnline[RGXFW_NUM_OS];

	IMG_BOOL					bUnload;					/*!< Driver unload is in progress */

	IMG_HANDLE					hTLCtrlStream;				/*! Control plane for TL streams */

	PVRSRV_POOL					*psBridgeBufferPool;			/*! Pool of bridge buffers */
	IMG_HANDLE					hDriverThreadEventObject;		/*! Event object relating to multi-threading in the Server */
	POS_LOCK					hDriverThreadLock;			/*! Lock to protect bDriverSuspended and iNumActiveDriverThreads */
	IMG_BOOL					bDriverSuspended;			/*! if TRUE, the driver is suspended and new threads should not enter */
	ATOMIC_T					iNumActiveDriverThreads;			/*! Number of threads active in the Server */

	PMR							*psInfoPagePMR;				/*! Handle to exportable PMR of the information page. */
	IMG_UINT32					*pui32InfoPage;				/*! CPU memory mapping for information page. */
	DEVMEM_MEMDESC				*psInfoPageMemDesc;			/*! Memory descriptor of the information page. */
	POS_LOCK					hInfoPageLock;				/*! Lock guarding access to information page. */

	POS_LOCK                    hConnectionsLock;           /*!< Lock protecting sConnections */
	DLLIST_NODE                 sConnections;               /*!< The list of currently active connection objects */
} PVRSRV_DATA;

typedef IMG_BOOL (*PFN_LISR)(void *pvData);

/*!
******************************************************************************

 @Function	PVRSRVGetPVRSRVData

 @Description	Get a pointer to the global data

 @Return   PVRSRV_DATA *

******************************************************************************/
PVRSRV_DATA *PVRSRVGetPVRSRVData(void);

/*!
******************************************************************************************
@Note   Kernel code must always query the driver mode using the PVRSRV_VZ_MODE_IS() macro
		_only_ and PVRSRV_DATA->eDriverMode should not be read directly as the field also
		overloads as driver OSID (i.e. not to be confused with hardware kick register OSID)
		when running on non-VZ capable BVNC as the driver has to simulate OSID propagation
		to the firmware in the absence of the hardware kick register propagating this OSID
		on any non-VZ BVNC.
******************************************************************************************/
#define PVRSRV_VZ_MODE_IS(_expr)              (((((IMG_INT)_expr)>0)&&((IMG_INT)PVRSRVGetPVRSRVData()->eDriverMode>0)) ? \
                                                   (IMG_TRUE) : ((_expr) == (PVRSRVGetPVRSRVData()->eDriverMode)))
#define PVRSRV_VZ_RETN_IF_MODE(_expr)         do { if (  PVRSRV_VZ_MODE_IS(_expr)) { return; } } while(0)
#define PVRSRV_VZ_RETN_IF_NOT_MODE(_expr)     do { if (! PVRSRV_VZ_MODE_IS(_expr)) { return; } } while(0)
#define PVRSRV_VZ_RET_IF_MODE(_expr, _rc)     do { if (  PVRSRV_VZ_MODE_IS(_expr)) { return (_rc); } } while(0)
#define PVRSRV_VZ_RET_IF_NOT_MODE(_expr, _rc) do { if (! PVRSRV_VZ_MODE_IS(_expr)) { return (_rc); } } while(0)
#define PVRSRV_VZ_DRIVER_OSID                 (((IMG_INT)PVRSRVGetPVRSRVData()->eDriverMode) > (0) ? \
												   ((IMG_UINT32)(PVRSRVGetPVRSRVData()->eDriverMode)) : (0))

/*!
************************************************************************************************
@Note	The driver execution mode AppHint (i.e. PVRSRV_APPHINT_DRIVERMODE) can be an override or
		non-override 32-bit value. An override value has the MSB bit set & a non-override value
		has this MSB bit cleared. Excluding this MSB bit & interpreting the remaining 31-bit as
		a signed 31-bit integer, the mode values are [-1 native <default>: 0 host : +1 guest ].
************************************************************************************************/
#define PVRSRV_VZ_APPHINT_MODE_IS_OVERRIDE(_expr)   ((IMG_UINT32)(_expr)&(IMG_UINT32)(1<<31))
#define PVRSRV_VZ_APPHINT_MODE(_expr)				\
	((((IMG_UINT32)(_expr)&(IMG_UINT32)0x7FFFFFFF) == (IMG_UINT32)0x7FFFFFFF) ? DRIVER_MODE_NATIVE : \
		!((IMG_UINT32)(_expr)&(IMG_UINT32)0x7FFFFFFF) ? DRIVER_MODE_HOST : \
			((IMG_UINT32)((IMG_UINT32)(_expr)&(IMG_UINT)0x7FFFFFFF)==(IMG_UINT32)0x1) ? DRIVER_MODE_GUEST : \
				((IMG_UINT32)(_expr)&(IMG_UINT32)0x7FFFFFFF))

/*!
******************************************************************************

 @Function	LMA memory management API

******************************************************************************/
PVRSRV_ERROR LMA_PhyContigPagesAlloc(PVRSRV_DEVICE_NODE *psDevNode, size_t uiSize,
							PG_HANDLE *psMemHandle, IMG_DEV_PHYADDR *psDevPAddr);

void LMA_PhyContigPagesFree(PVRSRV_DEVICE_NODE *psDevNode, PG_HANDLE *psMemHandle);

PVRSRV_ERROR LMA_PhyContigPagesMap(PVRSRV_DEVICE_NODE *psDevNode, PG_HANDLE *psMemHandle,
							size_t uiSize, IMG_DEV_PHYADDR *psDevPAddr,
							void **pvPtr);

void LMA_PhyContigPagesUnmap(PVRSRV_DEVICE_NODE *psDevNode, PG_HANDLE *psMemHandle,
					void *pvPtr);

PVRSRV_ERROR LMA_PhyContigPagesClean(PVRSRV_DEVICE_NODE *psDevNode,
                                     PG_HANDLE *psMemHandle,
                                     IMG_UINT32 uiOffset,
                                     IMG_UINT32 uiLength);


/*!
******************************************************************************
 @Function	PVRSRVPollForValueKM

 @Description
 Polls for a value to match a masked read

 @Input pui32LinMemAddr : CPU linear address to poll
 @Input ui32Value : required value
 @Input ui32Mask : Mask

 @Return   PVRSRV_ERROR :
******************************************************************************/
IMG_IMPORT PVRSRV_ERROR IMG_CALLCONV PVRSRVPollForValueKM(volatile IMG_UINT32	*pui32LinMemAddr,
														  IMG_UINT32			ui32Value,
														  IMG_UINT32			ui32Mask);

/*!
******************************************************************************
 @Function	PVRSRVWaitForValueKM

 @Description
 Waits (using EventObjects) for a value to match a masked read

 @Input pui32LinMemAddr			: CPU linear address to poll
 @Input ui32Value				: required value
 @Input ui32Mask				: Mask

 @Return   PVRSRV_ERROR :
******************************************************************************/
IMG_IMPORT PVRSRV_ERROR IMG_CALLCONV PVRSRVWaitForValueKM(volatile IMG_UINT32	*pui32LinMemAddr,
														IMG_UINT32			ui32Value,
														IMG_UINT32			ui32Mask);

/*!
******************************************************************************
 @Function	PVRSRVWaitForValueKMAndHoldBridgeLockKM

 @Description
 Waits without releasing bridge lock (using EventObjects) for a value
 to match a masked read

 @Input pui32LinMemAddr			: CPU linear address to poll
 @Input ui32Value				: required value
 @Input ui32Mask				: Mask

 @Return   PVRSRV_ERROR :
******************************************************************************/
PVRSRV_ERROR IMG_CALLCONV PVRSRVWaitForValueKMAndHoldBridgeLockKM(volatile IMG_UINT32 *pui32LinMemAddr,
                                                                  IMG_UINT32          ui32Value,
                                                                  IMG_UINT32          ui32Mask);

/*!
*****************************************************************************
 @Function	: PVRSRVSystemHasCacheSnooping

 @Description	: Returns whether the system has cache snooping

 @Return : IMG_TRUE if the system has cache snooping
*****************************************************************************/
IMG_BOOL PVRSRVSystemHasCacheSnooping(PVRSRV_DEVICE_CONFIG *psDevConfig);

/*!
*****************************************************************************
 @Function	: PVRSRVSystemSnoopingIsEmulated

 @Description : Returns whether system cache snooping support is emulated

 @Return : IMG_TRUE if the system cache snooping is emulated in software
*****************************************************************************/
IMG_BOOL PVRSRVSystemSnoopingIsEmulated(PVRSRV_DEVICE_CONFIG *psDevConfig);

/*!
*****************************************************************************
 @Function	: PVRSRVSystemSnoopingOfCPUCache

 @Description	: Returns whether the system supports snooping of the CPU cache

 @Return : IMG_TRUE if the system has CPU cache snooping
*****************************************************************************/
IMG_BOOL PVRSRVSystemSnoopingOfCPUCache(PVRSRV_DEVICE_CONFIG *psDevConfig);

/*!
*****************************************************************************
 @Function	: PVRSRVSystemSnoopingOfDeviceCache

 @Description	: Returns whether the system supports snooping of the device cache

 @Return : IMG_TRUE if the system has device cache snooping
*****************************************************************************/
IMG_BOOL PVRSRVSystemSnoopingOfDeviceCache(PVRSRV_DEVICE_CONFIG *psDevConfig);

/*!
*****************************************************************************
 @Function	: PVRSRVSystemHasNonMappableLocalMemory

 @Description	: Returns whether the device has non-mappable part of local memory

 @Return : IMG_TRUE if the device has non-mappable part of local memory
*****************************************************************************/
IMG_BOOL PVRSRVSystemHasNonMappableLocalMemory(PVRSRV_DEVICE_CONFIG *psDevConfig);

/*!
*****************************************************************************
 @Function	: PVRSRVSystemWaitCycles

 @Description	: Waits for at least ui32Cycles of the Device clk.

*****************************************************************************/
void PVRSRVSystemWaitCycles(PVRSRV_DEVICE_CONFIG *psDevConfig, IMG_UINT32 ui32Cycles);

PVRSRV_ERROR PVRSRVSystemInstallDeviceLISR(void *pvOSDevice,
										   IMG_UINT32 ui32IRQ,
										   const IMG_CHAR *pszName,
										   PFN_LISR pfnLISR,
										   void *pvData,
										   IMG_HANDLE *phLISRData);

PVRSRV_ERROR PVRSRVSystemUninstallDeviceLISR(IMG_HANDLE hLISRData);

int PVRSRVGetDriverStatus(void);

/*!
*****************************************************************************
 @Function	: PVRSRVIsBridgeEnabled

 @Description	: Returns whether the given bridge group is enabled

 @Return : IMG_TRUE if the given bridge group is enabled
*****************************************************************************/
static inline IMG_BOOL PVRSRVIsBridgeEnabled(IMG_HANDLE hServices, IMG_UINT32 ui32BridgeGroup)
{
	PVR_UNREFERENCED_PARAMETER(hServices);

#if defined(SUPPORT_RGX)
	if(ui32BridgeGroup >= PVRSRV_BRIDGE_RGX_FIRST)
	{
		return ((1U << (ui32BridgeGroup - PVRSRV_BRIDGE_RGX_FIRST)) &
							gui32RGXBridges) != 0;
	}
	else
#endif /* SUPPORT_RGX */
	{
		return ((1U << (ui32BridgeGroup - PVRSRV_BRIDGE_FIRST)) &
							gui32PVRBridges) != 0;
	}
}

/*!
*****************************************************************************
 @Function	: PVRSRVSystemBIFTilingHeapGetXStride

 @Description	: return the default x-stride configuration for the given
                  BIF tiling heap number

 @Input psDevConfig: Pointer to a device config

 @Input uiHeapNum: BIF tiling heap number, starting from 1

 @Output puiXStride: pointer to x-stride output of the requested heap

*****************************************************************************/
PVRSRV_ERROR
PVRSRVSystemBIFTilingHeapGetXStride(PVRSRV_DEVICE_CONFIG *psDevConfig,
									IMG_UINT32 uiHeapNum,
									IMG_UINT32 *puiXStride);

/*!
*****************************************************************************
 @Function              : PVRSRVSystemBIFTilingGetConfig

 @Description           : return the BIF tiling mode and number of BIF
                          tiling heaps for the given device config

 @Input psDevConfig     : Pointer to a device config

 @Output peBifTilingMode: Pointer to a BIF tiling mode enum

 @Output puiNumHeaps    : pointer to uint to hold number of heaps

*****************************************************************************/
PVRSRV_ERROR
PVRSRVSystemBIFTilingGetConfig(PVRSRV_DEVICE_CONFIG  *psDevConfig,
                               RGXFWIF_BIFTILINGMODE *peBifTilingMode,
                               IMG_UINT32            *puiNumHeaps);

#if defined(SUPPORT_GPUVIRT_VALIDATION)
/*!
***********************************************************************************
 @Function				: PopulateLMASubArenas

 @Description			: Uses the Apphints passed by the client at initialization
						  time to add bases and sizes in the various arenas in the
						  LMA memory

 @Input psDeviceNode	: Pointer to the device node struct containing all the
						  arena information

 @Input ui32OSidMin		: Single dimensional array containing the minimum values
						  for each OSid area

 @Input ui32OSidMax		: Single dimensional array containing the maximum values
						  for each OSid area
***********************************************************************************/

void PopulateLMASubArenas(PVRSRV_DEVICE_NODE *psDeviceNode, IMG_UINT32 aui32OSidMin[GPUVIRT_VALIDATION_NUM_REGIONS][GPUVIRT_VALIDATION_NUM_OS], IMG_UINT32 aui32OSidMax[GPUVIRT_VALIDATION_NUM_REGIONS][GPUVIRT_VALIDATION_NUM_OS]);

#if defined(EMULATOR)
	void SetAxiProtOSid(IMG_UINT32 ui32OSid, IMG_BOOL bState);
	void SetTrustedDeviceAceEnabled(void);
#endif

#endif


/*!
******************************************************************************

 @Function			PVRSRVVzDeviceCreate

 @Description 		Performs additional device creation

 @Return			PVRSRV_ERROR	PVRSRV_OK on success. Otherwise, a PVRSRV_
									error code
 ******************************************************************************/
PVRSRV_ERROR PVRSRVVzDeviceCreate(PVRSRV_DEVICE_NODE *psDeviceNode);

/*!
******************************************************************************

 @Function			PVRSRVVzDeviceDestroy

 @Description 		Performs additional device destruction

 @Return			PVRSRV_ERROR	PVRSRV_OK on success. Otherwise, a PVRSRV_
									error code
 ******************************************************************************/
PVRSRV_ERROR PVRSRVVzDeviceDestroy(PVRSRV_DEVICE_NODE *psDeviceNode);

/*!
******************************************************************************

 @Function			PVRSRVVzRegisterFirmwarePhysHeap

 @Description 		Request to map a physical heap to kernel FW memory context

 @Return			PVRSRV_ERROR	PVRSRV_OK on success. Otherwise, a PVRSRV_
									error code
 ******************************************************************************/
PVRSRV_ERROR PVRSRVVzRegisterFirmwarePhysHeap(PVRSRV_DEVICE_NODE *psDeviceNode,
											  IMG_DEV_PHYADDR sDevPAddr,
											  IMG_UINT64 ui64DevPSize,
											  IMG_UINT32 uiOSID);

/*!
******************************************************************************

 @Function			PVRSRVVzUnregisterFirmwarePhysHeap

 @Description 		Request to unmap a physical heap from kernel FW memory context

 @Return			PVRSRV_ERROR	PVRSRV_OK on success. Otherwise, a PVRSRV_
									error code
 ******************************************************************************/
PVRSRV_ERROR PVRSRVVzUnregisterFirmwarePhysHeap(PVRSRV_DEVICE_NODE *psDeviceNode,
												IMG_UINT32 uiOSID);

#endif /* PVRSRV_H */
