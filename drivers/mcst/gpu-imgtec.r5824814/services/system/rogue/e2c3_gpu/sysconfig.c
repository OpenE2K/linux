/*************************************************************************/ /*!
@File
@Title          System Configuration
@Copyright      Copyright (c) Imagination Technologies Ltd. All Rights Reserved
@Copyright      Copyright (c) MCST
@Description    System Configuration functions
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

#include <linux/version.h>

#include "sysinfo.h"

#include "pvrsrv.h"
#include "pvrsrv_device.h"
#include "rgxdevice.h"
#include "syscommon.h"
#include "allocmem.h"
#include "pvr_debug.h"

#include "e2c3_gpu_drv.h"

#include <linux/platform_device.h>
#include <linux/dma-mapping.h>
#include <linux/iommu.h>
#include <linux/dma-direct.h>

#define SYS_RGX_ACTIVE_POWER_LATENCY_MS (10)

#if defined(SUPPORT_LINUX_DVFS) || defined(SUPPORT_PDVFS)

/* Dummy DVFS configuration used purely for testing purposes */

static const IMG_OPP asOPPTable[] = {
#if 0
	/*   uV        Hz  */
/*
Disabled freqs:
	{  800000,1000000000},
	{  800000, 941000000},
	{  800000, 889000000},
	{  800000, 842000000},
*/
	{  800000, 800000000}, /* Maximum traget freq in silicon */
	{  800000, 762000000}, /* Info in Bug 109159 */
	{  800000, 727000000},
	{  800000, 696000000},
	{  800000, 667000000},
	{  800000, 640000000},
	{  800000, 615000000},
	{  800000, 593000000},
	{  800000, 571000000},
	{  800000, 552000000},
	{  800000, 533000000},
	{  800000, 516000000},
	{  800000, 500000000},
	{  800000, 471000000},
	{  800000, 444000000},
	{  800000, 421000000},
	{  800000, 400000000},
/*
Disabled freqs:
	{  800000, 381000000},
	{  800000, 364000000},
	{  800000, 348000000},
	{  800000, 333000000},
	{  800000, 320000000},
	{  800000, 308000000},
	{  800000, 296000000},
	{  800000, 286000000},
	{  800000, 276000000},
	{  800000, 267000000},
	{  800000, 258000000},
*/
#else
	{ 1000000, 2500000 }, /* FPGA prototype reality */
#endif
};

#define LEVEL_COUNT (sizeof(asOPPTable) / sizeof(IMG_OPP))

static void SetFrequency(IMG_UINT32 ui32Frequency)
{
	PVR_DPF((PVR_DBG_WARNING, "SetFrequency %u", ui32Frequency));
}

static void SetVoltage(IMG_UINT32 ui32Voltage)
{
	PVR_DPF((PVR_DBG_WARNING, "SetVoltage %u", ui32Voltage));
}

#endif

/*
 * CPU to Device physical address translation
 */
static void UMAPhysHeapCpuPAddrToDevPAddr(IMG_HANDLE hPrivData,
					  IMG_UINT32 ui32NumOfAddr,
					  IMG_DEV_PHYADDR *psDevPAddr,
					  IMG_CPU_PHYADDR *psCpuPAddr)
{
	/* Not implemented/used */
	BUG();
}

/*
 * Device to CPU physical address translation
 */
static void UMAPhysHeapDevPAddrToCpuPAddr(IMG_HANDLE hPrivData,
					  IMG_UINT32 ui32NumOfAddr,
					  IMG_CPU_PHYADDR *psCpuPAddr,
					  IMG_DEV_PHYADDR *psDevPAddr)
{
	PVRSRV_DEVICE_CONFIG *psDevConfig = hPrivData;
	struct device *dev = (struct device *)psDevConfig->pvOSDevice;
	struct iommu_domain *dom = NULL;
	IMG_UINT32 ui32Idx;

	if (device_iommu_mapped(dev)) {
		dom = iommu_get_domain_for_dev(dev);
		BUG_ON(!dom);
	}

	for (ui32Idx = 0; ui32Idx < ui32NumOfAddr; ++ui32Idx)
	{
		IMG_UINT64 va = psDevPAddr[ui32Idx].uiAddr;
		IMG_UINT64 pa = dom ? iommu_iova_to_phys(dom, va) :
				dma_to_phys(dev, va);
		psCpuPAddr[ui32Idx].uiAddr = pa;
	}
}

static PHYS_HEAP_FUNCTIONS gsPhysHeapFuncs = {
	.pfnCpuPAddrToDevPAddr = UMAPhysHeapCpuPAddrToDevPAddr,
	.pfnDevPAddrToCpuPAddr = UMAPhysHeapDevPAddrToCpuPAddr,
};

static PHYS_HEAP_REGION gsPhysHeapRegion = {
	.sStartAddr.uiAddr = 0,
	.sCardBase.uiAddr = 0,
	.uiSize = 0,
	.hPrivData = NULL,
};

static PHYS_HEAP_CONFIG gsPhysHeapConfig = {
	.ui32PhysHeapID = 0,
	.pszPDumpMemspaceName = "SYSMEM",
	.eType = PHYS_HEAP_TYPE_UMA,
	.psMemFuncs = &gsPhysHeapFuncs,
	.pasRegions = &gsPhysHeapRegion,
	.ui32NumOfRegions = 1,
	.hPrivData = NULL,
};

typedef struct _SYS_DATA_ SYS_DATA;

struct _SYS_DATA_ {
	struct platform_device *pdev;

	struct e2c3_gpu_rogue_platform_data *pdata;

	struct resource *registers;
};

static void DeviceConfigDestroy(PVRSRV_DEVICE_CONFIG *psDevConfig)
{
	OSFreeMem(psDevConfig);
}

static PVRSRV_ERROR DeviceConfigCreate(SYS_DATA *psSysData,
				       PVRSRV_DEVICE_CONFIG **ppsDevConfigOut)
{
	PVRSRV_DEVICE_CONFIG *psDevConfig;
	RGX_DATA *psRGXData;
	RGX_TIMING_INFORMATION *psRGXTimingInfo;

	psDevConfig = OSAllocZMem(sizeof(*psDevConfig) + sizeof(*psRGXData) +
				  sizeof(*psRGXTimingInfo));
	if (!psDevConfig) {
		return PVRSRV_ERROR_OUT_OF_MEMORY;
	}

	psRGXData =
		(RGX_DATA *)IMG_OFFSET_ADDR(psDevConfig, sizeof(*psDevConfig));
	psRGXTimingInfo = (RGX_TIMING_INFORMATION *)IMG_OFFSET_ADDR(
		psRGXData, sizeof(*psRGXData));

	/* Setup RGX specific timing data */
	psRGXTimingInfo->ui32CoreClockSpeed = 800000000;
	psRGXTimingInfo->bEnableActivePM = IMG_FALSE;
	psRGXTimingInfo->bEnableRDPowIsland = IMG_FALSE;
	psRGXTimingInfo->ui32ActivePMLatencyms =
		SYS_RGX_ACTIVE_POWER_LATENCY_MS;

	/* Set up the RGX data */
	psRGXData->psRGXTimingInfo = psRGXTimingInfo;

	/* Setup the device config */
	psDevConfig->pvOSDevice = &psSysData->pdev->dev;
	psDevConfig->pszName = "e2c3-gpu";
	psDevConfig->pszVersion = NULL;

	psDevConfig->sRegsCpuPBase.uiAddr = psSysData->registers->start;
	psDevConfig->ui32RegsSize =
		(IMG_UINT32)resource_size(psSysData->registers);

	psDevConfig->ui32IRQ = 0;

	if (NATIVE_IS_MACHINE_SIM) {
		/* simulator does not support snoops */
		psDevConfig->eCacheSnoopingMode = PVRSRV_DEVICE_SNOOP_NONE;
	} else {
		psDevConfig->eCacheSnoopingMode = PVRSRV_DEVICE_SNOOP_CPU_ONLY;
	}

	/* Device's physical heaps */
	psDevConfig->pasPhysHeaps = &gsPhysHeapConfig;
	BUG_ON(gsPhysHeapConfig.hPrivData);
	gsPhysHeapConfig.hPrivData = psDevConfig;
	psDevConfig->ui32PhysHeapCount = 1;

	/* Device's physical heap IDs */
	psDevConfig->aui32PhysHeapID[PVRSRV_DEVICE_PHYS_HEAP_GPU_LOCAL] = 0;
	psDevConfig->aui32PhysHeapID[PVRSRV_DEVICE_PHYS_HEAP_CPU_LOCAL] = 0;
	psDevConfig->aui32PhysHeapID[PVRSRV_DEVICE_PHYS_HEAP_FW_LOCAL] = 0;
	psDevConfig->aui32PhysHeapID[PVRSRV_DEVICE_PHYS_HEAP_EXTERNAL] = 0;

	/* Only required for LMA but having this always set shouldn't be a problem */
	psDevConfig->bDevicePA0IsValid = IMG_TRUE;

	psDevConfig->hDevData = psRGXData;
	psDevConfig->hSysData = psSysData;

	*ppsDevConfigOut = psDevConfig;

	return PVRSRV_OK;
}

PVRSRV_ERROR SysDevInit(void *pvOSDevice, PVRSRV_DEVICE_CONFIG **ppsDevConfig)
{
	PVRSRV_DEVICE_CONFIG *psDevConfig;
	SYS_DATA *psSysData;
	resource_size_t uiRegistersSize;
	PVRSRV_ERROR eError;
	int err = 0;

	PVR_ASSERT(pvOSDevice);

	psSysData = OSAllocZMem(sizeof(*psSysData));
	if (psSysData == NULL) {
		return PVRSRV_ERROR_OUT_OF_MEMORY;
	}

	psSysData->pdev = to_platform_device((struct device *)pvOSDevice);
	psSysData->pdata = psSysData->pdev->dev.platform_data;

	dma_set_mask(pvOSDevice, DMA_BIT_MASK(40));

	err = e2c3_gpu_enable(psSysData->pdev->dev.parent);
	if (err) {
		PVR_DPF((PVR_DBG_ERROR, "%s: Failed to enable PCI device (%d)",
			 __func__, err));
		eError = PVRSRV_ERROR_PCI_CALL_FAILED;
		goto ErrFreeSysData;
	}

	psSysData->registers = platform_get_resource_byname(
		psSysData->pdev, IORESOURCE_MEM, "rogue-regs");
	if (!psSysData->registers) {
		PVR_DPF((PVR_DBG_ERROR,
			 "%s: Failed to get Rogue register information",
			 __func__));
		eError = PVRSRV_ERROR_PCI_REGION_UNAVAILABLE;
		goto ErrorDevDisable;
	}

	/* Check the address range is large enough. */
	uiRegistersSize = resource_size(psSysData->registers);
	if (uiRegistersSize < E2C3_GPU_RGX_REG_REGION_SIZE) {
		PVR_DPF((
			PVR_DBG_ERROR,
			"%s: Rogue register region isn't big enough (was %pa, required 0x%08x)",
			__func__, &uiRegistersSize,
			E2C3_GPU_RGX_REG_REGION_SIZE));

		eError = PVRSRV_ERROR_PCI_REGION_TOO_SMALL;
		goto ErrorDevDisable;
	}

	/* Reserve the address range */
	if (!request_mem_region(psSysData->registers->start,
				resource_size(psSysData->registers),
				SYS_RGX_DEV_NAME)) {
		PVR_DPF((PVR_DBG_ERROR,
			 "%s: Rogue register memory region not available",
			 __func__));
		eError = PVRSRV_ERROR_PCI_CALL_FAILED;

		goto ErrorDevDisable;
	}

	eError = DeviceConfigCreate(psSysData, &psDevConfig);
	if (eError != PVRSRV_OK) {
		goto ErrorReleaseMemRegion;
	}

#if defined(SUPPORT_LINUX_DVFS) || defined(SUPPORT_PDVFS)
	/* Dummy DVFS configuration used purely for testing purposes */
	psDevConfig->sDVFS.sDVFSDeviceCfg.pasOPPTable = asOPPTable;
	psDevConfig->sDVFS.sDVFSDeviceCfg.ui32OPPTableSize = LEVEL_COUNT;
	psDevConfig->sDVFS.sDVFSDeviceCfg.pfnSetFrequency = SetFrequency;
	psDevConfig->sDVFS.sDVFSDeviceCfg.pfnSetVoltage = SetVoltage;
#endif
#if defined(SUPPORT_LINUX_DVFS)
	psDevConfig->sDVFS.sDVFSDeviceCfg.ui32PollMs = 1000;
	psDevConfig->sDVFS.sDVFSDeviceCfg.bIdleReq = IMG_TRUE;
	psDevConfig->sDVFS.sDVFSGovernorCfg.ui32UpThreshold = 90;
	psDevConfig->sDVFS.sDVFSGovernorCfg.ui32DownDifferential = 10;
#endif

	*ppsDevConfig = psDevConfig;

	return PVRSRV_OK;

ErrorReleaseMemRegion:
	release_mem_region(psSysData->registers->start,
			   resource_size(psSysData->registers));
ErrorDevDisable:
	e2c3_gpu_disable(psSysData->pdev->dev.parent);
ErrFreeSysData:
	OSFreeMem(psSysData);
	return eError;
}

void SysDevDeInit(PVRSRV_DEVICE_CONFIG *psDevConfig)
{
	SYS_DATA *psSysData = (SYS_DATA *)psDevConfig->hSysData;

	DeviceConfigDestroy(psDevConfig);

	release_mem_region(psSysData->registers->start,
			   resource_size(psSysData->registers));
	e2c3_gpu_disable(psSysData->pdev->dev.parent);

	OSFreeMem(psSysData);
}

PVRSRV_ERROR SysDebugInfo(PVRSRV_DEVICE_CONFIG *psDevConfig,
			  DUMPDEBUG_PRINTF_FUNC *pfnDumpDebugPrintf,
			  void *pvDumpDebugFile)
{
	PVR_UNREFERENCED_PARAMETER(psDevConfig);
	PVR_UNREFERENCED_PARAMETER(pfnDumpDebugPrintf);

	PVR_DUMPDEBUG_LOG("------[ %s system debug ]------", SYS_RGX_DEV_NAME);
	PVR_DUMPDEBUG_LOG("TODO: (temp, pll state and other)");

	return PVRSRV_OK;
}

typedef struct {
	struct device *psDev;
	void *pvData;
	PFN_LISR pfnLISR;
} LISR_DATA;

static void E2C3_GPU_InterruptHandler(void *pvData)
{
	LISR_DATA *psLISRData = pvData;
	psLISRData->pfnLISR(psLISRData->pvData);
}

PVRSRV_ERROR SysInstallDeviceLISR(IMG_HANDLE hSysData, IMG_UINT32 ui32IRQ,
				  const IMG_CHAR *pszName, PFN_LISR pfnLISR,
				  void *pvData, IMG_HANDLE *phLISRData)
{
	SYS_DATA *psSysData = (SYS_DATA *)hSysData;
	LISR_DATA *psLISRData;
	PVRSRV_ERROR eError;
	int err;

	PVR_UNREFERENCED_PARAMETER(ui32IRQ);

	psLISRData = OSAllocZMem(sizeof(*psLISRData));
	if (!psLISRData) {
		eError = PVRSRV_ERROR_OUT_OF_MEMORY;
		goto err_out;
	}

	psLISRData->pfnLISR = pfnLISR;
	psLISRData->pvData = pvData;
	psLISRData->psDev = psSysData->pdev->dev.parent;

	err = e2c3_gpu_set_interrupt_handler(
		psLISRData->psDev, E2C3_GPU_InterruptHandler, psLISRData);
	if (err) {
		PVR_DPF((PVR_DBG_ERROR,
			 "%s: e2c3_gpu_set_interrupt_handler() failed (%d)",
			 __func__, err));
		eError = PVRSRV_ERROR_UNABLE_TO_INSTALL_ISR;
		goto err_free_data;
	}

	err = e2c3_gpu_enable_interrupt(psLISRData->psDev);
	if (err) {
		PVR_DPF((PVR_DBG_ERROR,
			 "%s: e2c3_gpu_enable_interrupt() failed (%d)",
			 __func__, err));
		eError = PVRSRV_ERROR_UNABLE_TO_INSTALL_ISR;
		goto err_unset_interrupt_handler;
	}

	*phLISRData = psLISRData;
	eError = PVRSRV_OK;

	PVR_TRACE(("Installed device LISR " IMG_PFN_FMTSPEC, pfnLISR));

err_out:
	return eError;
err_unset_interrupt_handler:
	e2c3_gpu_set_interrupt_handler(psLISRData->psDev, NULL, NULL);
err_free_data:
	OSFreeMem(psLISRData);
	goto err_out;
}

PVRSRV_ERROR SysUninstallDeviceLISR(IMG_HANDLE hLISRData)
{
	LISR_DATA *psLISRData = (LISR_DATA *)hLISRData;
	int err;

	err = e2c3_gpu_disable_interrupt(psLISRData->psDev);
	if (err) {
		PVR_DPF((PVR_DBG_ERROR,
			 "%s: e2c3_gpu_disable_interrupt() failed (%d)",
			 __func__, err));
	}

	err = e2c3_gpu_set_interrupt_handler(psLISRData->psDev, NULL, NULL);
	if (err) {
		PVR_DPF((PVR_DBG_ERROR,
			 "%s: e2c3_gpu_set_interrupt_handler() failed (%d)",
			 __func__, err));
	}

	PVR_TRACE(("Uninstalled device LISR " IMG_PFN_FMTSPEC,
		   psLISRData->pfnLISR));

	OSFreeMem(psLISRData);

	return PVRSRV_OK;
}
