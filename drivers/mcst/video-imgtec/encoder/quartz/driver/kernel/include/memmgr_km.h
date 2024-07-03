/*!
 *****************************************************************************
 *
 * @File       memmgr_km.h
 * @Title      Kernel module memory manager
 * @Description    Kernel mode side of the VXE memory manager
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

#ifndef MEMMGR_KM_H_
#define MEMMGR_KM_H_

#include "img_types.h"
#include "img_errors.h"
#include <sysmem_utils.h>

/*
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

typedef struct KM_DEVICE_BUFFER_TAG
{
	IMG_HANDLE hMemoryRegionID;
	IMG_HANDLE talmmuHandle;

	SYSBRG_UINT64	ui64umToken;
	SYSBRG_UINT64	ui64DevPhysAddr;	/* Offset from start of Frame buffer to surface */

	IMG_VOID *pvKmAddress;		/* Linear Surface Address */
	IMG_UINT32	ui32Size;

	IMG_HANDLE sysMemHandle;
	IMG_HANDLE hMMUContext;

	IMG_UINT32 bufferId;
} KM_DEVICE_BUFFER;


IMG_BOOL allocMemory(
	IMG_HANDLE pvDevContext,
	IMG_UINT32	ui32Size,
	IMG_UINT32	ui32Alignment,
	IMG_BOOL	bSaveRestore,
	KM_DEVICE_BUFFER	**ppMemInfo,
        IMG_UINT32 mapping);

IMG_BOOL allocGenericMemory(
	IMG_UINT32			ui32Size,
	KM_DEVICE_BUFFER	**ppMemoryInfo,
	IMG_BOOL			allocMemInfo,
        IMG_UINT32 mapping);

IMG_BOOL allocNonMMUMemory(
	IMG_HANDLE	pvDevContext,
	IMG_UINT32	ui32Size,
	IMG_UINT32	ui32Alignment,
	IMG_BOOL	bSaveRestore,
	KM_DEVICE_BUFFER	**ppMemInfo,
        IMG_UINT32      mapping);

IMG_BOOL freeMemory(KM_DEVICE_BUFFER **ppMemoryInfo);

IMG_BOOL freeMemoryNonMMU(KM_DEVICE_BUFFER **ppMemoryInfo);

IMG_PVOID getKMAddress(KM_DEVICE_BUFFER *pMemoryInfo);

IMG_VOID writeMemoryRef(
	IMG_HANDLE                      hRegMemSpaceId,
    IMG_UINT32                      ui32Offset,
    IMG_HANDLE                      hRefDeviceMem,
    IMG_UINT32                      ui32RefOffset);

IMG_VOID writeMemoryRefNoMMU(
	IMG_HANDLE                      hMemSpaceId,
    IMG_UINT32                      ui32Offset,
    IMG_HANDLE                      hRefDeviceMem,
    IMG_UINT32                      ui32RefOffset);


#ifndef SYSBRG_NO_BRIDGING
#define updateDeviceMemory(memoryInfo)     SYSMEMU_UpdateMemory((memoryInfo)->sysMemHandle, CPU_TO_DEV)
#define updateDeviceMemoryRegion(x, y, z)  SYSMEMU_UpdateMemory((memoryInfo)->sysMemHandle, CPU_TO_DEV)
#define updateHostMemory(memoryInfo)       SYSMEMU_UpdateMemory((memoryInfo)->sysMemHandle, DEV_TO_CPU)
#define updateHostMemoryRegion(x, y, z)    SYSMEMU_UpdateMemory((memoryInfo)->sysMemHandle, DEV_TO_CPU)
#define COMM_PdumpComment(text)
#define updateNonMMUDeviceMemory(memoryInfo) SYSMEMU_UpdateMemory((memoryInfo)->sysMemHandle, CPU_TO_DEV)
#else
IMG_BOOL updateDeviceMemory(KM_DEVICE_BUFFER *pMemoryInfo);
#define updateDeviceMemoryRegion(x, y, z)	UpdateDeviceMemoryRegion(x, y, z) // not used yet in non brg
IMG_BOOL updateHostMemory(KM_DEVICE_BUFFER *pMemoryInfo);
#define updateHostMemoryRegion(x, y, z) UpdateHostMemoryRegion(x, y, z) // not used yet in non brg

#include "memmgr_um.h"
#endif


IMG_BOOL MMUDeviceMemoryInitialise(IMG_HANDLE pvDevContext);

IMG_BOOL MMUDeviceMemoryHWSetup(IMG_HANDLE pvDevContext);

IMG_VOID MMDeviceMemoryDeInitialise(IMG_HANDLE pvDevContext);


IMG_BOOL QUARTZKM_MMUFlushMMUTableCache(IMG_HANDLE pvDevContext);


/**
* \fn QUARTZ_KM_CreateMutex
* \brief Create a mutext 
**/
IMG_RESULT QUARTZ_KM_CreateMutex(IMG_HANDLE *  phMutexHandle);

/**
* \fn QUARTZ_KM_DestroyMutex
* \brief Destroy a mutext 
**/
IMG_VOID QUARTZ_KM_DestroyMutex(IMG_HANDLE  hMutexHandle);

/**
* \fn QUARTZ_KM_LockMutex
* \brief  
* \param hMutexHandle handle of the MUTEX to lock
**/
#if defined(IMG_KERNEL_MODULE)
#define QUARTZ_KM_LockMutex(hMutexHandle, subclass) mutex_lock_nested(hMutexHandle, subclass);
#else
IMG_VOID QUARTZ_KM_LockMutex(IMG_HANDLE  hMutexHandle, IMG_UINT subclass);
#endif

/**
* \fn QUARTZ_KM_UnlockMutex
* \brief  
* \param hMutexHandle handle of the MUTEX to lock
**/
#if defined(IMG_KERNEL_MODULE)
#define QUARTZ_KM_UnlockMutex(hMutexHandle) mutex_unlock(hMutexHandle);
#else
IMG_VOID QUARTZ_KM_UnlockMutex(IMG_HANDLE  hMutexHandle);
#endif



#endif /* MEMMGR_KM_H_ */



