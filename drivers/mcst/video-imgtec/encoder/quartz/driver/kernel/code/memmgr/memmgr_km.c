/*!
 *****************************************************************************
 *
 * @File       memmgr_km.c
 * @Title      Kernel module memory manager
 * @Description    Implementation of the kernel mode side of the VXE memory manager
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

#include "tal.h"
#include "rman_api.h"
#include "img_types.h"
#include "img_errors.h"
#include "sysmem_utils.h"
#include "talmmu_api.h"

#include "memmgr_api_quartz.h"
#include "memmgr_km.h"
#include "quartz_mmu.h"
#include "page_alloc_km.h"
#include "sysos_api_km.h"
#include "sysdev_utils.h"

//#define DEBUG_PA

// Debug Page Alloc leaks


#include <vxe_KM.h>

#define RMAN_SOCKETS_ID 0x101
#define RMAN_BUFFERS_ID 0x102


/*!
 *******************************************************************************
 * \fn allocateMemoryHelper
 *******************************************************************************
 * \brief Wraps page allocation and mapping, used by alloc functions
 * \params [in] psDevContext Device context to which this allocation is attached
 * \params [in] ui32Size Size of the device memory to allocate
 * \params [in] ui32Alignment Alignement constraint
 * \params [in] ui32Heap Heap to use for the allocation
 * \params [in] bSaveRestore Should this device memory saved on power transitions
 * \params [in] pMemInfo Pointer on KM_DEVICE_BUFFER allocated by the caller, to be filled here
 * \params [in] tileSensetive Is this buffer tiled or not
 * \params [in] mem_attrib SYSMEM attribute to use
 * \return IMG_TRUE on normal completion, IMG_FALSE if one allocation fails
 *
 */
static IMG_BOOL allocateMemoryHelper(
	VXE_KM_DEVCONTEXT	*psDevContext,
	IMG_UINT32			ui32Size,
	IMG_UINT32			ui32Alignment,
	IMG_UINT32  		ui32Heap,
	IMG_BOOL			bSaveRestore,
	KM_DEVICE_BUFFER	*pMemInfo,
	IMG_BOOL 			tileSensitive,
	SYS_eMemAttrib 		mem_attrib,
        IMG_UINT32              mapping)
{
	IMG_RESULT		result;
	IMG_PHYSADDR	paAddr;

	/* We would not want a zero sized allocation */
	if (0 == ui32Size)
	{
		IMG_ASSERT(ui32Size != 0);
		return IMG_FALSE;
	}

	/* If tileSensitive then change the alignment and the heapID, otherwise .. don't change the params. */
	if(tileSensitive && psDevContext->sDevSpecs.bUseTiledMemory)
	{
		ui32Alignment = 512 << psDevContext->sDevSpecs.asMMU_HeapInfo[0].ui32XTileStride;
		ui32Heap = 0;

		ui32Alignment <<=4;

		ui32Size = (ui32Size + ui32Alignment - 1) & ~(ui32Alignment - 1);
	}

	/* Allocate device memory. */
	/* We always for to be at least page aligned. */
	if ( ui32Alignment >= SYS_MMU_PAGE_SIZE )
	{
		/* Alignment requirement specified by user is larger than page size - make sure alignment	*/
		/* is a multiple of page size.																*/
		IMG_ASSERT ( (ui32Alignment % SYS_MMU_PAGE_SIZE) == 0 );
		if ((ui32Alignment % SYS_MMU_PAGE_SIZE) != 0)
		{
			return IMG_FALSE;
		}
	}
	else
	{
	/* Alignment requirement specified by user is smaller than page size - make sure page size	*/
	/* is a multiple of alignment.																*/
	if ( ui32Alignment != 0 )
	{
		IMG_ASSERT ( (SYS_MMU_PAGE_SIZE % ui32Alignment) == 0 );
		if ((SYS_MMU_PAGE_SIZE % ui32Alignment) != 0)
		{
			return IMG_FALSE;
		}
	}

	/* Now round up alignment to one page */
	ui32Alignment = SYS_MMU_PAGE_SIZE;
	}

	/* Round size up to next multiple of physical pages */
	if (( ui32Size % SYS_MMU_PAGE_SIZE ) != 0)
	{
		ui32Size = ((ui32Size / SYS_MMU_PAGE_SIZE) + 1) * SYS_MMU_PAGE_SIZE;
	}

	/* Before entering the SYSMEM and TAL layers, guarantee thread-safe access [allocateMemoryHelper is called by all alloc* functions] */
	QUARTZ_KM_LockMutex(psDevContext->sDevSpecs.g_hMemmgrMutex, MTX_SUBCLASS_MEMMGR);

	result = SYSMEMU_AllocatePages(ui32Size,
		mem_attrib,
		psDevContext->hSysDevHandle->sMemPool,
		&pMemInfo->sysMemHandle,
		IMG_NULL);
	IMG_ASSERT(result == IMG_SUCCESS);
	if (IMG_SUCCESS != result)
	{
		/* Cannot allocate device memory using memory model registered with SYSDEV, this is a fatal error */
		QUARTZ_KM_UnlockMutex(psDevContext->sDevSpecs.g_hMemmgrMutex);
		return IMG_FALSE;
	}

	// Currently the way the code is structured we can only turn off KM mapping
	// if UM mapping is also not requested
	if ( (!(mapping & IMG_MAP_HOST_KM)) && (!(mapping & IMG_MAP_HOST_UM)))
	{
		// if not mapping kernel then pass in dummy non-aligned address
		result = TALMMU_DevMemMapExtMem1(
                psDevContext->sDevSpecs.hQuartz_CoreMMUContext.Quartz_Core_mmu_context,
                psDevContext->sDevSpecs.asMMU_HeapInfo[ui32Heap].ui32HeapId,
                ui32Size,
                ui32Alignment,
#ifdef __LCC__
                (void *)0x1000,
#else
                0x1000,
#endif
                pMemInfo->sysMemHandle,
                &pMemInfo->talmmuHandle);
		IMG_ASSERT(result == IMG_SUCCESS && pMemInfo->talmmuHandle != NULL);

		pMemInfo->pvKmAddress = IMG_NULL;
	}
	else
	{
		result = SYSMEMU_GetCpuKmAddr(&(pMemInfo->pvKmAddress), pMemInfo->sysMemHandle);
		IMG_ASSERT(result == IMG_SUCCESS);
		if (IMG_SUCCESS != result)
		{
			/* Cannot obtain kernel virtual address */
			if (pMemInfo->sysMemHandle != IMG_NULL)
			{
				SYSMEMU_FreePages(pMemInfo->sysMemHandle);
			}

			QUARTZ_KM_UnlockMutex(psDevContext->sDevSpecs.g_hMemmgrMutex);
			return IMG_FALSE;
		}

		/* Allocate device "virtual" memory. */
		result = TALMMU_DevMemMapExtMem1(
		psDevContext->sDevSpecs.hQuartz_CoreMMUContext.Quartz_Core_mmu_context,
                psDevContext->sDevSpecs.asMMU_HeapInfo[ui32Heap].ui32HeapId,
                ui32Size,
                ui32Alignment,
                pMemInfo->pvKmAddress,
                pMemInfo->sysMemHandle,
                &pMemInfo->talmmuHandle);
		IMG_ASSERT(result == IMG_SUCCESS && pMemInfo->talmmuHandle != NULL);
	}

	/* Further calls are just read access, so we can release the mutex */
	QUARTZ_KM_UnlockMutex(psDevContext->sDevSpecs.g_hMemmgrMutex);

	if (IMG_SUCCESS != result || NULL == pMemInfo->talmmuHandle)
	{
		if (pMemInfo->sysMemHandle != IMG_NULL)
		{
			SYSMEMU_FreePages(pMemInfo->sysMemHandle);
		}

		return IMG_FALSE;
	}

	if ( (!(mapping & IMG_MAP_HOST_KM)) && (!(mapping & IMG_MAP_HOST_UM)))
	{
		paAddr = IMG_NULL;
	}
	else
	{
		paAddr = SYSMEMU_CpuKmAddrToCpuPAddr(psDevContext->hSysDevHandle->sMemPool, pMemInfo->pvKmAddress);
		pMemInfo->ui64umToken = paAddr;
#ifdef CONFIG_MCST
	paAddr = SYSMEMU_CpuKmAddrToDevPAddr(pMemInfo->sysMemHandle,
					     pMemInfo->pvKmAddress);
#else
		paAddr = SYSDEVU_CpuPAddrToDevPAddr(psDevContext->hSysDevHandle, paAddr);
#endif
	}

	/* If the map call failed, we free the pages and the caller will free pMemInfo */
	if (result != IMG_SUCCESS)
	{
		if (pMemInfo->sysMemHandle != IMG_NULL)
		{
			SYSMEMU_FreePages(pMemInfo->sysMemHandle);
		}
		return IMG_FALSE;
	}

	pMemInfo->ui64DevPhysAddr = paAddr;
	pMemInfo->ui32Size = ui32Size;
	pMemInfo->bufferId = 0;
	/* Store a reference on the MMU context because it will be required for the free */
	pMemInfo->hMMUContext = (void*)&psDevContext->sDevSpecs;


	return IMG_TRUE;
}

/*!
 *******************************************************************************
 * \fn freeMemoryHelper
 *******************************************************************************
 * \brief Cleanup wrapper called either directly or through destruction callbacks
 * \params [in] pMemInfo Pointer on KM_DEVICE_BUFFER allocated by the caller, to be free'd here
 * \return IMG_TRUE on normal completion, IMG_FALSE if one allocation fails
 *
 */
static IMG_BOOL freeMemoryHelper(KM_DEVICE_BUFFER *pMemInfo)
{
	VXE_KM_DEVICE_SPECIFIC_INFO *psDevSpec = (VXE_KM_DEVICE_SPECIFIC_INFO *)pMemInfo->hMMUContext;

	if (!pMemInfo->talmmuHandle)
		return IMG_FALSE;


	QUARTZ_KM_LockMutex(psDevSpec->g_hMemmgrMutex, MTX_SUBCLASS_MEMMGR); // _free_Memory (callback associated with the buffer resource) comes back here, same for bridging direct call

	/* Free the memory. */
	TALMMU_DevMemFree1(pMemInfo->talmmuHandle);

	if (pMemInfo->sysMemHandle != IMG_NULL)
	{
		SYSMEMU_FreePages(pMemInfo->sysMemHandle);
	}

	QUARTZ_KM_UnlockMutex(psDevSpec->g_hMemmgrMutex);

	return IMG_TRUE;
}



/*!
 *******************************************************************************
 * \fn releaseExtMemoryHelper
 *******************************************************************************
 * \brief Release wrapper called either directly or through destruction callbacks
 * \param [in] pMemInfo KM_DEVICE_BUFFER representing to external allocation to be released
 * \return IMG_TRUE on normal completion, IMG_FALSE if one allocation fails
 *
 */
static IMG_BOOL releaseExtMemoryHelper(KM_DEVICE_BUFFER *pMemInfo)
{
	IMG_RESULT result;
	VXE_KM_DEVICE_SPECIFIC_INFO *psDevSpecs = (VXE_KM_DEVICE_SPECIFIC_INFO *)pMemInfo->hMMUContext;


	/* Unmap the page and update page table */
	QUARTZ_KM_LockMutex(psDevSpecs->g_hMemmgrMutex, MTX_SUBCLASS_MEMMGR);

	result = TALMMU_DevMemFree1(pMemInfo->talmmuHandle);
	QUARTZ_KM_UnlockMutex(psDevSpecs->g_hMemmgrMutex);

	/* Signal an error */
	IMG_ASSERT(result == IMG_SUCCESS);
	if (result != IMG_SUCCESS)
	{
		return IMG_FALSE;
	}

	return IMG_TRUE;
}


/*!
 *******************************************************************************
 * \fn allocateMemoryCommon
 *******************************************************************************
 * \brief Wraps the calls to #allocateMemoryHelper for the other allocation functions
 * \param [in] psDevContext Device context to which the allocation will be attached
 * \param [in] ui32Size Size of the device memory to allocate
 * \param [in] ui32Alignment Alignment constraint
 * \param [in] ui32Heap Heap to use for the allocation
 * \param [in] bSaveRestore Should this device memory saved on power transitions
 * \param [out] ppMemInfo KM_DEVICE_BUFFER returned to the caller, can be allocated here or used
 * \param [in] tileSensetive Is this buffer tiled or not
 * \param [in] allocMemInfo Drives whether <ppMemInfo> shall be allocated or not
 * \return IMG_TRUE on normal completion, IMG_FALSE if one allocation fails
 *
 */
static IMG_BOOL allocateMemoryCommon(
	VXE_KM_DEVCONTEXT	*psDevContext,
	IMG_UINT32			ui32Size,
	IMG_UINT32			ui32Alignment,
	IMG_UINT32  		ui32Heap,
	IMG_BOOL			bSaveRestore,
	KM_DEVICE_BUFFER	**ppMemInfo,
	IMG_BOOL 			tileSensitive,
	IMG_BOOL 			allocMemInfo,
	IMG_UINT32			mapping)
{
	IMG_BOOL result;
	KM_DEVICE_BUFFER *pMemoryInfo;

	if (ui32Size == 0)
	{
		IMG_ASSERT(ui32Size != 0 && "allocateMemoryCommon - Invalid zero size allocation provided");
		return IMG_FALSE;
	}

	if (allocMemInfo)
	{
		pMemoryInfo = (KM_DEVICE_BUFFER *)IMG_MALLOC(sizeof(KM_DEVICE_BUFFER));
	}
	else
	{
		if (!ppMemInfo)
		{
			IMG_ASSERT(ppMemInfo != 0 && "allocateMemoryCommon - Invalid NULL ppMemInfo provided");
			return IMG_FALSE;
		}

		pMemoryInfo = *ppMemInfo;
	}
	IMG_ASSERT(pMemoryInfo != IMG_NULL);
	if(pMemoryInfo == IMG_NULL)
	{
		return IMG_FALSE;
	}
	IMG_MEMSET(pMemoryInfo, 0, sizeof(*pMemoryInfo));

	result = allocateMemoryHelper(psDevContext, ui32Size, ui32Alignment, ui32Heap, bSaveRestore, pMemoryInfo, tileSensitive, (SYS_MEMATTRIB_UNCACHED | SYS_MEMATTRIB_WRITECOMBINE), mapping);
	IMG_ASSERT(result == IMG_TRUE);
	if(result != IMG_TRUE)
	{
		if (allocMemInfo)
		{
			IMG_FREE(pMemoryInfo);
		}
		return IMG_FALSE;
	}

	pMemoryInfo->hMemoryRegionID = psDevContext->sDevSpecs.hSysMemId;

	if (allocMemInfo)
	{
		*ppMemInfo = pMemoryInfo;
	}

	return IMG_TRUE;
}

/*
 * Exposed allocation functions
 */

IMG_BOOL allocMemory(
	IMG_HANDLE			pvDevContext,
	IMG_UINT32			ui32Size,
	IMG_UINT32			ui32Alignment,
	IMG_BOOL			bSaveRestore,
	KM_DEVICE_BUFFER	**ppMemInfo,
	IMG_UINT32			mapping)
{
	if (allocateMemoryCommon((VXE_KM_DEVCONTEXT*)pvDevContext, ui32Size, ui32Alignment, MMU_GENERAL_HEAP_ID, bSaveRestore, ppMemInfo, IMG_FALSE, IMG_TRUE, mapping))
	{
		IMG_VOID *pData = getKMAddress(*ppMemInfo);
		IMG_MEMSET(pData, 0, ui32Size);
		return IMG_TRUE;
	}

	return IMG_FALSE;
}

IMG_BOOL allocNonMMUMemory(
	IMG_HANDLE			pvDevContext,
	IMG_UINT32			ui32Size,
	IMG_UINT32			ui32Alignment,
	IMG_BOOL			bSaveRestore,
	KM_DEVICE_BUFFER	**ppMemInfo,
	IMG_UINT32			mapping)
{
	IMG_UINT32 ui32Result;
	IMG_PHYSADDR paAddr;
	KM_DEVICE_BUFFER *pMemoryInfo;
	VXE_KM_DEVCONTEXT *psDevContext = (VXE_KM_DEVCONTEXT *)pvDevContext;

	if (!pvDevContext)
	{
		IMG_ASSERT(pvDevContext != 0 && "allocMemory - Invalid NULL pvDevContext provided");
		return IMG_FALSE;
	}

	if (!ppMemInfo)
	{
		IMG_ASSERT(ppMemInfo != 0 && "alloMemory - Invalid NULL ppMemInfo provided");
		return IMG_FALSE;
	}

	if (ui32Size == 0)
	{
		IMG_ASSERT(ui32Size != 0 && "allocMemory - Invalid zero size allocation provided");
		return IMG_FALSE;
	}


	pMemoryInfo = (KM_DEVICE_BUFFER*) IMG_MALLOC(sizeof(KM_DEVICE_BUFFER));
	IMG_ASSERT(pMemoryInfo != IMG_NULL);
	if(pMemoryInfo == IMG_NULL)
	{
		*ppMemInfo = IMG_NULL;
		return IMG_FALSE;
	}
	IMG_MEMSET(pMemoryInfo, 0, sizeof(*pMemoryInfo));

	/* Protect the SYSMEM call since MMU is bypassed here */
	QUARTZ_KM_LockMutex(psDevContext->sDevSpecs.g_hMemmgrMutex, MTX_SUBCLASS_MEMMGR);
	ui32Result = SYSMEMU_AllocatePages(
			ui32Size,
			psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.eMemAttrib,
			psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.eMemPool,
			&pMemoryInfo->sysMemHandle,
			(IMG_PHYSADDR **)&(pMemoryInfo->pvKmAddress));
	QUARTZ_KM_UnlockMutex(psDevContext->sDevSpecs.g_hMemmgrMutex);

	IMG_ASSERT(ui32Result == IMG_SUCCESS);
	if (ui32Result != IMG_SUCCESS)
	{
		IMG_FREE(pMemoryInfo);
		*ppMemInfo = pMemoryInfo = NULL;
		return IMG_FALSE;
	}


	paAddr = SYSMEMU_CpuKmAddrToCpuPAddr(psDevContext->hSysDevHandle->sMemPool, pMemoryInfo->pvKmAddress);
	paAddr = SYSDEVU_CpuPAddrToDevPAddr(psDevContext->hSysDevHandle, paAddr);

	pMemoryInfo->ui64DevPhysAddr = paAddr;
	pMemoryInfo->talmmuHandle = pMemoryInfo;
	pMemoryInfo->hMMUContext = (void*)&psDevContext->sDevSpecs;

	*ppMemInfo = pMemoryInfo;
	return IMG_TRUE;
}

IMG_BOOL freeMemory(KM_DEVICE_BUFFER **ppMemoryInfo)
{
	if (!ppMemoryInfo)
		return IMG_FALSE;

	if (!*ppMemoryInfo)
		return IMG_FALSE;

	if (!freeMemoryHelper(*ppMemoryInfo))
		return IMG_FALSE;

	IMG_FREE(*ppMemoryInfo);
	*ppMemoryInfo = IMG_NULL;
	return IMG_TRUE;
}

IMG_BOOL freeMemoryNonMMU(KM_DEVICE_BUFFER **ppMemoryInfo)
{
	KM_DEVICE_BUFFER *pMemoryInfo = *ppMemoryInfo;
	VXE_KM_DEVICE_SPECIFIC_INFO *psDevSpecs = (VXE_KM_DEVICE_SPECIFIC_INFO *)pMemoryInfo->hMMUContext;

	QUARTZ_KM_LockMutex(psDevSpecs->g_hMemmgrMutex, MTX_SUBCLASS_MEMMGR);
	SYSMEMU_FreePages(pMemoryInfo->sysMemHandle);
	QUARTZ_KM_UnlockMutex(psDevSpecs->g_hMemmgrMutex);
	*ppMemoryInfo = IMG_NULL;
	return IMG_TRUE;
}


IMG_PVOID getKMAddress(KM_DEVICE_BUFFER *pMemoryInfo)
{
	return pMemoryInfo->pvKmAddress;
}


/*!
 *******************************************************************************
 * \fn writeMemoryRef
 *******************************************************************************
 * \brief Write a device virtual address in a register
 * \params [in] ui32MemSpaceId Handle on the register space
 * \params [in] ui32Offset Register offset in this bank
 * \params [in] hRefDeviceMem KM_DEVICE_BUFFER pointer of which the address is to be written
 * \params [in] ui32RefOffset Offset to add to the written virtual address
 *
 */
IMG_VOID writeMemoryRef(
	IMG_HANDLE                      ui32MemSpaceId,
    IMG_UINT32                      ui32Offset,
    IMG_HANDLE                      hRefDeviceMem,
    IMG_UINT32                      ui32RefOffset)
{
	KM_DEVICE_BUFFER *srcMem;
	IMG_UINT32 devVirtAddress;
	IMG_UINT32 ui32Result;

	srcMem = (KM_DEVICE_BUFFER *)hRefDeviceMem;
	ui32Result = TALMMU_GetDevVirtAddress(srcMem->talmmuHandle, &devVirtAddress);
	IMG_ASSERT(ui32Result == IMG_SUCCESS);
	TALREG_WriteWord32(ui32MemSpaceId, ui32Offset, devVirtAddress + ui32RefOffset);
}

IMG_VOID writeMemoryRefNoMMU(
	IMG_HANDLE                      ui32MemSpaceId,
    IMG_UINT32                      ui32Offset,
    IMG_HANDLE                      hRefDeviceMem,
    IMG_UINT32                      ui32RefOffset)
{
	KM_DEVICE_BUFFER *mem = (KM_DEVICE_BUFFER *)hRefDeviceMem;
	TALREG_WriteWord32(ui32MemSpaceId, ui32Offset, (IMG_UINT32)mem->ui64DevPhysAddr + ui32RefOffset);
}


/*
 * Bridge ..
 */


/*!
 *******************************************************************************
 * \fn MMUDeviceMemoryInitialise
 *******************************************************************************
 * \brief Extract basic MMU settings from the flags and call in #quartz_mmu.c for complete initialisation
 * \params [in] pvDevContext Device context which MMU shall be initialised
 * \return	- IMG_TRUE on normal completion
 * 			- IMG_FALSE if the mutex cannot be created or if MMU can't be configured
 *
 */
IMG_BOOL MMUDeviceMemoryInitialise(IMG_HANDLE pvDevContext)
{
	IMG_UINT32 ui32MMUTileStride;
	VXE_KM_DEVCONTEXT *psDevContext = (VXE_KM_DEVCONTEXT *)pvDevContext;

	if (!pvDevContext)
	{
		IMG_ASSERT(pvDevContext != NULL && "MMUDeviceMemoryInitialise NULL context pointer");
		return IMG_FALSE;
	}

	psDevContext->sDevSpecs.bUseTiledMemory = (psDevContext->sDevSpecs.ui32MMUFlags & MMU_TILED_FLAG)?IMG_TRUE:IMG_FALSE;
	psDevContext->sDevSpecs.bUseExtendedAddressing = (psDevContext->sDevSpecs.ui32MMUFlags & MMU_EXTENDED_ADDR_FLAG)?IMG_TRUE:IMG_FALSE;
	psDevContext->sDevSpecs.bUseSecureFwUpload = (psDevContext->sDevSpecs.ui32MMUFlags & MMU_SECURE_FW_UPLOAD)?IMG_TRUE:IMG_FALSE;
	psDevContext->sDevSpecs.bUseInterleavedTiling = (psDevContext->sDevSpecs.ui32MMUFlags & MMU_TILED_INTERLEAVED)?IMG_TRUE:IMG_FALSE;
	psDevContext->sDevSpecs.bUseAlternateTiling = (psDevContext->sDevSpecs.ui32MMUFlags & MMU_ALT_TILING)?IMG_TRUE:IMG_FALSE;

	/* Memmgr is protected by a mutex for concurrent multi-threaded access */
	if (QUARTZ_KM_CreateMutex(&psDevContext->sDevSpecs.g_hMemmgrMutex) != IMG_SUCCESS)
	{
		IMG_ASSERT(psDevContext->sDevSpecs.g_hMemmgrMutex != NULL);
		/* Kernel null pointer exception should be following soon */
		psDevContext->sDevSpecs.g_hMemmgrMutex = NULL;

		return IMG_FALSE;
	}

	//TALMMU_Initialise(); Called in the following function instead
	// Let's try configuring our MMU space here for now..
	ui32MMUTileStride = 512;
	while (ui32MMUTileStride < psDevContext->sDevSpecs.ui32MMUTileStride)
	{
		ui32MMUTileStride <<= 1;
	}
	/* Update the stride to its 512-aligned version */
	psDevContext->sDevSpecs.ui32MMUTileStride = ui32MMUTileStride;

	return Quartz_Core_MMU_Configure(pvDevContext);
}


/*!
 *******************************************************************************
 * \fn MMUDeviceMemoryHWSetup
 *******************************************************************************
 * \brief Setup page table root directory address
 * \params [in] pvDevContext Device context which table shall be set
 * \return	IMG_TRUE, always
 *
 */
IMG_BOOL MMUDeviceMemoryHWSetup(IMG_HANDLE pvDevContext)
{
	return Quartz_Core_MMU_HWSetup(pvDevContext);
}


/*!
 *******************************************************************************
 * \fn MMDeviceMemoryDeInitialise
 *******************************************************************************
 * \brief Destroy MMU template and mutex protecting memmgr_km layer
 * \params [in] pvDevContext Device context which template shall be destroyed
 *
 */
IMG_VOID MMDeviceMemoryDeInitialise(IMG_HANDLE pvDevContext)
{
	VXE_KM_DEVCONTEXT *psDevContext = (VXE_KM_DEVCONTEXT *)pvDevContext;

	Quartz_Core_MMU_Reset(pvDevContext);

	if (psDevContext->sDevSpecs.g_hMemmgrMutex)
	{
		QUARTZ_KM_DestroyMutex(psDevContext->sDevSpecs.g_hMemmgrMutex);
	}
}


/*!
 *******************************************************************************
 * \fn QUARTZKM_MMUFlushMMUTableCache
 *******************************************************************************
 * \brief Exposed TLB flush facility
 * \params [in] pvDevContext Device context which table shall be free'd
 * \return	#Quartz_Core_MMU_FlushCache return code
 *
 */
IMG_BOOL QUARTZKM_MMUFlushMMUTableCache(IMG_HANDLE pvDevContext)
{
	return Quartz_Core_MMU_FlushCache(pvDevContext);
}

/*!
 *******************************************************************************
 * \fn _free_Memory
 *******************************************************************************
 * \brief Callback triggered for an internally allocated stream buffer linked to a socket object
 * \params [in] params Handle on the memory to be free'd
 *
 */
IMG_VOID _free_Memory(IMG_VOID *params)
{
	KM_DEVICE_BUFFER *pMemInfo = (KM_DEVICE_BUFFER *)params;
	freeMemoryHelper(pMemInfo);
	IMG_FREE(pMemInfo);
}

/*!
 *******************************************************************************
 * \fn _release_ExtMemory
 *******************************************************************************
 * \brief Callback triggered for an externally allocated stream buffer linked to a socket object
 * \params [in] params Handle on the memory to be released
 *
 */
IMG_VOID _release_ExtMemory(IMG_VOID *params)
{
	KM_DEVICE_BUFFER *pMemInfo = (KM_DEVICE_BUFFER *)params;
	releaseExtMemoryHelper(pMemInfo);
	IMG_FREE(pMemInfo);
}

/*!
 *******************************************************************************
 * \fn QUARTZKM_MMUMFreeDeviceMemory
 *******************************************************************************
 * \brief Free device memory corresponding to the buffer id parameter
 * \params bufferId Unique allocation identifier
 * \return IMG_TRUE on normal completion
 * \details
 * Fetch the resource from the stream bucket thanks to the buffer id parameter
 * in order to free it.
 *
 */
IMG_BOOL QUARTZKM_MMUMFreeDeviceMemory(IMG_UINT32 bufferId)
{
	IMG_RESULT result;
	IMG_HANDLE resHandle;
	//KM_DEVICE_BUFFER *pMemInfo = IMG_NULL; // RMAN_FreeResource might already do it
	
	if(!bufferId)
	{
		IMG_ASSERT(bufferId != 0 && "Trying to free a buffer with no id");
		return IMG_FALSE;
	}

	// Stream buffer
	result = RMAN_GetResource(bufferId, RMAN_BUFFERS_ID, IMG_NULL/*(void**)&pMemInfo*/, &resHandle);
	IMG_ASSERT(result == IMG_SUCCESS); // not finding a buffer means it has been free'd already (happens if the socket is closed before all its attached buffer have been free'd)
	if (result != IMG_SUCCESS)
	{
		return IMG_FALSE;
	}

	RMAN_FreeResource(resHandle);

	//freeMemory(&pMemInfo); // Enable this if it turn out free'ing the resource handle destroyed the whole socket bucket

	return IMG_TRUE;
}


/*!
 *******************************************************************************
 * \fn QUARTZKM_StreamMMUMAllocateHeapDeviceMemory
 *******************************************************************************
 * \brief Allocate a buffer and link it to the KM stream object
 * \params [in] ui32StreamId Unique stream id used to access the socket object
 * \params [in] ui32Size Total size of the allocation
 * \params [in] ui32Alignment Alignment for this allocation
 * \params [in] ui32Heap Heap to use
 * \params [in] bSaveRestore Should this buffer be saved on power transitions
 * \params [out] pbufferId Unique id for this buffer
 * \params [out] pui64umToken Content of the KM_DEVICE_BUFFER::ui64umToken
 * \params [out] pui32VirtAddr Device virtual address which the user mode is allowed to see
 * \params [in] tileSensitive Are we allocating a tiled buffer
 * \return IMG_TRUE on normal completion
 * \details
 * Fetch the socket object thanks to its unique id that the UM passed down.
 * If this socket exists, allocate the buffer and register it associated with
 * the stream bucket for future fetching. The user will only ever know about
 * this unique buffer id return after registration.
 *
 */
IMG_BOOL QUARTZKM_StreamMMUMAllocateHeapDeviceMemory(
	IMG_UINT32	ui32StreamId,
	IMG_UINT32	ui32Size,
	IMG_UINT32	ui32Alignment,
	IMG_UINT32  ui32Heap,
	IMG_BOOL	bSaveRestore,
	SYSBRG_POINTER_ARG(IMG_UINT32) pbufferId,
	SYSBRG_POINTER_ARG(IMG_UINT64) pui64umToken,
	SYSBRG_POINTER_ARG(IMG_UINT32) pui32VirtAddr,
	IMG_BOOL tileSensitive,
	IMG_UINT32 mapping)
{
	IMG_RESULT out;
	IMG_BOOL result;
	KM_DEVICE_BUFFER *pMemoryInfo;
	VXE_KM_COMM_SOCKET *pSocket;
	IMG_UINT32 ui32VirtAddr;

	/* Obtain the stream object thanks to the id UM provided */
	out = RMAN_GetResource(ui32StreamId, RMAN_SOCKETS_ID, (IMG_VOID **)&pSocket, IMG_NULL);
	IMG_ASSERT(out == IMG_SUCCESS);
	if (out != IMG_SUCCESS)
	{
		return IMG_FALSE;
	}

	/* Allocate memory handle */
	pMemoryInfo = (KM_DEVICE_BUFFER *)IMG_MALLOC(sizeof(KM_DEVICE_BUFFER));
	IMG_ASSERT(pMemoryInfo != IMG_NULL);
	if(pMemoryInfo == IMG_NULL)
	{
		return IMG_FALSE;
	}
	IMG_MEMSET(pMemoryInfo, 0, sizeof(*pMemoryInfo));

	/* Calls in TALMMU and SYSMEM layers to allocate the device memory */
	result = allocateMemoryHelper(pSocket->psDevContext, ui32Size, ui32Alignment, ui32Heap, bSaveRestore, pMemoryInfo, tileSensitive, (SYS_MEMATTRIB_UNCACHED | SYS_MEMATTRIB_WRITECOMBINE), mapping);
	IMG_ASSERT(result == IMG_TRUE);
	if(result != IMG_TRUE)
	{
		IMG_FREE(pMemoryInfo);
		return IMG_FALSE;
	}

	/* Access the virtual address, published to the user for later usage (can be used directly to avoid bridging calls) */
	out = TALMMU_GetDevVirtAddress(pMemoryInfo->talmmuHandle, &ui32VirtAddr);
	IMG_ASSERT(out == IMG_SUCCESS);
	if (out != IMG_SUCCESS)
	{
		if (pMemoryInfo->sysMemHandle != IMG_NULL)
		{
			SYSMEMU_FreePages(pMemoryInfo->sysMemHandle);
		}
		IMG_FREE(pMemoryInfo);
		return IMG_FALSE;
	}

	/* Now that allocation is successful, register it in the resource bucket of the socket for future fetching and cleanup in case anything goes wrong */
	out = RMAN_RegisterResource(pSocket->hResBHandle, RMAN_BUFFERS_ID, _free_Memory, (IMG_VOID *)pMemoryInfo, IMG_NULL, &pMemoryInfo->bufferId);
	IMG_ASSERT(out == IMG_SUCCESS);
	if(out != IMG_SUCCESS)
	{
		if (pMemoryInfo->sysMemHandle != IMG_NULL)
		{
			SYSMEMU_FreePages(pMemoryInfo->sysMemHandle);
		}
		IMG_FREE(pMemoryInfo);
		return IMG_FALSE;
	}

	/* Inform the user about what it requested */
	out = SYSOSKM_CopyToUser(pbufferId, &pMemoryInfo->bufferId, sizeof(IMG_UINT32));
	IMG_ASSERT(out == IMG_SUCCESS);
	out |= SYSOSKM_CopyToUser(pui64umToken, &pMemoryInfo->ui64umToken, sizeof(IMG_UINT64));
	IMG_ASSERT(out == IMG_SUCCESS);
	out |= SYSOSKM_CopyToUser(pui32VirtAddr, &ui32VirtAddr, sizeof(IMG_UINT32));
	IMG_ASSERT(out == IMG_SUCCESS);

	/* Has it been successful after copy_to_user() calls? */
	result = (result && IMG_SUCCESS == out);

	return result;
}


/*!
 *******************************************************************************
 * \fn QUARTZKM_MMUAllocateHeapDeviceMemory
 *******************************************************************************
 * \brief Allocate a buffer and link it to the KM device context
 * \params [in] ui32ConnId Unique connection id to the device
 * \params [in] ui32Size Total size of the allocation
 * \params [in] ui32Alignment Alignment for this allocation
 * \params [in] ui32Heap Heap to use
 * \params [out] pbufferId Unique id for this buffer
 * \params [in] tileSensitive Are we allocating a tiled buffer
 * \return IMG_TRUE on normal completion
 * \details
 * When generic memory allocations are required before any stream is available
 * (backdoor internal allocations for instance), we need facility to allow these
 * allocation to succeed. In this situation, only the connection to the device
 * is opened, which means we will attach these allocation the the resource bucket
 * of this device context. When these internal allocation will be imported in a
 * stream, we will just update the ownership of the buffer by registering them
 * in the socket object bucket.
 *
 */
IMG_BOOL QUARTZKM_MMUAllocateHeapDeviceMemory(
	IMG_UINT32	ui32ConnId,
	IMG_UINT32	ui32Size,
	IMG_UINT32	ui32Alignment,
	IMG_UINT32  ui32Heap,
	SYSBRG_POINTER_ARG(IMG_UINT32) pbufferId,
	IMG_BOOL tileSensitive,
	IMG_UINT32 mapping)
{
	IMG_RESULT eRet;
	IMG_HANDLE hDevHandle;
	IMG_HANDLE hConnHandle;
	VXE_KM_CONNDATA *psConnData;
	VXE_KM_DEVCONTEXT *psDevContext;
	KM_DEVICE_BUFFER *pMemoryInfo;

	/* First, we need to get the device context resource bucket since our allocation will be linked to it */
	eRet = DMANKM_GetConnHandleFromId(ui32ConnId, &hConnHandle);
	IMG_ASSERT(eRet == IMG_SUCCESS && "Connection handle not found");
	if (eRet != IMG_SUCCESS)
	{
		return IMG_FALSE;
	}

	hDevHandle = DMANKM_GetDevHandleFromConn(hConnHandle);
	if (!hDevHandle)
	{
		return IMG_FALSE;
	}
	psDevContext = DMANKM_GetDevInstanceData(hDevHandle); /*NULL pointer will be caught below*/
	psConnData = DMANKM_GetDevConnectionData(hConnHandle);
	if (!psConnData)
	{
		return IMG_FALSE;
	}

	if (!psDevContext || !psDevContext->bInitialised)
	{
		return IMG_FALSE;
	}

	/* Allocate kernel side allocation */
	pMemoryInfo = (KM_DEVICE_BUFFER *)IMG_MALLOC(sizeof(KM_DEVICE_BUFFER));
	IMG_ASSERT(pMemoryInfo != IMG_NULL);
	if(IMG_NULL == pMemoryInfo)
	{
		return IMG_FALSE;
	}
	IMG_MEMSET(pMemoryInfo, 0, sizeof(*pMemoryInfo));

	/* Calls in TALMMU and SYSMEM layers to _really_ allocate the device memory */
	eRet = allocateMemoryHelper(psDevContext, ui32Size, ui32Alignment, ui32Heap, IMG_FALSE, pMemoryInfo, tileSensitive, (SYS_MEMATTRIB_UNCACHED | SYS_MEMATTRIB_WRITECOMBINE), mapping);
	IMG_ASSERT(eRet == IMG_TRUE);
	if (IMG_TRUE != eRet)
	{
		IMG_FREE(pMemoryInfo);
		return IMG_FALSE;
	}

	/* Allocation is successful, we will register the buffer with the global device context for future _internal_ importing */
	eRet = RMAN_RegisterResource(psConnData->hResBHandle, RMAN_BUFFERS_ID, _free_Memory, (IMG_VOID *)pMemoryInfo, IMG_NULL, &pMemoryInfo->bufferId);
	IMG_ASSERT(eRet == IMG_SUCCESS);
	if (IMG_SUCCESS != eRet)
	{
		if (pMemoryInfo->sysMemHandle != IMG_NULL)
		{
			SYSMEMU_FreePages(pMemoryInfo->sysMemHandle);
		}
		IMG_FREE(pMemoryInfo);
		return IMG_FALSE;
	}

	/* The only information UM needs is the buffer unique id, it will be used to find the correct buffer in the device resource bucker, so we copy it back to user mode */
	eRet = SYSOSKM_CopyToUser(pbufferId, &pMemoryInfo->bufferId, sizeof(IMG_UINT32));
	IMG_ASSERT(eRet == IMG_SUCCESS);

	return (eRet == IMG_SUCCESS);
}


/*!
 *******************************************************************************
 * \fn QUARTZKM_ImportGenericBuffer
 *******************************************************************************
 * \brief Change ownership of the buffer from device context to stream context
 * \params [in] ui32BufId Buffer id in the device context
 * \params [out] pui32VirtAddr Published virtual address exposed to user mode
 * \return IMG_TRUE on normal completion
 * \details
 * Generic memory allocation mechanism used for buffers being allocated through
 * a backdoor facility are linked to the device context. This import is just exposing
 * the virtual address back to User Space.
 *
 */
IMG_BOOL QUARTZKM_ImportGenericBuffer(
	IMG_UINT32	ui32BufId,
	SYSBRG_POINTER_ARG(IMG_UINT32) pui32VirtAddr)
{
	IMG_RESULT eRet;
	IMG_HANDLE resHandle;
	KM_DEVICE_BUFFER *pMemoryInfo;
	IMG_UINT32 ui32VirtAddr;

	/* First, we need to get the device context resource bucket since our allocation will be linked to it */
	eRet = RMAN_GetResource(ui32BufId, RMAN_BUFFERS_ID, (void**)&pMemoryInfo, &resHandle);
	IMG_ASSERT(eRet == IMG_SUCCESS);
	if (eRet != IMG_SUCCESS)
	{
		return IMG_FALSE;
	}

	/* Access the virtual address, published to the user for later usage (can be used directly to avoid bridging calls) */
	eRet = TALMMU_GetDevVirtAddress(pMemoryInfo->talmmuHandle, &ui32VirtAddr);
	IMG_ASSERT(eRet == IMG_SUCCESS);
	if (eRet != IMG_SUCCESS)
	{
		return IMG_FALSE;
	}

	/* Inform the user about what it requested */
	eRet = SYSOSKM_CopyToUser(pui32VirtAddr, &ui32VirtAddr, sizeof(IMG_UINT32));
	IMG_ASSERT(eRet == IMG_SUCCESS);

	return (eRet == IMG_SUCCESS);
}

/* Exported API through bridging */


/*!
 *******************************************************************************
 * \fn QUARTZKM_GetToken
 *******************************************************************************
 * \brief Access the token of a previously allocated buffer on request from user space
 * \params [in] bufferId Unique buffer id to be mapped
 * \params [out] pui64UmToken User mode token on the newly mapped memory location
 * \return IMG_TRUE on normal completion
 * \details
 * Access the UM token of the buffer to be lazily mapped thanks to id.
 * The UM caller will then call in the sysbrg API to map the buffer using this token.
 *
 */
IMG_BOOL QUARTZKM_GetToken(IMG_UINT32 bufferId, SYSBRG_POINTER_ARG(IMG_UINT64) pui64UmToken)
{
	IMG_RESULT result;
	KM_DEVICE_BUFFER* pMemInfo;
	IMG_HANDLE resHandle;

	/* In order to create the user mapping, the buffer needs to be linked to a stream */
	if (!bufferId)
	{
		IMG_ASSERT(bufferId != 0 && "Trying to create user mapping of a buffer not linked to a stream");
		return IMG_FALSE;
	}

	/* It has been linked to a stream so we can access the bucket holding it, and the buffer inside the bucket thanks to the third param */
	result = RMAN_GetResource(bufferId, RMAN_BUFFERS_ID, (void**)&pMemInfo, &resHandle);
	IMG_ASSERT(result == IMG_SUCCESS);
	if (result != IMG_SUCCESS)
	{
		return IMG_FALSE;
	}

	/* User wants to access the UM token in order to create the mapping using the sysbrg API */
	result = SYSOSKM_CopyToUser(pui64UmToken, &pMemInfo->ui64umToken, sizeof(IMG_UINT64));
	IMG_ASSERT(result == IMG_SUCCESS);

	return (result == IMG_SUCCESS);
}


/*!
 *******************************************************************************
 * \fn QUARTZKM_MapExternal
 *******************************************************************************
 * \brief Unmap a previously imported external buffer
 * \params [in] ui32StreamId Unique stream id used to access the socket object
 * \params [in] ui32BufLen Total size of the allocation
 * \params [in] ui32PallocId Page allocation unique id
 * \params [in] ui32Heap Heap to use
 * \params [in] ui32Alignment Alignment of the newly allocated buffer
 * \params [in] bTileInterleaved Is this tiling scheme having byte interleaved?
 * \params [out] pbufferId Unique id for this buffer
 * \params [out] pui32VirtAddr Virtual address returned to the host
 * \return IMG_TRUE on normal completion
 * \details
 * Access the socket object with its unique stream id, and exist immediately if
 * it has not been found, we want to map buffers to already created/opened streams.
 * After creating the KM_DEVICE_BUFFER that will hold the allocation meta-information,
 * it imports the external buffer in it. To be able to fetch it with the id, we
 * then register the imported buffer with the socket bucket handle and return
 * the unique buffer id back to User Space.
 *
 */
IMG_BOOL QUARTZKM_MapExternal(
	IMG_UINT32 ui32StreamId,
	IMG_UINT32 ui32BufLen,
	IMG_UINT32 ui32PallocId,
	IMG_UINT32 ui32Heap,
	IMG_UINT32 ui32Alignment,
	IMG_BOOL bTileInterleaved,
	SYSBRG_POINTER_ARG(IMG_UINT32) pbufferId,
	SYSBRG_POINTER_ARG(IMG_UINT32) pui32VirtAddr)
{
	IMG_RESULT			result;
	IMG_HANDLE			hTemp;
	KM_DEVICE_BUFFER* 	pMemoryInfo;
	IMG_HANDLE 			hDevMemHeap;
	IMG_HANDLE 			pallocHandle;
	IMG_VOID *pvUM = 	(void*)0x42424242;
	VXE_KM_COMM_SOCKET 	*pSocket;
	IMG_UINT32			ui32VirtAddr;

	/* Obtain the stream object thanks to the id UM provided */
	result = RMAN_GetResource(ui32StreamId, RMAN_SOCKETS_ID, (IMG_VOID **)&pSocket, IMG_NULL);
	IMG_ASSERT(result == IMG_SUCCESS);
	if (result != IMG_SUCCESS)
	{
		return IMG_FALSE;
	}

	/* Sanity check the tiling scheme */
	IMG_ASSERT((bTileInterleaved && pSocket->psDevContext->sDevSpecs.bUseInterleavedTiling) ? ((MMU_TILED_HEAP_ID == ui32Heap) ? IMG_TRUE : IMG_FALSE) : IMG_TRUE);

	/* Get the page handle from the given id */
	result = PALLOCKM_GetPagesHandle(ui32PallocId, &pallocHandle);
	IMG_ASSERT(pallocHandle != IMG_NULL);
	if(pallocHandle == IMG_NULL)
	{
		return IMG_FALSE;
	}

	/* Allocate the new buffer in kernel space */
	pMemoryInfo = (KM_DEVICE_BUFFER *)IMG_MALLOC(sizeof(KM_DEVICE_BUFFER));
	IMG_ASSERT(pMemoryInfo != IMG_NULL);
	if(pMemoryInfo == IMG_NULL)
	{
		return IMG_FALSE;
	}
	IMG_MEMSET(pMemoryInfo, 0, sizeof(*pMemoryInfo));

	/* Get handle of the heap we have been told to use */
	result = TALMMU_GetHeapHandle(
			pSocket->psDevContext->sDevSpecs.asMMU_HeapInfo[ui32Heap].ui32HeapId,
			pSocket->psDevContext->sDevSpecs.hQuartz_CoreMMUContext.Quartz_Core_mmu_context,
			&hDevMemHeap);
	IMG_ASSERT(result == IMG_SUCCESS);
	if(result != IMG_SUCCESS)
	{
		goto map_failed;
	}

	/* Map the external memory in our MMU to be able to use it with the hardware */
	QUARTZ_KM_LockMutex(pSocket->psDevContext->sDevSpecs.g_hMemmgrMutex, MTX_SUBCLASS_MEMMGR);
	result = TALMMU_DevMemMapExtMem(
			pSocket->psDevContext->sDevSpecs.hQuartz_CoreMMUContext.Quartz_Core_mmu_context,
			hDevMemHeap,
			ui32BufLen,
			ui32Alignment,
			pvUM,
			pallocHandle,
			&hTemp);
	QUARTZ_KM_UnlockMutex(pSocket->psDevContext->sDevSpecs.g_hMemmgrMutex);

	IMG_ASSERT(result == IMG_SUCCESS);
	if (result != IMG_SUCCESS)
	{
		goto map_failed;
	}

	pMemoryInfo->pvKmAddress = pvUM;
	pMemoryInfo->talmmuHandle = hTemp;
	pMemoryInfo->ui64DevPhysAddr = 0;

	/* Now that allocation is successful, register it in the resource bucket of the socket for future fetching and cleanup in case anything goes wrong */
	result = RMAN_RegisterResource(pSocket->hResBHandle, RMAN_BUFFERS_ID, _release_ExtMemory, (IMG_VOID *)pMemoryInfo, IMG_NULL, &pMemoryInfo->bufferId);
	IMG_ASSERT(result == IMG_SUCCESS);
	if(result != IMG_SUCCESS)
	{
		goto register_failed;
	}

	/* Give access to the buffer virtual address (the reason for a failure here would be pMemoryInfo->talmmuHandle being NULL) */
	result = TALMMU_GetDevVirtAddress(pMemoryInfo->talmmuHandle, &ui32VirtAddr);
	if (IMG_SUCCESS == result)
	{
		result = SYSOSKM_CopyToUser(pui32VirtAddr, &ui32VirtAddr, sizeof(IMG_UINT32));
		IMG_ASSERT(result == IMG_SUCCESS);
		if (IMG_SUCCESS != result)
		{
			return IMG_FALSE;
		}
	}

	/* Send back to the user the id it requires to access the buffer later on */
	result = SYSOSKM_CopyToUser(pbufferId, &pMemoryInfo->bufferId, sizeof(IMG_UINT32));
	IMG_ASSERT(result == IMG_SUCCESS);

	pMemoryInfo->hMemoryRegionID = pSocket->psDevContext->sDevSpecs.hSysMemId;
	pMemoryInfo->hMMUContext = (void*)&pSocket->psDevContext->sDevSpecs;

	return (result == IMG_SUCCESS);

register_failed:
	/* The call to TALMMU_DevMemMapExtMem() was successful, we need to cleanup */
	QUARTZ_KM_LockMutex(pSocket->psDevContext->sDevSpecs.g_hMemmgrMutex, MTX_SUBCLASS_MEMMGR);
	result = TALMMU_DevMemFree1(pMemoryInfo->talmmuHandle);
	QUARTZ_KM_UnlockMutex(pSocket->psDevContext->sDevSpecs.g_hMemmgrMutex);
map_failed:
	IMG_FREE(pMemoryInfo);

	return IMG_FALSE;
}


/*!
 *******************************************************************************
 * \fn QUARTZKM_UnMapExternal
 *******************************************************************************
 * \brief Unmap a previously imported external buffer
 * \params [in] bufferId Unique buffer id given when importing the buffer
 * \return IMG_TRUE on normal completion
 * \details
 * Access the buffer thanks to its unique id (make sure the buffer id is valid),
 * using RMAN since the buffer has been attached to the socket. Call further down
 * in the TAL to update the page table.
 *
 */
IMG_BOOL QUARTZKM_UnMapExternal(IMG_UINT32 bufferId)
{
	IMG_RESULT result;
	KM_DEVICE_BUFFER* pMemInfo;
	IMG_HANDLE resHandle;

	/* A buffer, in order to unmapped, needs to be linked to a stream */
	if (!bufferId)
	{
		IMG_ASSERT(bufferId != 0 && "Trying to unmap buffer not linked to a stream");
		return IMG_FALSE;
	}

	/* It has been linked to a stream so we can access the bucket holding it, and the buffer inside the bucket thanks to the third param */
	result = RMAN_GetResource(bufferId, RMAN_BUFFERS_ID, (void**)&pMemInfo, &resHandle);
	IMG_ASSERT(result == IMG_SUCCESS);
	if (result != IMG_SUCCESS)
	{
		return IMG_FALSE;
	}

	/*
	 * Unmap the page and update page table (sharing code with the callback registered for cleanup)
	 * using RMAN to invoke the callback and free the RMAN internally allocated structures.
	 * We need to do it because we called RMAN_RegisterResource() in #QUARTZKM_MapExternal().
	 */
	RMAN_FreeResource(resHandle);

	return IMG_TRUE;
}


/*!
 *******************************************************************************
 * \fn QUARTZKM_MMCopyTiledBuffer
 *******************************************************************************
 * \brief Perform tiling or detiling operation between host view of a buffer and user mode memory
 * \params [in] bufferId Unique buffer id given when creating/importing the buffer
 * \params [in] pcBuffer User mode buffer containing untiled data
 * \params [in] ui32Size Total size of the allocation
 * \params [in] ui32Offset Byte offset from shadow
 * \params [in] bToMemory Direction of transfer (IMG_TRUE for tiling, IMG_FALSE for detiling)
 * \return IMG_TRUE on normal completion
 *
 */
IMG_BOOL QUARTZKM_MMCopyTiledBuffer(
	IMG_UINT32 bufferId,
	SYSBRG_POINTER_ARG(IMG_CHAR) pcBuffer,
	IMG_UINT32 ui32Size,
	IMG_UINT32 ui32Offset,
	IMG_BOOL bToMemory)
{
	IMG_RESULT result;
	KM_DEVICE_BUFFER *pMemInfo;
	IMG_CHAR *buffer;
	IMG_HANDLE resHandle;

	/* A buffer, in order to be tiled or de-tiled, needs to be linked to a stream */
	if (!bufferId)
	{
		IMG_ASSERT(bufferId != 0 && "Trying to copy buffer not linked to a stream");
		return IMG_FALSE;
	}

	if (ui32Size == 0)
	{
		IMG_ASSERT(ui32Size != 0 && "Trying to copy zero bytes");
		return IMG_FALSE;
	}


	/* It has been linked to a stream so we can access the bucket holding it, and the buffer inside the bucket thanks to the third param */
	result = RMAN_GetResource(bufferId, RMAN_BUFFERS_ID, (void**)&pMemInfo, &resHandle);
	IMG_ASSERT(result == IMG_SUCCESS);
	if (result != IMG_SUCCESS)
	{
		return IMG_FALSE;
	}

	/* Allocate a big buffer where the tiling operation will be done */
	buffer = IMG_BIGORSMALL_ALLOC(ui32Size);
	if(!buffer)
	{
		return IMG_FALSE;
	}

	/* Copy this buffer from User Space */
	result = SYSOSKM_CopyFromUser(buffer, pcBuffer, ui32Size);
	IMG_ASSERT(result == IMG_SUCCESS);
	if(result != IMG_SUCCESS)
	{
		IMG_BIGORSMALL_FREE(ui32Size, buffer);
		return IMG_FALSE;
	}

	/* Perform the tiling operation */
	if(TALMMU_CopyTileBuffer(pMemInfo->talmmuHandle, ui32Offset, ui32Size, buffer, bToMemory) != IMG_SUCCESS)
	{
		IMG_BIGORSMALL_FREE(ui32Size, buffer);
		return IMG_FALSE;
	}

	/* Proper completion, cleanup */
	IMG_BIGORSMALL_FREE(ui32Size, buffer);

	return IMG_TRUE;
}

