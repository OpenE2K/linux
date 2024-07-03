/*!
 *****************************************************************************
 *
 * @File       quartz_mmu.c
 * @Title      Quartz Core MMU functions
 * @Description    This file contains the QUARTZ MMU functions
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

/************************************************************** Header files */
#include "sysdev_utils.h"

#if defined (__PORT_FWRK__)
	#include "dman_api.h"
#endif

#if !defined (__TALMMU_NO_OS__)
	#include <sysos_api_km.h>
#endif


#include "img_types.h"
#include "tal.h"
#include "memmgr_km.h"
#include "vxe_fw_if.h" /* for F_ENCODE etc */
#include "quartz_mmu.h"

#include "e5500_public_regdefs.h"
#include "img_video_bus4_mmu_regs_defines.h"

#include "quartz_device_km.h"
#include <vxe_KM.h>


/************************************************** Globals */

/************************************************** Internal data structures */

#if ! defined (IMG_KERNEL_MODULE)	
// The two heaps have been squeezed from 1Gio to 512Mio - if this causes a problem, their sizes can be increased
// Also double-check the content of internal_driver\tal_config.cpp:142 in ::configure_tal()
// create_mem_space("MEMSYSMEM", 0x00000000, 0x20000000); have to be big enough!

// Also note that sysdevdevif.c (line 235) appears to be limiting the absolute amount of heap memory we can actually access
//#define MEM_SIZE    (0x20000000)    <- will need to change this to match if you are increasing allocations
#endif		

// We want the heap to start at a specific address
#define HEAP_BASE_ADDRESS	 0x88000000U
// We want the heap to start at a specific address
#define TILED_HEAP_BASE_ADDRESS	 0x08000000U
// These determine the sizes of the MMU heaps we are using.
// The tiled heap is set arbitrarily large at present.
#define TILEDMMUHEAPLENGTH   0x70000000U
// The general heap is set arbitrarily large at present.
#define GENERALMMUHEAPLENGTH 0x70000000U


static struct _quartz_mmu_control_
{
	/*
	 * This describes the heaps - the separate areas mapped by the MMU.
 	 * We currently have two heaps, one tiled and one which isn't
 	 */
	TALMMU_sHeapInfo g_asMMU_HeapInfo [HEAP_ID_NO_OF_HEAPS];

	/*
	 * This describes the memory being mapped by the MMU
	 */
	TALMMU_sDevMemInfo	g_sMMU_DeviceMemoryInfo;

	/*
	 * Template is shared across multiple devices
	 */
	IMG_HANDLE g_hMMURootTemplate;

	/*
	 * MMU device context
	 */
	struct Quartz_CoreMMUContext g_sMMUContext;

	/*
	 * As the global MMU control context been initialised
	 */
	IMG_BOOL g_bInitialised;

	/*
	 * Keep a counter of how many concurrent devices are using this template. Only release when it reaches 0.
	 */
	IMG_UINT32 g_ui32Usages;

} g_quartz_mmu_control =
{
	.g_asMMU_HeapInfo = {
		/* Heap Id					Heap type,					Heap Flags,						Mem space name,		Start addr,									Length,						bTiled,		Tile Stride	*/
		{ MMU_TILED_HEAP_ID,		TALMMU_HEAP_PERCONTEXT,		TALMMU_HEAPFLAGS_NONE,			"MEMSYSMEM",		TILED_HEAP_BASE_ADDRESS,					TILEDMMUHEAPLENGTH,			IMG_TRUE,	DEFAULT_TILE_STRIDE	},
		{ MMU_GENERAL_HEAP_ID,		TALMMU_HEAP_PERCONTEXT,		TALMMU_HEAPFLAGS_NONE,			"MEMSYSMEM",		HEAP_BASE_ADDRESS,			                GENERALMMUHEAPLENGTH,		0,			0	}
	},
	.g_sMMU_DeviceMemoryInfo = {
		0, /* ui32DeviceId */
		TALMMU_MMUTYPE_4K_PAGES_32BIT_ADDR, /* eMMUType */
		TALMMU_MMUTILING_SCHEME_0, /* eTilingScheme */
		TALMMU_DEVFLAGS_NONE, /* eDevFlags */
		"MEMSYSMEM", /* pszPageDirMemSpaceName */
		"MEMSYSMEM", /* pszPageTableMemSpaceName */
		4096, /* ui32PageSize */
		0, /* ui32PageTableDirAlignment */
		0, /* eMemAttrib */
		0, /* eMemPool */
		(IMG_CHAR *)&QUARTZ_DEV_BASE_NAME /* pszDeviceName */
	},
	.g_hMMURootTemplate = NULL,
	.g_sMMUContext = {
		NULL,
		0
	},
	.g_bInitialised = IMG_FALSE,
	.g_ui32Usages = 0
};


/*
*
****** NOTE:
*
* <g_asMMU_HeapInfo> and <g_sMMU_DeviceMemoryInfo> are defined once as global variables
* but will never be used directly. Each device context will have a copy of these two in
* its internal structure and they will be used in place of the global representations
* (we expect them to be identical across all devices but it might change later)
*
*/


/*!
******************************************************************************
*
* @function		Quartz_MMU_EventCallback
* @brief		Callback registered in the TAL layer to handle $eEvent
* @params		eEvent Which even TALMMU is issuing
* @params		pCallbackParameter Unused on flush, MMU context on page_directory_ref writes
* @params		ui32IntRegIdOrAddr Unused on flush, physical device address on page_direcory_ref writes
* @params		hMemSpace Memory space handle
* @returns		IMG_SUCCESS in all cases (no errors can be returned from the different code paths)
*
******************************************************************************/
static IMG_RESULT Quartz_MMU_EventCallback (
    TALMMU_eEvent               eEvent,
    IMG_VOID *                  pCallbackParameter,
    IMG_UINT32                  ui32IntRegIdOrAddr,
    IMG_HANDLE  			    hMemSpace
)
{
	IMG_BOOL bRet;
	(void)ui32IntRegIdOrAddr;
	(void)hMemSpace;

	switch(eEvent)
	{
	case TALMMU_EVENT_WRITE_PAGE_DIRECTORY_REF: {
#ifndef SYSBRG_NO_BRIDGING
		struct Quartz_CoreMMUContext *ctx = (struct Quartz_CoreMMUContext *)pCallbackParameter;
		ctx->ptd_phys_addr = ui32IntRegIdOrAddr;
#endif
		break;
	}
	case TALMMU_EVENT_FLUSH_CACHE:
		bRet = Quartz_Core_MMU_FlushCache(pCallbackParameter);
		if (!bRet)
		{
			DEBUG_PRINT("Cache flush ignored due to low power state\n");
			return IMG_ERROR_MMU_PAGE_TABLE_FAULT;
		}
		break;
	default:
		break;
	}
	return IMG_SUCCESS;
}


/*!
******************************************************************************
*
* @function		Quartz_Core_MMU_Configure
* @brief		Configure the MMU template and allocate the heaps
* @returns		IMG_TRUE on success, IMG_FALSE if any step fails
* @details
* During MMU hardware initialisation, this function is called to allocated the
* page table directory, instance the MMU template according to the above heap
* definition and the address range being used. It also register the callback
* which will handle the MMU events being raised by TALMMU/VXEKM layers.
* To sum up, it sets everything but the directory address register.
*
******************************************************************************/
IMG_BOOL Quartz_Core_MMU_Configure(IMG_HANDLE pvDevContext)
{
	IMG_UINT32 ui32i;
	IMG_RESULT result;
	IMG_UINT32 ui32XTileStride = 0;
	IMG_HANDLE hQuartzMultipipeRegs;
	IMG_HANDLE hMMURegs;
	IMG_UINT32 ui32HWRev;
	VXE_KM_DEVCONTEXT *psDevContext = (VXE_KM_DEVCONTEXT *)pvDevContext;

	/* Extra care here, only device 0 can initialise the global (it should always be here!) */
	if (0 != psDevContext->sDevSpecs.ui32CoreDevIdx)
	{
		/* Already initialised, just copy what is required in the context */
		if (g_quartz_mmu_control.g_bInitialised)
		{
			IMG_MEMCPY(psDevContext->sDevSpecs.asMMU_HeapInfo, g_quartz_mmu_control.g_asMMU_HeapInfo, sizeof(psDevContext->sDevSpecs.asMMU_HeapInfo));
			IMG_MEMCPY(&psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo, &g_quartz_mmu_control.g_sMMU_DeviceMemoryInfo, sizeof(psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo));
			IMG_MEMCPY(&psDevContext->sDevSpecs.hQuartz_CoreMMUContext, &g_quartz_mmu_control.g_sMMUContext, sizeof(psDevContext->sDevSpecs.hQuartz_CoreMMUContext));
			psDevContext->sDevSpecs.hMMUTemplate = g_quartz_mmu_control.g_hMMURootTemplate;
			g_quartz_mmu_control.g_ui32Usages++;

			return IMG_TRUE;
		}

		return IMG_FALSE;
	}
	else if (g_quartz_mmu_control.g_bInitialised)
	{
		PRINT("ERROR: MMU template is reported initialised already\n");
		return IMG_FALSE;
	}

	/* Bring the global definitions in the device context */
	IMG_MEMCPY(psDevContext->sDevSpecs.asMMU_HeapInfo, g_quartz_mmu_control.g_asMMU_HeapInfo, sizeof(psDevContext->sDevSpecs.asMMU_HeapInfo));
	IMG_MEMCPY(&psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo, &g_quartz_mmu_control.g_sMMU_DeviceMemoryInfo, sizeof(psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo));
	/* Change the name to correctly identify the device in the MMU context */
	psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.pszDeviceName = psDevContext->hSysDevHandle->sDevInfo.pszDeviceName;
	psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.ui32DeviceId = psDevContext->sDevSpecs.ui32CoreDevIdx;

	/* We may want to alter psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo global here */

#ifdef __TALMMU_USE_PALLOC__
	{
		//***************** INITIALISING MMU SUPPORT - Do this once only
		IMG_UINT32        ui32AttachId;

		result = PALLOCKM_Initialise();
		IMG_ASSERT(result == IMG_SUCCESS);
		if (IMG_SUCCESS != result)
		{
			return IMG_FALSE;
		}

		ui32Result = PALLOC_AttachToConnection(psDevContext->ui32ConnId, &ui32AttachId);
		IMG_ASSERT(ui32Result == IMG_SUCCESS);
		if (IMG_SUCCESS != result)
		{
			goto error_palloc_init;
			return IMG_FALSE;
		}
		psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.ui32AttachId = ui32AttachId;
	}
#endif

	psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.eMemAttrib = (SYS_MEMATTRIB_UNCACHED | SYS_MEMATTRIB_WRITECOMBINE);
	psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.eMemPool = psDevContext->hSysDevHandle->sMemPool;

	DEBUG_PRINT("%s() - Device %i (eMemPool = %x)\n", __FUNCTION__,
			psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.ui32DeviceId,
			psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.eMemPool);

	/* Initialise TALMMU API and create a template */
	result = TALMMU_Initialise();
	IMG_ASSERT(result == IMG_SUCCESS);
	if(result != IMG_SUCCESS)
	{
		goto error_tal_mmu_init;
	}

	/* We will access register from these banks */
	hMMURegs = psDevContext->sDevSpecs.hQuartzMMUBank;
	hQuartzMultipipeRegs = psDevContext->sDevSpecs.hQuartzMultipipeBank;

	/* HW revision will give us supported addressing modes */
	TALREG_ReadWord32(hQuartzMultipipeRegs, QUARTZ_TOP_QUARTZ_CORE_REV, &ui32HWRev);
	ui32HWRev &= (MASK_QUARTZ_TOP_QUARTZ_MAINT_REV | MASK_QUARTZ_TOP_QUARTZ_MINOR_REV | MASK_QUARTZ_TOP_QUARTZ_MAJOR_REV);

	/* Kernel module knows if 32 or 40 bit addressing is used */
	if (psDevContext->sDevSpecs.bUseExtendedAddressing)
	{
#if SECURE_MMU
		psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.eMMUType = TALMMU_MMUTYPE_4K_PAGES_40BIT_ADDR;
#else
		IMG_UINT32 ui32RegVal;

		/* Make sure it is a Quartz hardware version */
		if (ui32HWRev >= MIN_50_REV)
		{
			TALREG_ReadWord32(hMMURegs, IMG_BUS4_MMU_CONFIG0, &ui32RegVal);

			switch (F_DECODE(ui32RegVal, IMG_BUS4_EXTENDED_ADDR_RANGE))
			{
			case 0:
				psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.eMMUType = TALMMU_MMUTYPE_4K_PAGES_32BIT_ADDR;
				break;
			case 4:
				psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.eMMUType = TALMMU_MMUTYPE_4K_PAGES_36BIT_ADDR;
				break;
			case 8:
				psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.eMMUType = TALMMU_MMUTYPE_4K_PAGES_40BIT_ADDR;
				break;
			default:
			{
				goto error_ext_range;
			}
			}
		}
		else
		{
			/* Only HW 5.0 support */
			goto error_core_rev;
		}
#endif
	}
	if (psDevContext->sDevSpecs.bUseTiledMemory)
	{
		/* It only makes sense to use 256x16 tiles (scheme 0) for video but we can do 512x8 tiles (scheme 1) as well. */
		psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.eTilingScheme = (psDevContext->sDevSpecs.bUseAlternateTiling?TALMMU_MMUTILING_SCHEME_1:TALMMU_MMUTILING_SCHEME_0); 

		ui32XTileStride = psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.eTilingScheme;
		while ((IMG_UINT32)(512 << ui32XTileStride) < psDevContext->sDevSpecs.ui32MMUTileStride) ui32XTileStride++;

		ui32XTileStride -= psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.eTilingScheme;
	}

	/* Template will be: 4k pages, 12bits offset, 10bits page table index, 10bits directory index */
	result = TALMMU_DevMemTemplateCreate(&psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo, &psDevContext->sDevSpecs.hMMUTemplate);
	IMG_ASSERT(result == IMG_SUCCESS);
	if(result != IMG_SUCCESS)
	{
		goto error_mem_template_create;
	}

	/* Register the callback defined above */
	result = TALMMU_AddCallback(psDevContext->sDevSpecs.hMMUTemplate, Quartz_MMU_EventCallback, psDevContext);
	IMG_ASSERT(result == IMG_SUCCESS);
	if(result != IMG_SUCCESS)
	{
		goto error_mem_template_callback;
	}

	/* Add heaps to the template */
	for (ui32i=0;ui32i<HEAP_ID_NO_OF_HEAPS;ui32i++)
	{
		if (psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i].bTiled == IMG_TRUE && psDevContext->sDevSpecs.bUseInterleavedTiling)
		{
			psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i].eHeapFlags |= TALMMU_HEAPFLAGS_128BYTE_INTERLEAVE;
		}
		psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i].ui32XTileStride = ui32XTileStride;

		result = TALMMU_DevMemHeapAdd(psDevContext->sDevSpecs.hMMUTemplate, &(psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i]));
		IMG_ASSERT(result == IMG_SUCCESS);
		if(result != IMG_SUCCESS)
		{
			goto error_new_mem_heap;
		}

	}

	/* Create a context from the template: allocate page directory and instantiate the memory pool for each heap */
	result = TALMMU_DevMemContextCreate(psDevContext->sDevSpecs.hMMUTemplate, psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo.ui32DeviceId, &psDevContext->sDevSpecs.hQuartz_CoreMMUContext.Quartz_Core_mmu_context); // (Template, User allocated user ID)
	IMG_ASSERT(result == IMG_SUCCESS);
	if(result != IMG_SUCCESS)
	{
		goto error_mem_context_create;
	}

	/* Setup the page directory: KM_addr => CPU_phys_addr => DEV_phys_addr translation, use the result to update hQuartz_CoreMMUContext::ptd_phys_addr through the callback registered just above */
	result = TALMMU_DevMemContextSetMMUPtd(psDevContext->sDevSpecs.hQuartz_CoreMMUContext.Quartz_Core_mmu_context, &psDevContext->sDevSpecs.hQuartz_CoreMMUContext);
	if(result != IMG_SUCCESS)
	{
		goto error_set_pagetable_dir;
	}

	/* Page directory has been updated, so we need to flush the TLB cache */
	QUARTZKM_MMUFlushMMUTableCache((void*)psDevContext);

	if (psDevContext->sDevSpecs.bUseTiledMemory)
	{
		IMG_UINT32 ui32TiledHeap;
		ui32TiledHeap = 0;
		for (ui32i = 0; ui32i < HEAP_ID_NO_OF_HEAPS; ui32i++)
		{
			if (psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i].bTiled)
			{
#if SECURE_MMU
				if (ui32TiledHeap >= 1)
				{
					IMG_ASSERT(ui32TiledHeap < 1);
					goto error_tiled_heap_count;
				}
				psDevContext->sDevSpecs.sMMURegConfig.TILE_CFG0 = F_ENCODE(1, IMG_BUS4_TILE_ENABLE) | F_ENCODE(psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i].ui32XTileStride, IMG_BUS4_TILE_STRIDE);
				psDevContext->sDevSpecs.sMMURegConfig.TILE_MAX_ADDR0 = F_ENCODE((psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i].ui32BaseDevVirtAddr + psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i].ui32Size), IMG_BUS4_TILE_MAX_ADDR);
				psDevContext->sDevSpecs.sMMURegConfig.TILE_MIN_ADDR0 = F_ENCODE(psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i].ui32BaseDevVirtAddr, IMG_BUS4_TILE_MIN_ADDR);
#else
				if (ui32TiledHeap >= 2)
				{
					IMG_ASSERT(ui32TiledHeap < 2);
					goto error_tiled_heap_count;
				}
				TALREG_WriteWord32(hMMURegs,
					IMG_BUS4_MMU_TILE_CFG(ui32TiledHeap),
						F_ENCODE(1, IMG_BUS4_TILE_ENABLE) |
						F_ENCODE(psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i].ui32XTileStride, IMG_BUS4_TILE_STRIDE));
				TALREG_WriteWord32(hMMURegs, IMG_BUS4_MMU_TILE_MAX_ADDR(ui32TiledHeap), F_ENCODE((psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i].ui32BaseDevVirtAddr + psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i].ui32Size), IMG_BUS4_TILE_MAX_ADDR));
				TALREG_WriteWord32(hMMURegs, IMG_BUS4_MMU_TILE_MIN_ADDR(ui32TiledHeap++), F_ENCODE(psDevContext->sDevSpecs.asMMU_HeapInfo[ui32i].ui32BaseDevVirtAddr, IMG_BUS4_TILE_MIN_ADDR));
#endif
			}
		}
	}
	
	/* Update the global structure now */
	IMG_MEMCPY(g_quartz_mmu_control.g_asMMU_HeapInfo, psDevContext->sDevSpecs.asMMU_HeapInfo, sizeof(g_quartz_mmu_control.g_asMMU_HeapInfo));
	IMG_MEMCPY(&g_quartz_mmu_control.g_sMMU_DeviceMemoryInfo, &psDevContext->sDevSpecs.sMMU_DeviceMemoryInfo, sizeof(g_quartz_mmu_control.g_sMMU_DeviceMemoryInfo));
	IMG_MEMCPY(&g_quartz_mmu_control.g_sMMUContext, &psDevContext->sDevSpecs.hQuartz_CoreMMUContext, sizeof(g_quartz_mmu_control.g_sMMUContext));
	g_quartz_mmu_control.g_hMMURootTemplate = psDevContext->sDevSpecs.hMMUTemplate;
	g_quartz_mmu_control.g_bInitialised = IMG_TRUE;
	g_quartz_mmu_control.g_ui32Usages++;

	/* Return success */
	return IMG_TRUE;

error_tiled_heap_count:
error_set_pagetable_dir:
error_mem_context_create:
error_new_mem_heap:
error_mem_template_callback:
	TALMMU_DevMemTemplateDestroy(psDevContext->sDevSpecs.hMMUTemplate);
error_mem_template_create:
#if !SECURE_MMU
error_ext_range:
error_core_rev:
#endif
	TALMMU_Deinitialise();
error_tal_mmu_init:
#ifdef __TALMMU_USE_PALLOC__
error_palloc_init:
	PALLOCKM_Deinitialise();
#endif

	return IMG_FALSE;
}


/*!
******************************************************************************
*
* @function		Quartz_Core_MMU_Reset
* @brief		Ensure that the device MMU is properly de-initialised
* @param		pvDevContext Handle on device context calling this function
* @returns		IMG_TRUE on success, IMG_FALSE if core 0 has already destroyed the template
*
******************************************************************************/
IMG_BOOL Quartz_Core_MMU_Reset(IMG_HANDLE pvDevContext)
{
	VXE_KM_DEVCONTEXT *psDevContext = (VXE_KM_DEVCONTEXT *)pvDevContext;

	/* One device is closing down */
	g_quartz_mmu_control.g_ui32Usages--;

	/* All devices have been closed */
	if (0 == g_quartz_mmu_control.g_ui32Usages)
	{
		IMG_ASSERT(psDevContext->sDevSpecs.hMMUTemplate); /*we expect it to be present for each device*/
		if(psDevContext->sDevSpecs.hMMUTemplate)
		{
			TALMMU_DevMemTemplateDestroy(psDevContext->sDevSpecs.hMMUTemplate);
		}

		if (g_quartz_mmu_control.g_bInitialised)
		{
			/* Reset some part of the global structure */
			g_quartz_mmu_control.g_sMMU_DeviceMemoryInfo.eMMUType = TALMMU_MMUTYPE_4K_PAGES_32BIT_ADDR;
			g_quartz_mmu_control.g_sMMU_DeviceMemoryInfo.eTilingScheme = TALMMU_MMUTILING_SCHEME_0;
			g_quartz_mmu_control.g_sMMUContext.Quartz_Core_mmu_context = NULL;
			g_quartz_mmu_control.g_sMMUContext.ptd_phys_addr = 0;
			g_quartz_mmu_control.g_hMMURootTemplate = NULL;
			g_quartz_mmu_control.g_bInitialised = IMG_FALSE;
		}
		else
		{
			PRINT("ERROR: MMU template is already reported destroyed\n");
			return IMG_FALSE;
		}
	}

	return IMG_TRUE;
}


/*!
******************************************************************************
*
* @function		Quartz_Core_MMU_HWSetup
* @brief		Configure the MMU template and allocate the heap
* @param		hMultiPipeReg VXE multipipe level register bank
* @returns		IMG_TRUE in all cases
* @details
* After MMU hardware has been initialised, this function will be called to
* finalise its setup so it can fully be used by the device.
*
******************************************************************************/
IMG_BOOL Quartz_Core_MMU_HWSetup(IMG_HANDLE pvDevContext)
{
	IMG_UINT32 ui32Cmd;
#ifdef SYSBRG_NO_BRIDGING
	IMG_UINT8 uiByteShift;
	IMG_UINT32 ui32CoreRev;
#endif
#if !SECURE_MMU
#if !defined(__LCC__) || defined(SYSBRG_NO_BRIDGING)
	IMG_UINT32 ui32RegVal;
#endif
	IMG_HANDLE hMMURegs;
#endif
	VXE_KM_DEVCONTEXT *psDevContext = (VXE_KM_DEVCONTEXT *)pvDevContext;

	if (!DMANKM_IsDevicePoweredOn(psDevContext->hDMANDevHandle))
	{
		return IMG_FALSE;
	}
#ifdef SYSBRG_NO_BRIDGING
	IMG_HANDLE hPageTableDirectory = IMG_NULL;
	// Obtain page table directory handle
	TALMMU_DevMemContextGetPtd(psDevContext->sDevSpecs.hQuartz_CoreMMUContext.Quartz_Core_mmu_context, &hPageTableDirectory);
#endif

#if !SECURE_MMU
	hMMURegs = psDevContext->sDevSpecs.hQuartzMMUBank;
#endif

#if !SECURE_MMU
	// Bypass all requesters while MMU is being configured
	// Bypass requestors (listed in TRM)
	ui32Cmd = F_ENCODE(1, IMG_BUS4_MMU_BYPASS);
	TALREG_WriteWord32(hMMURegs, IMG_BUS4_MMU_ADDRESS_CONTROL, ui32Cmd);
#endif
#ifdef SYSBRG_NO_BRIDGING
	TALREG_ReadWord32(psDevContext->sDevSpecs.hQuartzMultipipeBank, QUARTZ_TOP_QUARTZ_CORE_REV, &ui32CoreRev);
	ui32CoreRev &= (MASK_QUARTZ_TOP_QUARTZ_MAINT_REV | MASK_QUARTZ_TOP_QUARTZ_MINOR_REV | MASK_QUARTZ_TOP_QUARTZ_MAJOR_REV);
	uiByteShift=0;
	if (psDevContext->sDevSpecs.bUseExtendedAddressing)
	{
		if (ui32CoreRev >= MIN_50_REV)
		{
#if SECURE_MMU
			uiByteShift = 8;
#else
			// Quartz may be 32-bit, or 40-bit
			TALREG_ReadWord32(hMMURegs, IMG_BUS4_MMU_CONFIG0, &ui32RegVal);
			uiByteShift = (IMG_UINT8)(F_DECODE(ui32RegVal, IMG_BUS4_EXTENDED_ADDR_RANGE));
			// 0=32 bits
			// 4=36 bit
			// 8=40 bit
#endif
		}
		else
		{
			return IMG_FALSE;
		}
	}

	PRINT("Using %i bit addressing\n", 32 + uiByteShift);

	/* Insert WRW :MEMSYSMEM:$1 :MEMSYSMEM:BLOCK_{index_of_allocated_block}:0x0 */
	TALINTVAR_WriteMemRef(hPageTableDirectory, 0, psDevContext->sDevSpecs.hQuartzMultipipeBank, 1);
	/* Insert SHR :REG_QUARTZ_MULTIPIPE:$1 :REG_QUARTZ_MULTIPIPE:$1 <uiByteShift> */
    TALINTVAR_RunCommand( TAL_PDUMPL_INTREG_SHR,
										psDevContext->sDevSpecs.hQuartzMultipipeBank, 1,
										psDevContext->sDevSpecs.hQuartzMultipipeBank, 1,
										psDevContext->sDevSpecs.hQuartzMultipipeBank, uiByteShift, IMG_FALSE);

#if SECURE_MMU
	TALINTVAR_WriteToReg32(psDevContext->sDevSpecs.hLTPDataRam, FW_COMMAND_FIFO_START+4, psDevContext->sDevSpecs.hQuartzMultipipeBank, 1);
	/* Output page directory address */
	TALREG_ReadWord32(psDevContext->sDevSpecs.hLTPDataRam, FW_COMMAND_FIFO_START+4, &ui32Cmd);
	psDevContext->sDevSpecs.sMMURegConfig.DIR_BASE_ADDR0 = ui32Cmd;
#else
	/* Insert WRW :REG_MMU:0x20 :REG_QUARTZ_MULTIPIPE:$1 */
	TALINTVAR_WriteToReg32(hMMURegs, IMG_BUS4_MMU_DIR_BASE_ADDR(0), psDevContext->sDevSpecs.hQuartzMultipipeBank, 1);
	/* Output page directory address */
	TALREG_ReadWord32(hMMURegs, IMG_BUS4_MMU_DIR_BASE_ADDR(0), &ui32Cmd);
#endif


#else /*SYSBRG_NO_BRIDGING*/
#if SECURE_MMU
	/* Update of ptd_phys_addr happened earlier when the callback triggered */
	ui32Cmd = psDevContext->sDevSpecs.hQuartz_CoreMMUContext.ptd_phys_addr;
	psDevContext->sDevSpecs.sMMURegConfig.DIR_BASE_ADDR0 = psDevContext->sDevSpecs.hQuartz_CoreMMUContext.ptd_phys_addr;
#else
	/* Update of ptd_phys_addr happened earlier when the callback triggered */
	TALREG_WriteWord32(hMMURegs, IMG_BUS4_MMU_DIR_BASE_ADDR(0), psDevContext->sDevSpecs.hQuartz_CoreMMUContext.ptd_phys_addr);
	/* Output page directory address */
	TALREG_ReadWord32(hMMURegs, IMG_BUS4_MMU_DIR_BASE_ADDR(0), &ui32Cmd);
#endif
#endif /*SYSBRG_NO_BRIDGING*/

	DEBUG_PRINT("Page table directory at physical address 0x%08x\n", ui32Cmd);

	// Now enable MMU access for all requesters
	// Enable requestors (listed in TRM)
	ui32Cmd = F_ENCODE(0, IMG_BUS4_MMU_BYPASS);
	ui32Cmd |= F_ENCODE(psDevContext->sDevSpecs.bUseExtendedAddressing ? 1 : 0, IMG_BUS4_MMU_ENABLE_EXT_ADDRESSING); /* 36-bit or 40-bit actually means "not 32-bit" */

#if SECURE_MMU
	psDevContext->sDevSpecs.sMMURegConfig.ADDRESS_CONTROL = ui32Cmd;
#else
	/* This register does not get reset between encoder runs, so we need to ensure we always set it up one way or another here */
	TALREG_WriteWord32(hMMURegs, IMG_BUS4_MMU_ADDRESS_CONTROL, ui32Cmd);
#endif
	

	// Write our Control0 register
	ui32Cmd = F_ENCODE(psDevContext->sDevSpecs.bUseAlternateTiling, IMG_BUS4_MMU_TILING_SCHEME);
	ui32Cmd |= F_ENCODE(0, IMG_BUS4_FORCE_CACHE_POLICY_BYPASS);
	ui32Cmd |= F_ENCODE(0, IMG_BUS4_USE_TILE_STRIDE_PER_CONTEXT);
	ui32Cmd |= F_ENCODE(0, IMG_BUS4_MMU_CACHE_POLICY);

#if SECURE_MMU
	psDevContext->sDevSpecs.sMMURegConfig.MMU_CONTROL0 = ui32Cmd;
#else
	TALREG_WriteWord32(hMMURegs, IMG_BUS4_MMU_CONTROL0, ui32Cmd);
#endif

	/* Return success */
	return IMG_TRUE;
}


extern SYSDEVU_sInfo as_quartz_device[];
/*!
******************************************************************************
*
* @function		Quartz_Core_MMU_FlushCache
* @brief		After disabling interrupts, this function flushes the TLB cache by invalidating it
* @returns		IMG_TRUE on normal completion, IMG_FALSE if the MMU registers can't be accessed
* @details
* The assumption behind this implementation is that all devices share the same page table.
* The device context is still given as parameter so the internal implementation can decide
* only to flush one device.
* The flush only takes care of directory 0.
*
******************************************************************************/
IMG_BOOL Quartz_Core_MMU_FlushCache(IMG_HANDLE pvDevContext)
{
#if !SECURE_MMU
	IMG_UINT32 ui32RegValue, i;
	IMG_HANDLE ahMMURegs[VXE_KM_SUPPORTED_DEVICES], hDMANDevContext = NULL, hDevInstData = NULL;
	IMG_RESULT eRet;
	(void)pvDevContext;

	for (i = 0; i < VXE_KM_SUPPORTED_DEVICES; i++)
	{
		eRet = DMANKM_LocateDevice(as_quartz_device[i].sDevInfo.pszDeviceName, &hDMANDevContext);
		if (IMG_SUCCESS != eRet)
		{
			/* Device has not been initialised (this should never happen) */
			return IMG_FALSE;
		}
		if (!DMANKM_IsDevicePoweredOn(hDMANDevContext))
		{
			/* device is not currently powered on */
			return IMG_FALSE;
		}
		hDevInstData = DMANKM_GetDevInstanceData(hDMANDevContext);
		if (!hDevInstData)
		{
			/* Device context has not been attached to the device manager context */
			return IMG_FALSE;
		}
		ahMMURegs[i] = ((VXE_KM_DEVCONTEXT*)hDevInstData)->sDevSpecs.hQuartzMMUBank;
		if (!ahMMURegs[i])
		{
			/* MMU register space has not been discovered */
			return IMG_FALSE;
		}
	}

#if !defined (__TALMMU_NO_OS__)
    /* Disable interrupts */
    SYSOSKM_DisableInt();
#endif
	

	for (i = 0; i < VXE_KM_SUPPORTED_DEVICES; i++)
    {
		// Write the invalid cache line, instead of flush
		TALREG_ReadWord32(ahMMURegs[i], IMG_BUS4_MMU_CONTROL1, &ui32RegValue);
		// Set Invalid flag (this causes a flush with MMU still operating afterwards even if not cleared, but may want to replace with MMU_FLUSH?
		ui32RegValue |= F_ENCODE(1, IMG_BUS4_MMU_INVALDC(0));
		// Write Invalid flag
		TALREG_WriteWord32(ahMMURegs[i], IMG_BUS4_MMU_CONTROL1, ui32RegValue);
    }

#if !defined (__TALMMU_NO_OS__)
	/* Re-enable interrupts */
	SYSOSKM_EnableInt();
#endif
#endif
	/* Success */
	return IMG_TRUE;
}

