/*!
 *****************************************************************************
 *
 * @File       quartz_mmu.h
 * @Title      Quartz Core mmu functions
 * @Description    Quartz Core mmu functions
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


#include "talmmu_api.h"

/* set the default tile stride to 0=512-bytes stride */
#define DEFAULT_TILE_STRIDE     0

/* This will be overidden */
#define QUARTZ_DEV_BASE_NAME "QUARTZ_XXX"

enum heap_ids
{
	MMU_TILED_HEAP_ID = 0x00,
	MMU_GENERAL_HEAP_ID = 0x01,
	// Do not remove - keeps count of size
	HEAP_ID_NO_OF_HEAPS
};


struct Quartz_CoreMMUContext {
	IMG_HANDLE Quartz_Core_mmu_context;
	IMG_UINT32 ptd_phys_addr;
};

// Mutex subclasses
#define MTX_SUBCLASS_DEVKM		0x00
#define MTX_SUBCLASS_MEMMGR		0x01
#define MTX_SUBCLASS_COMTX		0x02
#define MTX_SUBCLASS_COMSTREAMS	0x03
#define MTX_SUBCLASS_CHECKANDSCHED 0x04

// Function definitions

/*!
******************************************************************************
*
* @function		Quartz_Core_MMU_Configure
* @brief 		Exposed TLB flush facility
* @param [in] 	pvDevContext Device context which table shall be flushed
* @return		#Quartz_Core_MMU_FlushCache return value
*
******************************************************************************/
IMG_BOOL QUARTZKM_MMUFlushMMUTableCache(IMG_HANDLE pvDevContext);


/*!
******************************************************************************
*
* @function		Quartz_Core_MMU_Configure
* @brief		Configure the MMU template and allocate the heaps
* @param		pvDevContext Handle on device context calling this function
* @returns		IMG_TRUE on success, IMG_FALSE if any step fails
* @details
* During MMU hardware initialisation, this function is called to allocated the
* page table directory, instance the MMU template according to the above heap
* definition and the address range being used. It also register the callback
* which will handle the MMU events being raised by TALMMU/VXEKM layers.
* To sum up, it sets everything but the directory address register.
*
******************************************************************************/
IMG_BOOL Quartz_Core_MMU_Configure(IMG_HANDLE pvDevContext);


/*!
******************************************************************************
*
* @function		Quartz_Core_MMU_Reset
* @brief		Ensure that the device MMU is properly de-initialised
* @param		pvDevContext Handle on device context calling this function
* @returns		IMG_TRUE on success, IMG_FALSE if any step fails
*
******************************************************************************/
IMG_BOOL Quartz_Core_MMU_Reset(IMG_HANDLE pvDevContext);


/*!
******************************************************************************
*
* @function		Quartz_Core_MMU_HWSetup
* @brief		Configure the MMU template and allocate the heap
* @param		pvDevContext Handle on device context calling this function
* @returns		IMG_TRUE in all cases
* @details
* After MMU hardware has been initialised, this function will be called to
* finalise its setup so it can fully be used by the device.
*
******************************************************************************/
IMG_BOOL Quartz_Core_MMU_HWSetup(IMG_HANDLE pvDevContext);


/*!
******************************************************************************
*
* @function		Quartz_Core_MMU_FlushCache
* @brief		Disabling interrupts if needed, this function flushes the cache by invalidating it
* @returns		IMG_TRUE on normal completion, IMG_FALSE if the MMU register can't be accessed
* @details
* Currently only taking care of directory 0
*
******************************************************************************/
IMG_BOOL Quartz_Core_MMU_FlushCache(IMG_HANDLE pvDevContext);
