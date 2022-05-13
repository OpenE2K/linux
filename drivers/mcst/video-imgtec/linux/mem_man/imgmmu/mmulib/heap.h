/*!
 *****************************************************************************
 *
 * @File       heap.h
 * @Description    MMU Library: device virtual allocation (heap)
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

#ifndef IMGMMU_HEAP_H
#define IMGMMU_HEAP_H

#ifdef __cplusplus
extern "C" {
#endif

#include <img_types.h>

/**
 * @defgroup IMGMMU_heap MMU Heap Interface
 * @brief The API for the device virtual address Heap - must be implemented 
 * (see tal_heap.c for an example implementation)
 * @ingroup IMGMMU_lib
 * @{
 */
/*-----------------------------------------------------------------------------
 * Following elements are in the IMGMMU_heap documentation module
 *---------------------------------------------------------------------------*/

/** @brief An allocation on a heap. */
typedef struct MMUHeapAlloc
{
    /** @brief Start of the allocation */
	IMG_UINTPTR uiVirtualAddress;
    /** @brief Size in bytes */
	IMG_SIZE uiAllocSize;
} IMGMMU_HeapAlloc;

/**
 * @brief A virtual address heap - not directly related to HW MMU directory 
 * entry
 */
typedef struct MMUHeap
{
    /** @brief Start of device virtual address */
	IMG_UINTPTR uiVirtAddrStart; 
    /** @brief Allocation atom in bytes */
	IMG_SIZE uiAllocAtom;
    /** @brief Total size of the heap in bytes */
	IMG_SIZE uiSize;
} IMGMMU_Heap;

/**
 * @name Device virtual address allocation (heap management)
 * @{
 */

/**
 * @brief Create a Heap
 *
 * @param uiVirtAddrStart start of the heap - must be a multiple of uiAllocAtom
 * @param uiAllocAtom the minimum possible allocation on the heap in bytes 
 * - usually related to the system page size
 * @param uiSize total size of the heap in bytes
 * @param pResult must be non-NULL - used to give detail about error
 *
 * @return pointer to the new Heap object and pResult is IMG_SUCCESS
 * @return NULL and the value of pResult can be:
 * @li IMG_ERROR_MALLOC_FAILED if internal allocation failed
 */
IMGMMU_Heap* IMGMMU_HeapCreate(IMG_UINTPTR uiVirtAddrStart, 
    IMG_SIZE uiAllocAtom, IMG_SIZE uiSize, IMG_RESULT *pResult);

/**
 * @brief Allocate from a heap
 *
 * @warning Heap do not relate to each other, therefore one must insure that
 * they should not overlap if they should not.
 *
 * @param pHeap must not be NULL
 * @param uiSize allocation size in bytes
 * @param pResult must be non-NULL - used to give details about error
 *
 * @return pointer to the new HeapAlloc object and pResult is IMG_SUCCESS
 * @return NULL and the value of pResult can be:
 * @li IMG_ERROR_INVALID_PARAMETERS if the give size is not a multiple of 
 * pHeap->uiAllocAtom
 * @li IMG_ERROR_MALLOC_FAILED if the internal structure allocation failed
 * @li IMG_ERROR_NOT_SUPPORTED if the internal device memory allocator did not
 * find a suitable virtual address
 */
IMGMMU_HeapAlloc* IMGMMU_HeapAllocate(IMGMMU_Heap *pHeap, IMG_SIZE uiSize, 
    IMG_RESULT *pResult);

/**
 * @brief Liberate an allocation
 *
 * @return IMG_SUCCESS
 */
IMG_RESULT IMGMMU_HeapFree(IMGMMU_HeapAlloc *pAlloc);

/**
 * @brief Destroy a heap object
 *
 * @return IMG_SUCCESS
 * @return IMG_ERROR_NOT_SUPPORTED if the given Heap still has attached 
 * allocation
 */
IMG_RESULT IMGMMU_HeapDestroy(IMGMMU_Heap *pHeap);

/**
 * @}
 */
/*-----------------------------------------------------------------------------
 * End of the public functions
 *---------------------------------------------------------------------------*/

/**
 * @}
 */
/*-----------------------------------------------------------------------------
 * End of the IMGMMU_heap documentation module
 *---------------------------------------------------------------------------*/ 

#ifdef __cplusplus
}
#endif

#endif // IMGMMU_HEAP_H
