/*!
 *****************************************************************************
 *
 * @File       memmgr_api_quartz.h
 * @Title      Kernel memory manager interface exposed to User Mode.
 * @Description    VXE memory manager interface exposed to User Mode.
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

#if !defined (__MEMMGR_API_H__)

// Mapping types
#define IMG_MAP_HOST_KM         0x00000001
#define IMG_MAP_HOST_UM         0x00000002
#define IMG_MAP_FIRMWARE        0x00000004

#ifdef  __RPCCODEGEN__
  #define rpc_prefix      MEMMGR
  #define rpc_filename    memmgr_api_quartz
#endif


/*!
 * \brief Allocate a buffer and link it to the KM stream object
 * \params [in] ui32StreamId Unique stream id used to access the socket object
 * \params [in] ui32Size Total size of the allocation
 * \params [in] ui32Alignment Alignment for this allocation
 * \params [in] ui32Heap Heap to use
 * \params [in] bSaveRestore Should this buffer be saved on power transitions
 * \params [out] pbufferId Unique id for this buffer
 * \params [out] pui64umToken Content of the KM_DEVICE_BUFFER::ui64umToken
 * \params [out] pui32VirtAddr Device virtual address which the user mode is allowed to see
 * \params [in] tileSensitive Is this buffer containing tiled data
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
        IMG_UINT32 mapping);

/*!
 * \brief Allocate a buffer and link it to the KM device context
 * \params [in] ui32ConnId Unique connection id to the device
 * \params [in] ui32Size Total size of the allocation
 * \params [in] ui32Alignment Alignment for this allocation
 * \params [in] ui32Heap Heap to use
 * \params [out] pbufferId Unique id for this buffer
 * \params [in] tileSensitive Is this buffer containing tiled data
 * \return IMG_TRUE on normal completion
 * \details
 * When generic memory allocations are required before any stream is available
 * (back-door internal allocations for instance), we need facility to allow these
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
        IMG_UINT32 mapping);

/*!
 * \brief Make sure that the previously allocated buffer will be accessible
 * \params [in] ui32BufId Buffer id in the device context
 * \params [out] pui32VirtAddr Published virtual address exposed to user mode
 * \return IMG_TRUE on normal completion
 * \details
 * Generic memory allocation mechanism used for buffers being allocated through
 * a back-door facility are linked to the device context. This import is just exposing
 * the virtual address back to User Space.
 *
 */
IMG_BOOL QUARTZKM_ImportGenericBuffer(
	IMG_UINT32	ui32BufId,
	SYSBRG_POINTER_ARG(IMG_UINT32) pui32VirtAddr);

/*!
 * \brief Free device memory corresponding to the buffer id parameter
 * \params bufferId Unique allocation identifier
 * \return IMG_TRUE on normal completion
 * \details
 * Fetch the resource from the stream bucket thanks to the buffer id parameter
 * in order to free it.
 *
 */
IMG_BOOL QUARTZKM_MMUMFreeDeviceMemory(IMG_UINT32 bufferId);

/*!
 * \brief Access the token of a buffer previously allocated or imported
 * \params [in] bufferId Unique buffer id previously mapped in VXE MMU
 * \params [out] pui64UmToken User mode token on the newly mapped memory location
 * \return IMG_TRUE on normal completion
 * \details
 * Access the UM token of the buffer to be lazily mapped thanks to id.
 * The UM caller will then call in the sysbrg API to map the buffer using this token.
 *
 */
IMG_BOOL QUARTZKM_GetToken(IMG_UINT32 bufferId, SYSBRG_POINTER_ARG(IMG_UINT64) pui64UmToken);


/*!
 * \brief Map an externally allocated buffer in VXE device address space
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
 * Access the socket object with its unique stream id, and exit immediately if
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
	SYSBRG_POINTER_ARG(IMG_UINT32) pui32VirtAddr);

/*!
 * \brief Unmap a previously imported external buffer
 * \params [in] bufferId Unique buffer id given when importing the buffer
 * \return IMG_TRUE on normal completion
 * \details
 * Access the buffer thanks to its unique id (make sure the buffer id is valid),
 * using RMAN since the buffer has been attached to the socket. Call further down
 * in the TAL to update the page table.
 *
 */
IMG_BOOL QUARTZKM_UnMapExternal(IMG_UINT32 bufferId);

/*!
 * \brief Perform tiling or de-tiling operation between host view of a buffer and user mode memory
 * \params [in] bufferId Unique buffer id given when creating/importing the buffer
 * \params [in] pcBuffer User mode buffer containing data
 * \params [in] ui32Size Total size of the allocation
 * \params [in] ui32Offset Byte offset from shadow
 * \params [in] bToMemory Direction of memory transfer (IMG_TRUE for tiling, IMG_FALSE for de-tiling)
 * \return IMG_TRUE on normal completion
 *
 */
IMG_BOOL QUARTZKM_MMCopyTiledBuffer(
	IMG_UINT32 bufferId,
	SYSBRG_POINTER_ARG(IMG_CHAR) pcBuffer,
	IMG_UINT32 ui32Size,
	IMG_UINT32 ui32Offset,
	IMG_BOOL bToMemory);

#endif
