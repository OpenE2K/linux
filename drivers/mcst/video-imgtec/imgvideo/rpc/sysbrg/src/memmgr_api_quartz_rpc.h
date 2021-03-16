/*!
 *****************************************************************************
 *
 * @File       memmgr_api_quartz_rpc.h
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

#ifndef __MEMMGR_RPC_H__
#define __MEMMGR_RPC_H__

#include "img_defs.h"
#include "sysbrg_api.h"
#include "memmgr_api_quartz.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	QUARTZKM_StreamMMUMAllocateHeapDeviceMemory_ID,
	QUARTZKM_MMUAllocateHeapDeviceMemory_ID,
	QUARTZKM_ImportGenericBuffer_ID,
	QUARTZKM_MMUMFreeDeviceMemory_ID,
	QUARTZKM_GetToken_ID,
	QUARTZKM_MapExternal_ID,
	QUARTZKM_UnMapExternal_ID,
	QUARTZKM_MMCopyTiledBuffer_ID,

} MEMMGR_eFuncId;

typedef struct
{
	MEMMGR_eFuncId	eFuncId;
    union
	{
	
		struct
		{
			 IMG_UINT32 ui32StreamId;
                          		 IMG_UINT32 ui32Size;
                          		 IMG_UINT32 ui32Alignment;
                          		 IMG_UINT32 ui32Heap;
                          		 IMG_BOOL bSaveRestore;
                          		 sysbrg_user_pointer pbufferId;
                          		 sysbrg_user_pointer pui64umToken;
                          		 sysbrg_user_pointer pui32VirtAddr;
                          		 IMG_BOOL tileSensitive;
                          		 IMG_UINT32 mapping;
                          
		} sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryCmd;
	
		struct
		{
			 IMG_UINT32 ui32ConnId;
                          		 IMG_UINT32 ui32Size;
                          		 IMG_UINT32 ui32Alignment;
                          		 IMG_UINT32 ui32Heap;
                          		 sysbrg_user_pointer pbufferId;
                          		 IMG_BOOL tileSensitive;
                          		 IMG_UINT32 mapping;
                          
		} sQUARTZKM_MMUAllocateHeapDeviceMemoryCmd;
	
		struct
		{
			 IMG_UINT32 ui32BufId;
                          		 sysbrg_user_pointer pui32VirtAddr;
                          
		} sQUARTZKM_ImportGenericBufferCmd;
	
		struct
		{
			 IMG_UINT32 bufferId;
                          
		} sQUARTZKM_MMUMFreeDeviceMemoryCmd;
	
		struct
		{
			 IMG_UINT32 bufferId;
                          		 sysbrg_user_pointer pui64UmToken;
                          
		} sQUARTZKM_GetTokenCmd;
	
		struct
		{
			 IMG_UINT32 ui32StreamId;
                          		 IMG_UINT32 ui32BufLen;
                          		 IMG_UINT32 ui32PallocId;
                          		 IMG_UINT32 ui32Heap;
                          		 IMG_UINT32 ui32Alignment;
                          		 IMG_BOOL bTileInterleaved;
                          		 sysbrg_user_pointer pbufferId;
                          		 sysbrg_user_pointer pui32VirtAddr;
                          
		} sQUARTZKM_MapExternalCmd;
	
		struct
		{
			 IMG_UINT32 bufferId;
                          
		} sQUARTZKM_UnMapExternalCmd;
	
		struct
		{
			 IMG_UINT32 bufferId;
                          		 sysbrg_user_pointer pcBuffer;
                          		 IMG_UINT32 ui32Size;
                          		 IMG_UINT32 ui32Offset;
                          		 IMG_BOOL bToMemory;
                          
		} sQUARTZKM_MMCopyTiledBufferCmd;
	
	} sCmd;
} MEMMGR_sCmdMsg;

typedef struct
{
    union
	{
	
		struct
		{
			IMG_BOOL		xQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryResp;
		} sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryResp;
            
		struct
		{
			IMG_BOOL		xQUARTZKM_MMUAllocateHeapDeviceMemoryResp;
		} sQUARTZKM_MMUAllocateHeapDeviceMemoryResp;
            
		struct
		{
			IMG_BOOL		xQUARTZKM_ImportGenericBufferResp;
		} sQUARTZKM_ImportGenericBufferResp;
            
		struct
		{
			IMG_BOOL		xQUARTZKM_MMUMFreeDeviceMemoryResp;
		} sQUARTZKM_MMUMFreeDeviceMemoryResp;
            
		struct
		{
			IMG_BOOL		xQUARTZKM_GetTokenResp;
		} sQUARTZKM_GetTokenResp;
            
		struct
		{
			IMG_BOOL		xQUARTZKM_MapExternalResp;
		} sQUARTZKM_MapExternalResp;
            
		struct
		{
			IMG_BOOL		xQUARTZKM_UnMapExternalResp;
		} sQUARTZKM_UnMapExternalResp;
            
		struct
		{
			IMG_BOOL		xQUARTZKM_MMCopyTiledBufferResp;
		} sQUARTZKM_MMCopyTiledBufferResp;
            
	} sResp;
} MEMMGR_sRespMsg;



extern IMG_VOID MEMMGR_dispatch(SYSBRG_sPacket __user *psPacket);

#ifdef __cplusplus
}
#endif

#endif
