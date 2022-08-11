/*!
 *****************************************************************************
 *
 * @File       memmgr_api_quartz_server.c
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

#include "sysbrg_api.h"
#include "sysbrg_api_km.h"
#include "sysos_api_km.h"
#include "memmgr_api_quartz.h"
#include "memmgr_api_quartz_rpc.h"


IMG_VOID MEMMGR_dispatch(SYSBRG_sPacket *psPacket)
{
	MEMMGR_sCmdMsg sCommandMsg;
	MEMMGR_sRespMsg sResponseMsg;

	if(SYSOSKM_CopyFromUser(&sCommandMsg, psPacket->pvCmdData, sizeof(sCommandMsg)))
		IMG_ASSERT(!"failed to copy from user");

	switch (sCommandMsg.eFuncId)
	{
	
      case QUARTZKM_StreamMMUMAllocateHeapDeviceMemory_ID:
      
      
	sResponseMsg.sResp.sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryResp.xQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryResp =
      		QUARTZKM_StreamMMUMAllocateHeapDeviceMemory(
      
	  sCommandMsg.sCmd.sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryCmd.ui32StreamId,
	  sCommandMsg.sCmd.sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryCmd.ui32Size,
	  sCommandMsg.sCmd.sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryCmd.ui32Alignment,
	  sCommandMsg.sCmd.sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryCmd.ui32Heap,
	  sCommandMsg.sCmd.sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryCmd.bSaveRestore,
	  sCommandMsg.sCmd.sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryCmd.pbufferId,
	  sCommandMsg.sCmd.sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryCmd.pui64umToken,
	  sCommandMsg.sCmd.sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryCmd.pui32VirtAddr,
	  sCommandMsg.sCmd.sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryCmd.tileSensitive,
	  sCommandMsg.sCmd.sQUARTZKM_StreamMMUMAllocateHeapDeviceMemoryCmd.mapping
      );
      break;
      
    
      case QUARTZKM_MMUAllocateHeapDeviceMemory_ID:
      
      
	sResponseMsg.sResp.sQUARTZKM_MMUAllocateHeapDeviceMemoryResp.xQUARTZKM_MMUAllocateHeapDeviceMemoryResp =
      		QUARTZKM_MMUAllocateHeapDeviceMemory(
      
	  sCommandMsg.sCmd.sQUARTZKM_MMUAllocateHeapDeviceMemoryCmd.ui32ConnId,
	  sCommandMsg.sCmd.sQUARTZKM_MMUAllocateHeapDeviceMemoryCmd.ui32Size,
	  sCommandMsg.sCmd.sQUARTZKM_MMUAllocateHeapDeviceMemoryCmd.ui32Alignment,
	  sCommandMsg.sCmd.sQUARTZKM_MMUAllocateHeapDeviceMemoryCmd.ui32Heap,
	  sCommandMsg.sCmd.sQUARTZKM_MMUAllocateHeapDeviceMemoryCmd.pbufferId,
	  sCommandMsg.sCmd.sQUARTZKM_MMUAllocateHeapDeviceMemoryCmd.tileSensitive,
	  sCommandMsg.sCmd.sQUARTZKM_MMUAllocateHeapDeviceMemoryCmd.mapping
      );
      break;
      
    
      case QUARTZKM_ImportGenericBuffer_ID:
      
      
	sResponseMsg.sResp.sQUARTZKM_ImportGenericBufferResp.xQUARTZKM_ImportGenericBufferResp =
      		QUARTZKM_ImportGenericBuffer(
      
	  sCommandMsg.sCmd.sQUARTZKM_ImportGenericBufferCmd.ui32BufId,
	  sCommandMsg.sCmd.sQUARTZKM_ImportGenericBufferCmd.pui32VirtAddr
      );
      break;
      
    
      case QUARTZKM_MMUMFreeDeviceMemory_ID:
      
      
	sResponseMsg.sResp.sQUARTZKM_MMUMFreeDeviceMemoryResp.xQUARTZKM_MMUMFreeDeviceMemoryResp =
      		QUARTZKM_MMUMFreeDeviceMemory(
      
	  sCommandMsg.sCmd.sQUARTZKM_MMUMFreeDeviceMemoryCmd.bufferId
      );
      break;
      
    
      case QUARTZKM_GetToken_ID:
      
      
	sResponseMsg.sResp.sQUARTZKM_GetTokenResp.xQUARTZKM_GetTokenResp =
      		QUARTZKM_GetToken(
      
	  sCommandMsg.sCmd.sQUARTZKM_GetTokenCmd.bufferId,
	  sCommandMsg.sCmd.sQUARTZKM_GetTokenCmd.pui64UmToken
      );
      break;
      
    
      case QUARTZKM_MapExternal_ID:
      
      
	sResponseMsg.sResp.sQUARTZKM_MapExternalResp.xQUARTZKM_MapExternalResp =
      		QUARTZKM_MapExternal(
      
	  sCommandMsg.sCmd.sQUARTZKM_MapExternalCmd.ui32StreamId,
	  sCommandMsg.sCmd.sQUARTZKM_MapExternalCmd.ui32BufLen,
	  sCommandMsg.sCmd.sQUARTZKM_MapExternalCmd.ui32PallocId,
	  sCommandMsg.sCmd.sQUARTZKM_MapExternalCmd.ui32Heap,
	  sCommandMsg.sCmd.sQUARTZKM_MapExternalCmd.ui32Alignment,
	  sCommandMsg.sCmd.sQUARTZKM_MapExternalCmd.bTileInterleaved,
	  sCommandMsg.sCmd.sQUARTZKM_MapExternalCmd.pbufferId,
	  sCommandMsg.sCmd.sQUARTZKM_MapExternalCmd.pui32VirtAddr
      );
      break;
      
    
      case QUARTZKM_UnMapExternal_ID:
      
      
	sResponseMsg.sResp.sQUARTZKM_UnMapExternalResp.xQUARTZKM_UnMapExternalResp =
      		QUARTZKM_UnMapExternal(
      
	  sCommandMsg.sCmd.sQUARTZKM_UnMapExternalCmd.bufferId
      );
      break;
      
    
      case QUARTZKM_MMCopyTiledBuffer_ID:
      
      
	sResponseMsg.sResp.sQUARTZKM_MMCopyTiledBufferResp.xQUARTZKM_MMCopyTiledBufferResp =
      		QUARTZKM_MMCopyTiledBuffer(
      
	  sCommandMsg.sCmd.sQUARTZKM_MMCopyTiledBufferCmd.bufferId,
	  sCommandMsg.sCmd.sQUARTZKM_MMCopyTiledBufferCmd.pcBuffer,
	  sCommandMsg.sCmd.sQUARTZKM_MMCopyTiledBufferCmd.ui32Size,
	  sCommandMsg.sCmd.sQUARTZKM_MMCopyTiledBufferCmd.ui32Offset,
	  sCommandMsg.sCmd.sQUARTZKM_MMCopyTiledBufferCmd.bToMemory
      );
      break;
      
    
	}
	if(SYSOSKM_CopyToUser(psPacket->pvRespData, &sResponseMsg, sizeof(sResponseMsg)))
		IMG_ASSERT(!"failed to copy to user");
}
