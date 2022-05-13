/*!
 *****************************************************************************
 *
 * @File       vxe_km_api_quartz_server.c
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
#include "vxe_km_api_quartz.h"
#include "vxe_km_api_quartz_rpc.h"


IMG_VOID HOSTUTILS_dispatch(SYSBRG_sPacket *psPacket)
{
	HOSTUTILS_sCmdMsg sCommandMsg;
	HOSTUTILS_sRespMsg sResponseMsg;

	if(SYSOSKM_CopyFromUser(&sCommandMsg, psPacket->pvCmdData, sizeof(sCommandMsg)))
		IMG_ASSERT(!"failed to copy from user");

	switch (sCommandMsg.eFuncId)
	{
	
      case KM_OpenSocket_ID:
      
      
	sResponseMsg.sResp.sKM_OpenSocketResp.xKM_OpenSocketResp =
      		KM_OpenSocket(
      
	  sCommandMsg.sCmd.sKM_OpenSocketCmd.aui32DevConnId,
	  sCommandMsg.sCmd.sKM_OpenSocketCmd.eCodec,
	  sCommandMsg.sCmd.sKM_OpenSocketCmd.ui32FeaturesFlag,
	  sCommandMsg.sCmd.sKM_OpenSocketCmd.ui8PipesToUse,
	  sCommandMsg.sCmd.sKM_OpenSocketCmd.pui8CtxtId,
	  sCommandMsg.sCmd.sKM_OpenSocketCmd.pui32SockId,
	  sCommandMsg.sCmd.sKM_OpenSocketCmd.pui8FirstPipeIdx,
	  sCommandMsg.sCmd.sKM_OpenSocketCmd.pui8LastPipeIdx
      );
      break;
      
    
      case KM_CloseSocket_ID:
      
      
	sResponseMsg.sResp.sKM_CloseSocketResp.xKM_CloseSocketResp =
      		KM_CloseSocket(
      
	  sCommandMsg.sCmd.sKM_CloseSocketCmd.ui32SockId
      );
      break;
      
    
      case KM_LinkSocketToFW_ID:
      
      
	sResponseMsg.sResp.sKM_LinkSocketToFWResp.xKM_LinkSocketToFWResp =
      		KM_LinkSocketToFW(
      
	  sCommandMsg.sCmd.sKM_LinkSocketToFWCmd.ui32SockId,
	  sCommandMsg.sCmd.sKM_LinkSocketToFWCmd.ui32FWVirtualAddr
      );
      break;
      
    
      case KM_SendCommandToFW_ID:
      
      
	sResponseMsg.sResp.sKM_SendCommandToFWResp.xKM_SendCommandToFWResp =
      		KM_SendCommandToFW(
      
	  sCommandMsg.sCmd.sKM_SendCommandToFWCmd.ui32SockId,
	  sCommandMsg.sCmd.sKM_SendCommandToFWCmd.eCommand,
	  sCommandMsg.sCmd.sKM_SendCommandToFWCmd.ui32DevMemBlock,
	  sCommandMsg.sCmd.sKM_SendCommandToFWCmd.ui32CommandData,
	  sCommandMsg.sCmd.sKM_SendCommandToFWCmd.pui32CmdSeqNum
      );
      break;
      
    
      case KM_WaitForMessageFW_ID:
      
      
	sResponseMsg.sResp.sKM_WaitForMessageFWResp.xKM_WaitForMessageFWResp =
      		KM_WaitForMessageFW(
      
	  sCommandMsg.sCmd.sKM_WaitForMessageFWCmd.ui32SockId,
	  sCommandMsg.sCmd.sKM_WaitForMessageFWCmd.peMessage,
	  sCommandMsg.sCmd.sKM_WaitForMessageFWCmd.pui32Data,
	  sCommandMsg.sCmd.sKM_WaitForMessageFWCmd.pui32ExtraInfo
      );
      break;
      
    
      case QUARTZ_KM_GetCoreConfig_ID:
      
      
	sResponseMsg.sResp.sQUARTZ_KM_GetCoreConfigResp.xQUARTZ_KM_GetCoreConfigResp =
      		QUARTZ_KM_GetCoreConfig(
      
	  sCommandMsg.sCmd.sQUARTZ_KM_GetCoreConfigCmd.ui32ConnId,
	  sCommandMsg.sCmd.sQUARTZ_KM_GetCoreConfigCmd.psHwConfig
      );
      break;
      
    
      case QUARTZ_KM_GetConnIdFromSockId_ID:
      
      
	sResponseMsg.sResp.sQUARTZ_KM_GetConnIdFromSockIdResp.xQUARTZ_KM_GetConnIdFromSockIdResp =
      		QUARTZ_KM_GetConnIdFromSockId(
      
	  sCommandMsg.sCmd.sQUARTZ_KM_GetConnIdFromSockIdCmd.ui32SockId,
	  sCommandMsg.sCmd.sQUARTZ_KM_GetConnIdFromSockIdCmd.pui32ConnId
      );
      break;
      
    
      case KM_EnableFirmwareTrace_ID:
      
      
	sResponseMsg.sResp.sKM_EnableFirmwareTraceResp.xKM_EnableFirmwareTraceResp =
      		KM_EnableFirmwareTrace(
      
	  sCommandMsg.sCmd.sKM_EnableFirmwareTraceCmd.ui32DevConnId,
	  sCommandMsg.sCmd.sKM_EnableFirmwareTraceCmd.ui32Size
      );
      break;
      
    
      case KM_GetFirmwareTrace_ID:
      
      
	sResponseMsg.sResp.sKM_GetFirmwareTraceResp.xKM_GetFirmwareTraceResp =
      		KM_GetFirmwareTrace(
      
	  sCommandMsg.sCmd.sKM_GetFirmwareTraceCmd.ui32DevConnId,
	  sCommandMsg.sCmd.sKM_GetFirmwareTraceCmd.pui64fwLogToken,
	  sCommandMsg.sCmd.sKM_GetFirmwareTraceCmd.pui32fwLogSize,
	  sCommandMsg.sCmd.sKM_GetFirmwareTraceCmd.pui32fwLogWoff
      );
      break;
      
    
	}
	if(SYSOSKM_CopyToUser(psPacket->pvRespData, &sResponseMsg, sizeof(sResponseMsg)))
		IMG_ASSERT(!"failed to copy to user");
}
