/*!
 *****************************************************************************
 *
 * @File       vxe_km_api_quartz_rpc.h
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

#ifndef __HOSTUTILS_RPC_H__
#define __HOSTUTILS_RPC_H__

#include "img_defs.h"
#include "sysbrg_api.h"
#include "vxe_km_api_quartz.h"

#ifdef __cplusplus
extern "C" {
#endif

typedef enum {
	KM_OpenSocket_ID,
	KM_CloseSocket_ID,
	KM_LinkSocketToFW_ID,
	KM_SendCommandToFW_ID,
	KM_WaitForMessageFW_ID,
	QUARTZ_KM_GetCoreConfig_ID,
	QUARTZ_KM_GetConnIdFromSockId_ID,
	KM_EnableFirmwareTrace_ID,
	KM_GetFirmwareTrace_ID,

} HOSTUTILS_eFuncId;

typedef struct
{
	HOSTUTILS_eFuncId	eFuncId;
    union
	{
	
		struct
		{
			 sysbrg_user_pointer aui32DevConnId;
                          		 VXE_CODEC eCodec;
                          		 IMG_UINT32 ui32FeaturesFlag;
                          		 IMG_UINT8 ui8PipesToUse;
                          		 sysbrg_user_pointer pui8CtxtId;
                          		 sysbrg_user_pointer pui32SockId;
                          		 sysbrg_user_pointer pui8FirstPipeIdx;
                          		 sysbrg_user_pointer pui8LastPipeIdx;
                          
		} sKM_OpenSocketCmd;
	
		struct
		{
			 IMG_UINT32 ui32SockId;
                          
		} sKM_CloseSocketCmd;
	
		struct
		{
			 IMG_UINT32 ui32SockId;
                          		 IMG_UINT32 ui32FWVirtualAddr;
                          
		} sKM_LinkSocketToFWCmd;
	
		struct
		{
			 IMG_UINT32 ui32SockId;
                          		 IMG_UINT32 eCommand;
                          		 IMG_UINT32 ui32DevMemBlock;
                          		 IMG_UINT32 ui32CommandData;
                          		 sysbrg_user_pointer pui32CmdSeqNum;
                          
		} sKM_SendCommandToFWCmd;
	
		struct
		{
			 IMG_UINT32 ui32SockId;
                          		 sysbrg_user_pointer peMessage;
                          		 sysbrg_user_pointer pui32Data;
                          		 sysbrg_user_pointer pui32ExtraInfo;
                          
		} sKM_WaitForMessageFWCmd;
	
		struct
		{
			 IMG_UINT32 ui32ConnId;
                          		 sysbrg_user_pointer psHwConfig;
                          
		} sQUARTZ_KM_GetCoreConfigCmd;
	
		struct
		{
			 IMG_UINT32 ui32SockId;
                          		 sysbrg_user_pointer pui32ConnId;
                          
		} sQUARTZ_KM_GetConnIdFromSockIdCmd;
	
		struct
		{
			 IMG_UINT32 ui32DevConnId;
                          		 IMG_UINT32 ui32Size;
                          
		} sKM_EnableFirmwareTraceCmd;
	
		struct
		{
			 IMG_UINT32 ui32DevConnId;
                          		 sysbrg_user_pointer pui64fwLogToken;
                          		 sysbrg_user_pointer pui32fwLogSize;
                          		 sysbrg_user_pointer pui32fwLogWoff;
                          
		} sKM_GetFirmwareTraceCmd;
	
	} sCmd;
} HOSTUTILS_sCmdMsg;

typedef struct
{
    union
	{
	
		struct
		{
			IMG_RESULT		xKM_OpenSocketResp;
		} sKM_OpenSocketResp;
            
		struct
		{
			IMG_RESULT		xKM_CloseSocketResp;
		} sKM_CloseSocketResp;
            
		struct
		{
			IMG_RESULT		xKM_LinkSocketToFWResp;
		} sKM_LinkSocketToFWResp;
            
		struct
		{
			IMG_RESULT		xKM_SendCommandToFWResp;
		} sKM_SendCommandToFWResp;
            
		struct
		{
			IMG_RESULT		xKM_WaitForMessageFWResp;
		} sKM_WaitForMessageFWResp;
            
		struct
		{
			IMG_RESULT		xQUARTZ_KM_GetCoreConfigResp;
		} sQUARTZ_KM_GetCoreConfigResp;
            
		struct
		{
			IMG_RESULT		xQUARTZ_KM_GetConnIdFromSockIdResp;
		} sQUARTZ_KM_GetConnIdFromSockIdResp;
            
		struct
		{
			IMG_RESULT		xKM_EnableFirmwareTraceResp;
		} sKM_EnableFirmwareTraceResp;
            
		struct
		{
			IMG_RESULT		xKM_GetFirmwareTraceResp;
		} sKM_GetFirmwareTraceResp;
            
	} sResp;
} HOSTUTILS_sRespMsg;



extern IMG_VOID HOSTUTILS_dispatch(SYSBRG_sPacket __user *psPacket);

#ifdef __cplusplus
}
#endif

#endif
