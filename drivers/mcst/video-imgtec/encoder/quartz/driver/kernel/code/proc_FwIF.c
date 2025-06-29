/*!
 *****************************************************************************
 *
 * @File       proc_FwIF.c
 * @Title      Quartz embedded core functions
 * @Description    This file contains the QUARTZ Kernel to Firmware interface module
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

#include "img_types.h"
#include "img_defs.h"


#include "VXE_Enc_GlobalDefs.h"


/****** Memory related includes ******/
#include "tal.h"
// Memory allocation from the Kernel Space
#include <memmgr_km.h>


/****** Firmware interfaces/Kernel includes ******/
#include "proc_FwIF.h"
#include "vxe_fw_if.h"
#include "quartz_device_km.h"
#include "quartz_mmu.h"
#include "vxe_KM.h"

#ifndef LOAD_FW_VIA_LINUX
// All firmware builds are published through this header file
#include "../firmware/quartz/fw_binaries/include_all_fw_variants.h"
#endif

/****** Register includes ******/
// Handmade file for now, here to help fleshing the code right
#include "ltp_regs.h"
#include "e5500_public_regdefs.h"
#include "img_video_bus4_mmu_regs_defines.h"
#include "img_soc_dmac_regs.h"

#ifdef LOAD_FW_VIA_LINUX
#include <linux/firmware.h>
#include <linux/version.h>
#endif

#ifdef WIN32
#define TRACK_FREE(ptr) 		IMG_FREE(ptr)
#define TRACK_MALLOC(ptr) 		IMG_MALLOC(ptr)
#define TRACK_DEVICE_MEMORY_INIT
#define TRACK_DEVICE_MEMORY_SHOW
#include <sys/timeb.h>
#define TIMER_INIT
#define TIMER_START(a,b)
#define TIMER_END(a)
#define TIMER_CAPTURE(a)
#define TIMER_CLOSE
#define __func__ __FUNCTION__
//#include "timer.h"
#else
#define TRACK_FREE(ptr) 		IMG_FREE(ptr)
#define TRACK_MALLOC(ptr) 		IMG_MALLOC(ptr)
#define TRACK_DEVICE_MEMORY_INIT
#define TRACK_DEVICE_MEMORY_SHOW
#define TIMER_INIT
#define TIMER_START(...)
#define TIMER_END(...)
#define TIMER_CLOSE
#define TIMER_CAPTURE(...)
#endif

#ifdef LOAD_FW_VIA_LINUX
extern char* firmware_name;
#endif


#if ! defined (IMG_KERNEL_MODULE)
extern IMG_BOOL g_bDoingPdump;
IMG_BOOL g_bFWUseBootloader;
#endif


/* Guard the codec enum */
STATIC_ASSERT(VXE_CODEC_NONE == 0 && VXE_CODEC_H264 == 1 && VXE_CODEC_H265 == 2);
/* If this assert trigger, the below lookup table should be update to reflect the change in VXE_CODEC enum */
STATIC_ASSERT(VXE_CODEC_COUNT == 3);
/* ui16CodecMask | pszFormat| pszRCModes */
VXE_KM_LOOKUP_CODEC_FORMAT_RC g_asLookupTableCodecToMask[] =
{
	/*[VXE_CODEC_NONE] =*/	{0x0000, "", ""},
	/*[VXE_CODEC_H264] =*/	{0x0010, "H264", "ALL"},
	/*[VXE_CODEC_H265] =*/	{0x0080, "H265", "ALL"},
};



/*!
* @enum _VXE_KM_REGS_SAVED_ON_POWER_TRANS_ Registers saved when entering low power
* @brief Keep this enum updated so that we know what's going on during power save/restore
*/
enum _VXE_KM_REGS_SAVED_ON_POWER_TRANS_
{
	SAVED_IMG_BUS4_MMU_DIR_BASE_ADDR_0 = 0,		//!< Page table directory address
	SAVED_IMG_BUS4_MMU_TILE_CFG_0,				//!< Tiling setup for MMU context 0
	SAVED_IMG_BUS4_MMU_TILE_CFG_1,				//!< Tiling setup for MMU context 1
	SAVED_IMG_BUS4_MMU_ADDRESS_CONTROL,			//!< Page size and address range configuration
	SAVED_MULTICORE_INTEN,						//!< Firmware interrupts which will trigger the kernel isr
	SAVED_IMG_BUS4_MMU_CONTROL0,				//!< MMU global configuration
	SAVED_FW_FEEDBACK_PRODUCER,					//!< Firmware progress on writing the feedback FIFO
	SAVED_FW_FEEDBACK_CONSUMER,					//!< Kernel progress on reading the feedback FIFO
	SAVED_REGISTERS_APM
};


/****** Local defines ******/

#if defined(IMG_KERNEL_MODULE)
#define DMAC_FW_LOAD_TIMEOUT (1000)
#else
#define DMAC_FW_LOAD_TIMEOUT (10000)
#endif


/* Avoid magic numbers and refer to the TRM system bus register map */
#define QUARTZ_PROC_CODE_BASE_ADDR (0x20000)
#define QUARTZ_PROC_DATA_BASE_ADDR (0x30000)

#define QUARTZ_MAX_CODE_SIZE (64*1024)
#define QUARTZ_MAX_DATA_SIZE (32*1024)

/* When booting from external memory, we need a stack not conflicting with the stack in LTP data ram */
#define LTP_EXTERNAL_MEM_STACK_SIZE (0x1000)

#define LTP_WR_COMB_TIMEOUT (100) /*wr_comb will automatically flush after that many cycles*/

/* Currently we only wired pipe 0 (trigger 1) to this, do we want to wire each pipe to its own or all pipes to this one */
#define LTP_INTERNAL_TRIGGER_PIPE			(12)
#define LTP_INTERNAL_TRIGGER_MULTIPIPE		(4)


// Registers defined here for simplicity
#define LTP_CR_MSLVCTRL0 					(0x2080)
#define MASK_LTP_CR_LTP_MSLV_AUTOINC		(0x00000002)
#define SHIFT_LTP_CR_LTP_MSLV_AUTOINC		(1)
#define MASK_LTP_CR_LTP_MSLV_RNW			(0x00000001)
#define SHIFT_LTP_CR_LTP_MSLV_RNW			(0)
#define LTP_CR_MSLVCTRL1 					(0x20c0)
#define MASK_LTP_CR_LTP_MSLV_PORT_RDY		(0x01000000)
#define SHIFT_LTP_CR_LTP_MSLV_PORT_RDY		(24)
#define MASK_LTP_CR_LTP_MSLV_COREMEM_IDLE	(0x02000000)
#define SHIFT_LTP_CR_LTP_MSLV_COREMEM_IDLE	(25)
#define MASK_LTP_CR_LTP_MSLV_GLOB_REG_IDLE	(0x04000000)
#define SHIFT_LTP_CR_LTP_MSLV_GLOB_REG_IDLE	(26)
#define MASK_LTP_CR_LTP_DEF_BUS_ERROR		(0x00100000)
#define SHIFT_LTP_CR_LTP_DEF_BUS_ERROR		(20)
#define MASK_LTP_CR_LTP_WR_IN_PROGRESS		(0x00040000)
#define SHIFT_LTP_CR_LTP_WR_IN_PROGRESS		(18)
#define LTP_CR_MSLVDATAT 					(0x2040)
#define LTP_CR_MSLVDATAX 					(0x2000)
#define LTP_CR_MSLVKICK0 					(0x2400)
#define LTP_CR_MSLVSRST						(0x2600)
#define MASK_LTP_SOFT_RESET					(0x1)
#define SHIFT_LTP_SOFT_RESET				(0)
//#define CHECK_PRIV (1)

#define LTP_SYSC_DCACHE_FLUSH 			(0x04830038)
#define LTP_SYSC_ICACHE_FLUSH 			(0x04830040)
#define LTP_SYSC_CACHE_MMU_CONFIG 		(0x04830028)
#define LTP_MMCU_DCACHE_CTRL 			(0x04830018)
#define LTP_MMCU_ICACHE_CTRL 			(0x04830020)
#define LTP_SYSC_DCPART0 				(0x04830200)
#define LTP_MMCU_LOCAL_EBCTRL 			(0x04830600)
#define LTP_MMCU_GLOBAL_EBCTRL 			(0x04830608)

#define LTP_PERF_COUNT0 				(0x0480ffe0)


#define LTP_SYSC_JTAG_THREAD 			(0x04830030)
#define MASK_LTP_SYSC_PRIVILEGE			(0x00000004)
#define SHIFT_LTP_SYSC_PRIVILEGE		(2)

#define LTP_HWVEC0EXT					(0x04820700)
/* For trigger [0-31], we use the above register */
#define LTP_HWVECXEXT_0_20(extTrigger)	(LTP_HWVEC0EXT + (extTrigger) * 8)

#define LTP_HWLEVELEXT					(0x04820030)
#define MASK_LTP_LEVEL_EXT_0			(0x00000001)
#define SHIFT_LTP_LEVEL_EXT_0			(0)
#define MASK_LTP_LEVEL_EXT(extTrigger)	(MASK_LTP_LEVEL_EXT_0 << (extTrigger))
#define SHIFT_LTP_LEVEL_EXT(extTrigger)	(SHIFT_LTP_LEVEL_EXT_0 + (extTrigger))

/* Even if reset values are 0xffffffff, we force these values for the triggers */
#define LTP_HWMASKEXT_0					(0x04820050)
#define LTP_HWMASKEXT_1					(0x04820058)
#define LTP_HWMASKEXT_2					(0x04820060)
#define LTP_HWMASKEXT_3					(0x04820068)


/* Write combiner configuration */
#define LTP_WRCOMBCONFIG0						(0x04830100)
#define SHIFT_LTP_WRCOMB_TIMEOUT_COUNT			(0)
#define MASK_LTP_WRCOMB_TIMEOUT_COUNT			(0x3ff)
#define SHIFT_LTP_WRCOMB_TIMEOUT_ENABLED		(12)
#define MASK_LTP_WRCOMB_TIMEOUT_ENABLED			(0x1 << SHIFT_LTP_WRCOMB_TIMEOUT_ENABLED)
#define SHIFT_LTP_WRCOMB_ENABLED				(13)
#define MASK_LTP_WRCOMB_ENABLED					(0x1 << SHIFT_LTP_WRCOMB_ENABLED)
#define SHIFT_LTP_WRCOMB_AUTO_FLUSH_LINE_FULL	(14)
#define MASK_LTP_WRCOMB_AUTO_FLUSH_LINE_FULL	(0x1 << SHIFT_LTP_WRCOMB_AUTO_FLUSH_LINE_FULL)

#define LTP_WRCOMBCOMFIG4						(0x04830180)
#define SHIFT_LTP_WRCOMB_PARTITION_OFFSET		(0)
#define MASK_LTP_WRCOMB_PARTITION_OFFSET		(0xf)
#define SHIFT_LTP_WRCOMB_PARTITION_SIZE_LSB		(4)
#define MASK_LTP_WRCOMB_PARTITION_SIZE_LSB		(0x3 << SHIFT_LTP_WRCOMB_PARTITION_SIZE_LSB)
#define SHIFT_LTP_WRCOMB_PARTITION_ALLOC_ID		(6)
#define MASK_LTP_WRCOMB_PARTITION_ALLOC_ID		(0x3 << SHIFT_LTP_WRCOMB_PARTITION_ALLOC_ID)
#define SHIFT_LTP_WRCOMB_PARTITION_SIZE_MSB		(8)
#define MASK_LTP_WRCOMB_PARTITION_SIZE_MSB		(0x1 << SHIFT_LTP_WRCOMB_PARTITION_SIZE_MSB)

#define LTP_CR_MMCU_WRITECOMB_CTRL				(0x04830640) /*0x04830640 + 0x8*0 (since we only have thread0)*/
#define SHIFT_MMCU_WRITECOMB					(0)
#define MASK_MMCU_WRITECOMB						(0x7 << SHIFT_MMCU_WRITECOMB)
#define SHIFT_MMCU_WRITEABLE					(4)
#define MASK_MMCU_WRITEABLE						(0x7 << SHIFT_MMCU_WRITEABLE)
#define LTP_WRCOMB_USE_BYTE_27_ADDRESS			(0x3) /*only addresses in the form X8XXXXXX match this (so 08000000 and 88000000) */
#define LTP_WRCOMB_ALL_GLOB_LOC_ADDR_WRITEABLE	(0x0) /*whole content of both local (08000000-7fffffff) and global (88000000-fffdffff) regions are writeable*/
#define LTP_WRCOMB_ALL_GLOB_LOC_ADDR_ENABLED	(0x7) /*write combiner is enabled for both local (08000000-7fffffff) and global (88000000-fffdffff) regions w/o restrictions*/

#define SLAVE_INTERFACE_POLL_COUNT		(1000)
#define SLAVE_INTERFACE_POLL_TIMEOUT	(10)


/************************************************ PRIVATE FUNCTIONS ********************************************************/


/*!
* @fn ltp_slave_wait_idle
* @brief Waits for the slave interface to be idle to guarantee synchronisation
* @params psFWSoftImage Pointer on the firmware context representation
* @return	- IMG_SUCCESS on normal completion,
*			- IMG_ERROR_TIMEOUT on poll timeout
*/
static IMG_RESULT ltp_slave_wait_idle(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage)
{
	IMG_RESULT eRet;

	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Wait for LTP slave port to go idle");
	eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVCTRL1, TAL_CHECKFUNC_ISEQUAL,
		MASK_LTP_CR_LTP_MSLV_PORT_RDY | MASK_LTP_CR_LTP_MSLV_COREMEM_IDLE | MASK_LTP_CR_LTP_MSLV_GLOB_REG_IDLE,
		MASK_LTP_CR_LTP_MSLV_PORT_RDY | MASK_LTP_CR_LTP_MSLV_COREMEM_IDLE | MASK_LTP_CR_LTP_MSLV_GLOB_REG_IDLE,
		SLAVE_INTERFACE_POLL_COUNT, SLAVE_INTERFACE_POLL_TIMEOUT);

	return eRet;
}


/*!
* @fn ltp_slave_single_write
* @brief Perform a write to a LTP register using the slave interface
* @params psFWSoftImage Pointer on the firmware context representation
* @params ui32RegToWrite LTP internal register to write to (either prefixed by 0x04800000 or just the 16 bits wide offset)
* @params ui32ValToWrite Value to write in the internal register
* @details
* 1 - Poll content of bits 24, 25 and 26 of MSLVCTRL1 to be 1
* 2 - Set content of MSLVCTRL0 to the target address (not shifted) and bits 1 and 0 to 00
* 3 - Write data to be placed in the core register inside MSLVDATAT
* @return	- IMG_SUCCESS on normal completion,
*			- IMG_ERROR_TIMEOUT on poll timeout
*/
static IMG_RESULT ltp_slave_single_write(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage, IMG_UINT32 ui32RegToWrite, IMG_UINT32 ui32ValToWrite)
{
	IMG_RESULT eRet;

	eRet = ltp_slave_wait_idle(psFWSoftImage);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Slave port did not go idle in time");
		return eRet;
	}

	TALREG_WriteWord32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVCTRL0, 0x04800000 | ui32RegToWrite | F_ENCODE(0, LTP_CR_LTP_MSLV_RNW) | F_ENCODE(0, LTP_CR_LTP_MSLV_AUTOINC));
	TALREG_WriteWord32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAT, ui32ValToWrite);

	return eRet;
}


/*!
* @fn ltp_slave_single_read
* @brief Perform a read from a LTP register using the slave interface
* @params [in] psFWSoftImage Pointer on the firmware context representation
* @params [in] ui32RegToWrite LTP internal register to read from (either prefixed by 0x04800000 or just the 16 bits wide offset)
* @params [out] pui32ValRead Value read from the internal register
* @details
* 1 - Poll content of bits 24, 25 and 26 of MSLVCTRL1 to be 1
* 2 - Set content of MSLVCTRL0 to the target address (not shifted) and bits 1 and 0 to 01
* 3 - Poll content of bits 24, 25 and 26 of MSLVCTRL1 to be 1
* 4 - Read content of the core register from MSLVDATAX
* @return	- IMG_SUCCESS on normal completion,
*			- IMG_ERROR_TIMEOUT on poll timeout
*/
static IMG_RESULT ltp_slave_single_read(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage, IMG_UINT32 ui32RegToRead, IMG_UINT32 *pui32ValRead)
{
	IMG_RESULT eRet;

	eRet = ltp_slave_wait_idle(psFWSoftImage);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Slave port did not go idle in time");
		return eRet;
	}

	TALREG_WriteWord32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVCTRL0, 0x04800000 | ui32RegToRead | F_ENCODE(1, LTP_CR_LTP_MSLV_RNW) | F_ENCODE(0, LTP_CR_LTP_MSLV_AUTOINC));

	eRet = ltp_slave_wait_idle(psFWSoftImage);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Slave port did not go idle in time");
		return eRet;
	}

	TALREG_ReadWord32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAX, pui32ValRead);

	return eRet;
}


/*!
* @fn ltp_connectTriggers
* @brief Wraps up external to internal triggers connection
* @params psFWSoftImage Pointer on the context of the target LTP
* @returns:	- IMG_SUCCESS on normal completion
*			- IMG_ERROR_TIMEOUT if one poll fails
*/
static IMG_RESULT ltp_connectTriggers(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage)
{
	IMG_RESULT eRet;
	IMG_UINT32 i, level_sensitive_flag;
#if ! defined (IMG_KERNEL_MODULE)
	IMG_CHAR szComment[128];
#endif

#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Force triggers [0;127] to 1 (same as default) to guarantee their state");
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_HWMASKEXT_0, 0xffffffff);
	if (IMG_SUCCESS != eRet) {return eRet;}
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_HWMASKEXT_1, 0xffffffff);
	if (IMG_SUCCESS != eRet) {return eRet;}
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_HWMASKEXT_2, 0xffffffff);
	if (IMG_SUCCESS != eRet) {return eRet;}
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_HWMASKEXT_3, 0xffffffff);
	if (IMG_SUCCESS != eRet) {return eRet;}

#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Map external triggers :");
	SPRINT(szComment, "> 0 to internal trigger %i", LTP_INTERNAL_TRIGGER_MULTIPIPE);
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, szComment);
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_HWVECXEXT_0_20(0), LTP_INTERNAL_TRIGGER_MULTIPIPE); /*writes LTP_HWVEC0EXT + 0 * 8*/
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

	level_sensitive_flag = F_ENCODE(1, LTP_LEVEL_EXT(0));
	for (i = 0; i < psFWSoftImage->ui8QuartzHwPipes; i++)
	{
#if ! defined (IMG_KERNEL_MODULE)
		SPRINT(szComment, "> %i to internal trigger %i", 1+i, LTP_INTERNAL_TRIGGER_PIPE);
		TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, szComment);
#endif
		eRet = ltp_slave_single_write(psFWSoftImage, LTP_HWVECXEXT_0_20(1 + i), LTP_INTERNAL_TRIGGER_PIPE); /*writes LTP_HWVEC0EXT + (1 + i) * 8*/
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}
		level_sensitive_flag |= F_ENCODE(1, LTP_LEVEL_EXT(1 + i));
	}

#if ! defined (IMG_KERNEL_MODULE)
	SPRINT(szComment, "Set external triggers (0..%i) as level sensitive", psFWSoftImage->ui8QuartzHwPipes);
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, szComment);
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_HWLEVELEXT, level_sensitive_flag);

	return eRet;
}


/*!
* @fn ltp_setupCaches
* @brief Wraps up cache setup for LTP core
* @params psFWSoftImage Pointer on the context of the target LTP
* @returns:	- IMG_SUCCESS on normal completion
*			- IMG_ERROR_TIMEOUT if one poll fails
*/
IMG_RESULT ltp_setupCaches(VXE_KM_FW_SOFT_IMAGE * psFWSoftImage)
{
#if ! defined (IMG_KERNEL_MODULE)
	IMG_CHAR szComment[255];
#endif
	IMG_UINT32 ui32MMUCacheConfig, tmp;
	IMG_RESULT eRet;

#if ! defined (IMG_KERNEL_MODULE)
	SPRINT(szComment, "Flushing D cache: writing %08x to %08x", MASK_LTP_SYSC_DCACHE_FLUSH, LTP_SYSC_DCACHE_FLUSH);
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, szComment);
#endif

	/* Flush D cache */
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_SYSC_DCACHE_FLUSH, MASK_LTP_SYSC_DCACHE_FLUSH);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}
	/* Wait for flush completion */
	eRet = ltp_slave_single_read(psFWSoftImage, LTP_SYSC_DCACHE_FLUSH, &tmp);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}
#if ! defined (SYSBRG_NO_BRIDGING)
	if (tmp != MASK_LTP_SYSC_DCACHE_FLUSH)
#endif
	{
		eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAT, TAL_CHECKFUNC_ISEQUAL, MASK_LTP_SYSC_DCACHE_FLUSH, MASK_LTP_SYSC_DCACHE_FLUSH, SLAVE_INTERFACE_POLL_COUNT, SLAVE_INTERFACE_POLL_TIMEOUT);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "D cache flushing failed");
			return eRet;
		}
	}

#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Check the data cache flush completion");
#endif
	eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAX, TAL_CHECKFUNC_ISEQUAL, MASK_LTP_SYSC_DCACHE_FLUSH, MASK_LTP_SYSC_DCACHE_FLUSH, 1000, 10);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "D cache flushing didn't complete");
		return eRet;
	}

#if ! defined (IMG_KERNEL_MODULE)
	SPRINT(szComment, "Flushing I cache: writing %08x to %08x", MASK_LTP_SYSC_ICACHE_FLUSH, LTP_SYSC_ICACHE_FLUSH);
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, szComment);
#endif

	/* Flush I cache */
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_SYSC_ICACHE_FLUSH, MASK_LTP_SYSC_ICACHE_FLUSH);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}
	/* Wait for flush completion */
	eRet = ltp_slave_single_read(psFWSoftImage, LTP_SYSC_ICACHE_FLUSH, &tmp);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

#if ! defined (SYSBRG_NO_BRIDGING)
	if (tmp != MASK_LTP_SYSC_ICACHE_FLUSH)
#endif
	{
		eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAT, TAL_CHECKFUNC_ISEQUAL, MASK_LTP_SYSC_DCACHE_FLUSH, MASK_LTP_SYSC_ICACHE_FLUSH, SLAVE_INTERFACE_POLL_COUNT, SLAVE_INTERFACE_POLL_TIMEOUT);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "I cache flushing failed");
			return eRet;
		}
	}

#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Check the instruction cache flush completion");
#endif
	eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAX, TAL_CHECKFUNC_ISEQUAL, MASK_LTP_SYSC_ICACHE_FLUSH, MASK_LTP_SYSC_ICACHE_FLUSH, 1000, 10);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "I cache flushing didn't complete");
		return eRet;
	}

	/* Put MMU and caches in enhanced mode to enable them (after flush) */
	eRet = ltp_slave_single_read(psFWSoftImage, LTP_SYSC_CACHE_MMU_CONFIG, &ui32MMUCacheConfig);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}
	DEBUG_PRINT("\nSYSC_CACHE_MMU_CONFIG = %08x\n\n", ui32MMUCacheConfig);

	ui32MMUCacheConfig |= 0x6;
#if ! defined (IMG_KERNEL_MODULE)
	SPRINT(szComment, "Set MMU and caches in enhanced mode: writing %08x to %08x", ui32MMUCacheConfig, LTP_SYSC_CACHE_MMU_CONFIG);
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, szComment);
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_SYSC_CACHE_MMU_CONFIG, ui32MMUCacheConfig);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Enhanced mode enabling failed for both D and I caches");
		return eRet;
	}

	/* Check content of data cache partitioning */
	eRet = ltp_slave_single_read(psFWSoftImage, LTP_SYSC_DCPART0, &tmp);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}
	DEBUG_PRINT("\nSYSC_DCPART0 = %08x\n\n", tmp);

#if ! defined (IMG_KERNEL_MODULE)
	SPRINT(szComment, "Set content of data cache partitioning: writing %08x to %08x", tmp | MASK_LTP_GLOBAL_ADDR_MASK_T0 | MASK_LTP_LOCAL_ADDR_MASK_T0, LTP_SYSC_DCPART0);
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, szComment);
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_SYSC_DCPART0, tmp | MASK_LTP_GLOBAL_ADDR_MASK_T0 | MASK_LTP_LOCAL_ADDR_MASK_T0);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Data cache partitioning setting failed");
		return eRet;
	}

	/* Enable DCache */
#if ! defined (IMG_KERNEL_MODULE)
	SPRINT(szComment, "Enable D cache: writing 0x1 to %08x", LTP_MMCU_DCACHE_CTRL);
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, szComment);
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_MMCU_DCACHE_CTRL, 0x1);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "D cache enabling failed");
		return eRet;
	}

	/* Enable ICache */
#if ! defined (IMG_KERNEL_MODULE)
	SPRINT(szComment, "Enable I cache: writing 0x1 to %08x", LTP_MMCU_ICACHE_CTRL);
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, szComment);
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_MMCU_ICACHE_CTRL, 0x1);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "I cache enabling failed");
		return eRet;
	}

	/* Autoclock is set for both caches */
#if ! defined (IMG_KERNEL_MODULE)
	SPRINT(szComment, "Set autoclocking for both caches: writing %08x to %08x", F_ENCODE(0x2, LTP_ICACHE_CLK_CONTROL) | F_ENCODE(0x2, LTP_DCACHE_CLK_CONTROL), 0x04800000 | LTP_CR_LTP_CLKCTRL);
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, szComment);
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_CR_LTP_CLKCTRL, F_ENCODE(0x2, LTP_ICACHE_CLK_CONTROL) | F_ENCODE(0x2, LTP_DCACHE_CLK_CONTROL));
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Cache autoclock setting failed");
		return eRet;
	}

	/* Set both data and instruction cache win mode to "full normal operation" */
	eRet = ltp_slave_single_read(psFWSoftImage, LTP_MMCU_LOCAL_EBCTRL, &tmp);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}
	DEBUG_PRINT("\nMMCU_LOCAL_EBCTRL = %08x\n\n", tmp);

#if ! defined (IMG_KERNEL_MODULE)
	SPRINT(szComment, "(local) Set caches win mode to 'full normal operation': writing %08x to %08x", tmp | F_ENCODE(0x3, LTP_LOCAL_DC_WIN_MODE) | F_ENCODE(0x3, LTP_LOCAL_IC_WIN_MODE), LTP_MMCU_LOCAL_EBCTRL);
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, szComment);
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_MMCU_LOCAL_EBCTRL, tmp | F_ENCODE(0x3, LTP_LOCAL_DC_WIN_MODE) | F_ENCODE(0x3, LTP_LOCAL_IC_WIN_MODE));
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "(local) Cache win mode setting failed");
		return eRet;
	}

	eRet = ltp_slave_single_read(psFWSoftImage, LTP_MMCU_GLOBAL_EBCTRL, &tmp);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}
	DEBUG_PRINT("\nMMCU_GLOBAL_EBCTRL = %08x\n\n", tmp);

#if ! defined (IMG_KERNEL_MODULE)
	SPRINT(szComment, "(global) Set caches win mode to 'full normal operation': writing %08x to %08x", tmp | F_ENCODE(0x3, LTP_GLOBAL_DC_WIN_MODE) | F_ENCODE(0x3, LTP_GLOBAL_IC_WIN_MODE), LTP_MMCU_GLOBAL_EBCTRL);
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, szComment);
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_MMCU_GLOBAL_EBCTRL, tmp | F_ENCODE(0x3, LTP_GLOBAL_DC_WIN_MODE) | F_ENCODE(0x3, LTP_GLOBAL_IC_WIN_MODE));
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "(global) Cache win mode setting failed");
		return eRet;
	}
	DEBUG_PRINT("\nSYSC_CACHE_MMU_CONFIG = %08x\n\n", ui32MMUCacheConfig);

	return eRet;
}


/*!
* @fn ltp_waitCleanState
* @brief Waits for the LTP to finish any pending transaction on the slave port and checks bus errors
* @param psFWSoftImage Pointer to the context of the target LTP
*/
static IMG_RESULT ltp_waitCleanState(VXE_KM_FW_SOFT_IMAGE * psFWSoftImage)
{
	IMG_RESULT eRet;

	/* Wait for the slave port to indicate transactions have completed */
#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "Wait for 0xu7u0uuuu in MSLVCTRL1");
#endif
	eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVCTRL1, TAL_CHECKFUNC_ISEQUAL,
		MASK_LTP_CR_LTP_MSLV_PORT_RDY | MASK_LTP_CR_LTP_MSLV_COREMEM_IDLE | MASK_LTP_CR_LTP_MSLV_GLOB_REG_IDLE,
		MASK_LTP_CR_LTP_MSLV_PORT_RDY | MASK_LTP_CR_LTP_MSLV_COREMEM_IDLE | MASK_LTP_CR_LTP_MSLV_GLOB_REG_IDLE | MASK_LTP_CR_LTP_WR_IN_PROGRESS,
		SLAVE_INTERFACE_POLL_COUNT, SLAVE_INTERFACE_POLL_TIMEOUT);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "LTP pending transactions did not complete in time");
		return eRet;
	}

	/* Check that there are no bus errors, using a one shot poll since it is the expected way of things */
#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "Check that there are no bus errors");
#endif
	eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVCTRL1, TAL_CHECKFUNC_ISEQUAL, 0, MASK_LTP_CR_LTP_DEF_BUS_ERROR, 1, 1);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "LTP slave port reported a bus error");
		return eRet;
	}

	return eRet;
}


/*!
* @fn ltp_reset
* @brief Perform a reset of the LTP only
* @params psFWSoftImage Pointer to the context of the target LTP
*/
IMG_RESULT ltp_reset(VXE_KM_FW_SOFT_IMAGE * psFWSoftImage)
{
	IMG_RESULT eRet;
	IMG_UINT32 tmp;

	/* 1 - Disable the LTP core */
#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "Disabling LTP proc");
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_CR_LTP_ENABLE, 0x0);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

	/* 2 - Soft reset the LTP core */
	eRet = LTP_WriteSoftReset(psFWSoftImage);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

	eRet = ltp_slave_single_read(psFWSoftImage, LTP_SYSC_JTAG_THREAD, &tmp);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}
#if ! defined (SYSBRG_NO_BRIDGING)
	/* Skip the poll if possible */
	if ((tmp & MASK_LTP_SYSC_PRIVILEGE) == 0)
#endif
	{
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Waiting for privileges on the slave port");
#endif
		eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAT, TAL_CHECKFUNC_ISEQUAL, MASK_LTP_SYSC_PRIVILEGE, MASK_LTP_SYSC_PRIVILEGE, SLAVE_INTERFACE_POLL_COUNT, SLAVE_INTERFACE_POLL_TIMEOUT);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "Checking poll on privileges failed");
			return eRet;
		}
	}

	eRet = ltp_connectTriggers(psFWSoftImage);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Could not connect ltp trigger properly");
		return eRet;
	}

	/* 6 - Setup the write combiner (since we have one thread, only WRCOMBCONFIG4 will be used) */
#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Set write combiner partition 0 for thread 0 (offset 0), 1 line per partition");
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_WRCOMBCOMFIG4, 
		F_ENCODE(0, LTP_WRCOMB_PARTITION_OFFSET) |		/*no offset for partition 0*/
		F_ENCODE(0, LTP_WRCOMB_PARTITION_SIZE_LSB) |	/*1 lines in partition 0*/
		F_ENCODE(0, LTP_WRCOMB_PARTITION_ALLOC_ID) |	/*partition id matches thread id (0)*/
		F_ENCODE(0, LTP_WRCOMB_PARTITION_SIZE_MSB));	/*not setting MSB to have the desired number of lines*/
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Enabling write combiner for all addresses in global/local region (enhanced bypass mode)");
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_CR_MMCU_WRITECOMB_CTRL,
		F_ENCODE(LTP_WRCOMB_ALL_GLOB_LOC_ADDR_ENABLED, MMCU_WRITECOMB) |		/*write combiner is enabled for all addresses in global/local region (enhanced bypass mode)*/
		F_ENCODE(LTP_WRCOMB_ALL_GLOB_LOC_ADDR_WRITEABLE, MMCU_WRITEABLE));		/*all addresses are writeable*/
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Enabling write combiner (and automatic flush when lines are full)");
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_WRCOMBCONFIG0, 
		F_ENCODE(1, LTP_WRCOMB_ENABLED) |							/*write combiner is enabled*/
		F_ENCODE(1, LTP_WRCOMB_AUTO_FLUSH_LINE_FULL) |				/*automatic line flush is enabled*/
		F_ENCODE(1, LTP_WRCOMB_TIMEOUT_ENABLED) |					/*enabling timeout*/
		F_ENCODE(LTP_WR_COMB_TIMEOUT, LTP_WRCOMB_TIMEOUT_COUNT));	/*set a timeout of 100 cycles*/
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

	/* 7 - Setup Data and Instruction caches */
	{
		eRet = ltp_setupCaches(psFWSoftImage);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}
	}

	return eRet;
}


/*!
* @function ltp_enableMinim
* @brief Wrap MINIM instruction set enabling
* @param psFWSoftImage Pointer to the context of the target LTP
* @return
*	- IMG_SUCCESS on normal completion
*	- IMG_ERROR_TIMEOUT on error using the slave interface
*	- IMG_ERROR_NOT_INITIALISED if initialisation failed or is not already done
*	- IMG_ERROR_DEVICE_UNAVAILABLE if MINIM couldn't be enabled
*/
static IMG_RESULT ltp_enableMinim (VXE_KM_FW_SOFT_IMAGE* psFWSoftImage)
{
	IMG_UINT32 ui32Value;
	IMG_RESULT eRet;
	if (psFWSoftImage->bInitialized)
	{
		/* Explicitely turn on the MINIM instruction set in TXPRIVEXT */
		eRet = ltp_slave_single_read(psFWSoftImage, LTP_CR_LTP_PRIVEXT, &ui32Value);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}
		eRet = ltp_slave_single_write(psFWSoftImage, LTP_CR_LTP_PRIVEXT, ui32Value | MASK_LTP_MINIM_ENABLE);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}
		eRet = ltp_slave_single_read(psFWSoftImage, LTP_CR_LTP_PRIVEXT, &ui32Value);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}

		if ((ui32Value & MASK_LTP_MINIM_ENABLE) != MASK_LTP_MINIM_ENABLE)
		{
			IMG_ASSERT((ui32Value & MASK_LTP_MINIM_ENABLE) == MASK_LTP_MINIM_ENABLE);
			return IMG_ERROR_DEVICE_UNAVAILABLE;
		}

		return eRet;
	}

	return IMG_ERROR_NOT_INITIALISED;
}


/*!
* @function ltp_getLTPControlFromDash
* @brief Get exclusive control of the LTP slave interface
* @param psFWSoftImage Pointer to the context of the target LTP
* @return
*	- IMG_ERROR_BUSY if kernel already has control on dash
*	- IMG_ERROR_TIMEOUT if gpio_out pin did not go low in time
*	- IMG_SUCCESS on normal completion
*/
static IMG_RESULT ltp_getLTPControlFromDash(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage)
{
	IMG_RESULT eRet;
	/* We are going to read/write several registers */
	IMG_UINT32 ui32RegValue = 0;

	/* Control of the slave interface can only be granted once at a time */
	if (psFWSoftImage->bDriverHasProcCtrl)
	{
		IMG_ASSERT(!psFWSoftImage->bDriverHasProcCtrl);
		return IMG_ERROR_BUSY;
	}

	/* Request the bus control from the slave interface dash (bits [2:1] to 1) */
	ui32RegValue = F_ENCODE(0x2, QUARTZ_TOP_PROC_MSTR_DBG_GPIO_IN) | F_ENCODE(0x1, QUARTZ_TOP_PROC_MSTR_DBG_IS_SLAVE);
	TALREG_WriteWord32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_PROC_DEBUG_MSTR, ui32RegValue);

	/* Wait until the gpio_out pins have been set by the embedded processor */
#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_Comment(psFWSoftImage->hQuartzMultipipeMemSpace, "Polling for embedded core gpio_out to be zero");
#endif
	eRet = TALREG_Poll32(
		psFWSoftImage->hQuartzMultipipeMemSpace,
		QUARTZ_TOP_PROC_DEBUG_MSTR,
		TAL_CHECKFUNC_ISEQUAL,
		0,
		F_ENCODE(0x3, QUARTZ_TOP_PROC_MSTR_DBG_GPIO_OUT),
		400,
		1);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(IMG_SUCCESS == eRet && "dbg_gpio_out did not go low in time");
		return eRet;
	}

	/* Save the access control register */
	eRet = ltp_slave_single_read(psFWSoftImage, 0x04830000 | LTP_CR_LTP_RAM_ACCESS_CONTROL, &psFWSoftImage->ui32ProcRAMAccessControl);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

	/* We have now exclusive control on the slave interface */
	psFWSoftImage->bDriverHasProcCtrl = IMG_TRUE;

	return IMG_SUCCESS;
}


/*!
* @function ltp_releaseLTPControlFromDash
* @brief Release exclusive control of the LTP slave interface
* @param psFWSoftImage Pointer to the context of the target LTP
* @return
*	- IMG_ERROR_OPERATION_PROHIBITED if kernel does not have control on dash
*	- IMG_ERROR_TIMEOUT if LTP slave interface is locked up
*	- IMG_SUCCESS on normal completion
*/
static IMG_RESULT ltp_releaseLTPControlFromDash(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage)
{
	IMG_RESULT eRet;
	/* We are going to read/write several registers */
	IMG_UINT32 ui32RegValue = 0;

	/* We cannot release control if we don't have it already */
	if (!psFWSoftImage->bDriverHasProcCtrl)
	{
		IMG_ASSERT(psFWSoftImage->bDriverHasProcCtrl);
		return IMG_ERROR_OPERATION_PROHIBITED;
	}

	/* Restore the access control register to its previous value before taking its control */
	eRet = ltp_slave_single_write(psFWSoftImage, 0x04830000 | LTP_CR_LTP_RAM_ACCESS_CONTROL, psFWSoftImage->ui32ProcRAMAccessControl);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

	/* Release the bus by setting the JTAG port of the embedded processor to slave (shouldn't it be master?) */
	ui32RegValue = F_ENCODE(1, QUARTZ_TOP_PROC_MSTR_DBG_IS_SLAVE);
	TALREG_WriteWord32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_PROC_DEBUG_MSTR, ui32RegValue);

	/* We don't have control of the slave interface anymore */
	psFWSoftImage->bDriverHasProcCtrl = IMG_FALSE;

	return IMG_SUCCESS;
}

/*!
* @function ltp_readCoreReg
* @brief Read an LTP core register
* @param [in] psFWSoftImage Pointer to the context of the target LTP
* @param [in] ui32Reg Offset of register to read from
* @param [out] The value read from the register
* @return
*	- IMG_SUCCESS on normal completion
*/
static IMG_RESULT ltp_readCoreReg(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage, const IMG_UINT32 ui32Reg, IMG_UINT32 *pui32RegVal)
{
	/* Value read from the register */
	IMG_UINT32 ui32CoreRegValue = 0;
	IMG_UINT32 ui32Tmp = 0;
	IMG_RESULT eRet;

	/* First we want to get control of the slave interface */
	eRet = ltp_getLTPControlFromDash(psFWSoftImage);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}


	/*
	* Reading a core register through the slave register is done as follows:
	* 1-
	* Polling bits 24, 25 and 26 of MSLVCTRL1 being 1
	* Setting the address in MSVCTRL0 to be TXUXXRXRQ
	* Writting MSLVDATAT with the content of TXUXXRXRQ right:
	* - Setting RnW bit (bit 16 in TXUXXRXRQ register) to 1
	* - Setting the Unit and Register specifiers (bit 8:0 of the TXUXXRXRQ, passed as parameter and already set in the LSB)
	* - Setting the Thread specifier to 0, because LTP only has one
	* 2-
	* Polling bits 24, 25 and 26 of MSLVCTRL1 being 1
	* a) Setting the address in MSVCTRL0 to be TXUXXRXRQ
	* Polling bits 24, 25 and 26 of MSLVCTRL1 being 1
	* Reading content of MSLVDATAX:
	* - Waiting for the request to complete by polling DReady bit equal to 1 (bit 31 in TXUXXRXRQ register)
	* Repeating a) until condition is met
	* 3-
	* Polling bits 24, 25 and 26 of MSLVCTRL1 being 1
	* Setting the address in MSVCTRL0 to be TXUXXRXDT
	* Polling bits 24, 25 and 26 of MSLVCTRL1 being 1
	* Reading the content of MSLVDATAX register to have TXUXXRXDT content
	*/
	ui32CoreRegValue |= MASK_LTP_LTP_RNW | (ui32Reg & 0x1FF);

	eRet = ltp_slave_single_write(psFWSoftImage, LTP_CR_LTP_REGISTER_READ_WRITE_REQUEST, ui32CoreRegValue);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

	eRet = ltp_slave_single_read(psFWSoftImage, LTP_CR_LTP_REGISTER_READ_WRITE_REQUEST, &ui32Tmp);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

#if ! defined (SYSBRG_NO_BRIDGING)
	if ((ui32Tmp & MASK_LTP_LTP_DREADY) == 0)
#endif
	{
		eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAT, TAL_CHECKFUNC_ISEQUAL, MASK_LTP_LTP_DREADY, MASK_LTP_LTP_DREADY, SLAVE_INTERFACE_POLL_COUNT, SLAVE_INTERFACE_POLL_TIMEOUT);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "LTP never set ready bit");
			return eRet;
		}
	}

#if ! defined (IMG_KERNEL_MODULE)
	// Make sure in the out2.txt that we see it
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Wait for LTP register read to complete");
#endif
	eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAX, TAL_CHECKFUNC_ISEQUAL, MASK_LTP_LTP_DREADY, MASK_LTP_LTP_DREADY, 1000, 10);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Checking poll on dready failed");
		return eRet;
	}

	eRet = ltp_slave_single_read(psFWSoftImage, LTP_CR_LTP_REGISTER_READ_WRITE_DATA, &ui32CoreRegValue);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

#if ! defined (IMG_KERNEL_MODULE)
	// Make sure that everything is ok
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Check LTP register read data is as expected");
#endif
	eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAX, TAL_CHECKFUNC_ISEQUAL, ui32CoreRegValue, 0xffffffff, 1000, 10);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "Checking poll on read data failed");
		return eRet;
	}


	/* Release control of the slave interface */
	eRet = ltp_releaseLTPControlFromDash(psFWSoftImage);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

	/* Return the accessed value */
	*pui32RegVal = ui32CoreRegValue;

	return IMG_SUCCESS;
}


/*!
* @function ltp_writeCoreReg
* @brief Write an LTP core register
* @param psFWSoftImage Pointer to the context of the target LTP
* @param ui32Reg Offset of register to write
* @param ui32Val Value to write to register
* @return
*	- IMG_SUCCESS on normal completion
*/
static IMG_RESULT ltp_writeCoreReg(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage, const IMG_UINT32 ui32Reg, const IMG_UINT32 ui32Val)
{
	IMG_UINT32 ui32ControlReg = 0;
	IMG_UINT32 ui32Tmp = 0;
	IMG_RESULT eRet;

	/* First we want to get control of the slave interface */
	eRet = ltp_getLTPControlFromDash(psFWSoftImage);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

	// Wait to be sure we have priviledges on the slave interface
	//eRet = TALREG_Poll32(psFWSoftImage->hMetaRegMemspace, 0x30, TAL_CHECKFUNC_ISEQUAL, 0x4, 0xffffffff, 50000000, 200);

	/*
	* Writing a core register is done as follows:
	* 1-
	* Polling bits 24, 25 and 26 of MSLVCTRL1 being 1
	* Setting the address in MSVCTRL0 to be TXUXXRXDT | 0x00
	* Writting MSLVDATAT with the content of ui32Val
	* 2-
	* Polling bits 24, 25 and 26 of MSLVCTRL1 being 1
	* Setting the address in MSVCTRL0 to be TXUXXRXRQ | 0x00
	* Writting MSLVDATAT with:
	* - Setting RnW bit (bit 16 in TXUXXRXRQ register) to 0
	* - Setting the Unit and Register specifiers (bit 8:0 of the TXUXXRXRQ, passed as parameter and already set in the LSB)
	* - Setting the Thread specifier to 0, because LTP only has one
	* 3-
	* Polling bits 24, 25 and 26 of MSLVCTRL1 being 1
	* a) Setting the address in MSVCTRL0 to be TXUXXRXRQ
	* Polling bits 24, 25 and 26 of MSLVCTRL1 being 1
	* Reading content of MSLVDATAX:
	* - Waiting for the request to complete by polling DReady bit equal to 1 (bit 31 in TXUXXRXRQ register)
	* Repeating a) until condition is met
	*/
	ui32ControlReg |= (ui32Reg & 0x1FF);

	eRet = ltp_slave_single_write(psFWSoftImage, LTP_CR_LTP_REGISTER_READ_WRITE_DATA, ui32Val);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

	eRet = ltp_slave_single_write(psFWSoftImage, LTP_CR_LTP_REGISTER_READ_WRITE_REQUEST, ui32ControlReg);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

	eRet = ltp_slave_single_read(psFWSoftImage, LTP_CR_LTP_REGISTER_READ_WRITE_REQUEST, &ui32Tmp);
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}

#if ! defined (SYSBRG_NO_BRIDGING)
	if ((ui32Tmp & MASK_LTP_LTP_DREADY) == 0)
#endif
	{
		eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAT, TAL_CHECKFUNC_ISEQUAL, MASK_LTP_LTP_DREADY, MASK_LTP_LTP_DREADY, SLAVE_INTERFACE_POLL_COUNT, SLAVE_INTERFACE_POLL_TIMEOUT);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "LTP never set ready bit");
			return eRet;
		}
	}

	// Make sure in the out2.txt that we see it
#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Wait for LTP register write to complete");
#endif
	eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAX, TAL_CHECKFUNC_ISEQUAL, MASK_LTP_LTP_DREADY, MASK_LTP_LTP_DREADY, 1000, 10);
	if (IMG_SUCCESS != eRet)
	{
		IMG_ASSERT(eRet == IMG_SUCCESS && "ltp_writeCoreReg() did not find the right value after reading ");
		return eRet;
	}

	/* Release the dash now that the write completed */
	eRet = ltp_releaseLTPControlFromDash(psFWSoftImage);

	return eRet;
}


/*!
* @function ltp_selectFirmwareBuild
* @brief According to the codec which will be used for the encode, select a firmware build
* @params psFWSoftImage Pointer to the context of the target LTP
* @params eCodec Required codec support
*/
static IMG_RESULT ltp_selectFirmwareBuild(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage, VXE_CODEC eCodec)
{
#ifndef LOAD_FW_VIA_LINUX
	struct IMG_COMPILED_FW_BIN_RECORD *psSelectedBuild = IMG_NULL;
	struct IMG_COMPILED_FW_BIN_RECORD *psIter = IMG_NULL;
	/*
	* First of all, we need the build to support the codec we requested and 
	* if possible we would like to select the one build with the maximum number
	* of supported coded, encoder pipes. The number of pipe won't ever be more
	* than 4
	*/
	IMG_UINT32 ui32TargetFWPipes;
	IMG_UINT32 ui32FwBuildIndex;
	IMG_UINT32 ui32CodeSizeReq, ui32DataSizeReq;
	IMG_UINT32 ui32CurrentHWConfig;
	IMG_BOOL bPreferedFirmwareLocated = IMG_FALSE; // we may want to promote one build over another
	IMG_BOOL bPreferedFirmwareFits;

	if (eCodec == VXE_CODEC_NONE)
	{
		/* We don't want to go any further in this case */
		return IMG_ERROR_UNEXPECTED_STATE;
	}

	(void)ui32CodeSizeReq;
	(void)ui32DataSizeReq;

	ui32TargetFWPipes = psFWSoftImage->ui8QuartzHwPipes;

	/* A bit arbitrary (0 = rev1, 1 = rev2, ..) */
	ui32CurrentHWConfig = 1;
	if (0x50200 >= psFWSoftImage->ui32QuartzCoreRev)
	{
		ui32CurrentHWConfig = 0;
	}

	/* ui32AllFirmwareBinariesCount comes from include_all_fw_variants.h */
	for (ui32FwBuildIndex = 0; ui32FwBuildIndex < ui32AllFirmwareBinariesCount; ++ui32FwBuildIndex)
	{
		psIter = sAllFirmwareBinaries[ui32FwBuildIndex];
		if (strcmp("H264_H265", psIter->sFormat) == 0)
		{
			/* Our prefered build has been found */
			bPreferedFirmwareLocated = IMG_TRUE;
			ui32CodeSizeReq = psIter->ui32TextSize * 4;
			ui32DataSizeReq = psIter->ui32DataSize * 4;
			break;
		}
	}

	/* Now that we found our favorite build, we want to be sure it will fit. Otherwise we need a working build that fits */
	bPreferedFirmwareFits =
		bPreferedFirmwareLocated									// it has to be found
		&& ui32CurrentHWConfig == psIter->ui32HwConfig				// matching HW config
		&& ui32TargetFWPipes <= psIter->ui32Pipes					// enough pipes support
		&& (g_asLookupTableCodecToMask[eCodec].ui16CodecMask & psIter->ui32FormatsMask)	// this build supports the requested codec
		;

	if (bPreferedFirmwareFits)
	{
		/* Everything matches, this build will be the one */
		psSelectedBuild = psIter;
	}
	else
	{
		/* Actual formats requiring support by the build */
		IMG_UINT32 ui32FormatsMask = g_asLookupTableCodecToMask[eCodec].ui16CodecMask;

		/* More work required to find a 'good enough' one */
		for (ui32FwBuildIndex = 0; ui32FwBuildIndex < ui32AllFirmwareBinariesCount; ++ui32FwBuildIndex)
		{
			psIter = sAllFirmwareBinaries[ui32FwBuildIndex];
			if (ui32CurrentHWConfig != psIter->ui32HwConfig)
			{
				/* The hardware config needs to match regardless of anything else */
				continue;
			}

			/* Current build supports what's been requested, is it enough? .. */
			if (psIter->ui32FormatsMask & ui32FormatsMask)
			{
				/* Found ideal firmware version */
				if (psIter->ui32Pipes == ui32TargetFWPipes)
				{
					psSelectedBuild = psIter;
					break;
				}
				/* This firmware matches by format / mode combination, now to check if it fits better than current best .. */
				else if (!psSelectedBuild && psIter->ui32Pipes >= ui32TargetFWPipes)
				{
					/* .. so we select it */
					psSelectedBuild = psIter;
				}
			}
		}
	}

	/* At this point, we hopefully found a build that suits our requirements */
	if (!psSelectedBuild)
	{
		PRINT("Failed to find firmware build for format '%s' and RC mode '%s'\n", g_asLookupTableCodecToMask[eCodec].pszFormat, g_asLookupTableCodecToMask[eCodec].pszRCModes);
		return IMG_ERROR_COULD_NOT_OBTAIN_RESOURCE;
	}

	DEBUG_PRINT("\nUsing firmware: %s with %i pipes, hwconfig=%i (text size=%i, data size=%i) for requested codec: '%s' - RC mode '%s'\n\n",
		psSelectedBuild->sFormat, psSelectedBuild->ui32Pipes, psSelectedBuild->ui32HwConfig, psSelectedBuild->ui32TextSize, psSelectedBuild->ui32DataSize,
		g_asLookupTableCodecToMask[eCodec].pszFormat, g_asLookupTableCodecToMask[eCodec].pszRCModes);
	
	/* Export the selected build in psFWSoftImage for further usage */
	psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildTextSize	= psSelectedBuild->ui32TextSize;
	psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildDataSize	= psSelectedBuild->ui32DataSize;
	psFWSoftImage->sFirmwareBuildInfos.pui32FWText					= psSelectedBuild->pui32Text;
	psFWSoftImage->sFirmwareBuildInfos.pui32FWData					= psSelectedBuild->pui32Data;
	psFWSoftImage->sFirmwareBuildInfos.ui32FWDataOrigin				= psSelectedBuild->ui32DataOrigin;
	psFWSoftImage->sFirmwareBuildInfos.ui32FWBootStrap				= psSelectedBuild->ui32BootAddr;
	psFWSoftImage->sFirmwareBuildInfos.ui32NumPipes					= psSelectedBuild->ui32Pipes;
	psFWSoftImage->sFirmwareBuildInfos.ui32FWDefinesLength			= psSelectedBuild->ui32IntDefineCount;
	psFWSoftImage->sFirmwareBuildInfos.ppszFWDefineNames			= psSelectedBuild->pscIntDefineNames;
	psFWSoftImage->sFirmwareBuildInfos.pui32FWDefinesValues			= psSelectedBuild->pui32IntDefines;
	psFWSoftImage->sFirmwareBuildInfos.ui32FWSupportedCodecs		= psSelectedBuild->ui32FormatsMask;
	psFWSoftImage->sFirmwareBuildInfos.ui32FWNumContexts			= FW_TOTAL_CONTEXT_SUPPORT;
#else
        // Do nothing
#endif
	return IMG_SUCCESS;
}


/*!
* @function ltp_uploadfwByCopy
* @brief Since ltp has access to external memory, this function will copy the content of the firmware in it
* @param psDevContext Pointer on the device context associated with the hardware (KM layer)
* @param psFWSoftImage Pointer to the context of the target LTP
* @return
*	- IMG_SUCCESS on normal completion
*/
static IMG_RESULT ltp_uploadfwByCopy(VXE_KM_DEVCONTEXT* psDevContext, VXE_KM_FW_SOFT_IMAGE* psFWSoftImage)
{
	IMG_UINT32 ui32LoopIdx = 0;
	/*
	* We want to keep a long term reference on the firmware code/data in order to load them chunk by chunk
	* on the embedded LTP RAM. Using the ability of LTP to read external RAM, we will try to have only the
	* code currently in use on core memory - limiting its size - and cache misses will bring back the code
	* for usage. Prefetching the code could be interesting but harder because synchronous behaviour from the
	* kernel would be required
	*/
	IMG_UINT32 ui32TextSize = psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildTextSize;
	IMG_UINT32 ui32DataSize = psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildDataSize;

	(void)psDevContext;

	/* The upload of the firmware should only be the bootloader part, which will then access all from external memory */
	if (psFWSoftImage->bInitialized)
	{
		IMG_RESULT eRet;

#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_ConsoleMessage(psFWSoftImage->hLTPCodeRam, "Upload the firmware code/data in LTP RAM");
#endif

		// Text
		for (ui32LoopIdx = 0; ui32LoopIdx < ui32TextSize; ++ui32LoopIdx)
		{
			TALREG_WriteWord32(psFWSoftImage->hLTPCodeRam, ui32LoopIdx * 4, psFWSoftImage->sFirmwareBuildInfos.pui32FWText[ui32LoopIdx]);
		}
		// Data
		for (ui32LoopIdx = 0; ui32LoopIdx < ui32DataSize; ++ui32LoopIdx)
		{
			/* The first chunk of LTP data is for general purpose data */
			TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, sizeof(GENERAL_PURPOSE_DATA) + ui32LoopIdx * 4, psFWSoftImage->sFirmwareBuildInfos.pui32FWData[ui32LoopIdx]);
		}

		/* Explicitely turn on the MINIM instruction set in TXPRIVEXT */
		eRet = ltp_enableMinim(psFWSoftImage);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "MINIM instruction set could not be enabled");
			return eRet;
		}

#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_ConsoleMessage(TAL_MEMSPACE_ID_ANY, "ltp_uploadfwByCopy complete!");
#endif
	}

	return IMG_SUCCESS;
}


/*!
* @fn ltp_dmacTransfer
* @brief Reset the DMAC before performing the transfer as requested by the parameters
* @params psFWSoftImage Pointer on the firmware representation structure 
* @params ui32Channel Channel to use, probably ever going to be 0 since we use only one channel of the SoC DMAC
* @params psDevMemToCopy Pointer on the KM_DEVICE_BUFFER holding the memory to be copied
* @params ui32SrcOffset Offset in the previous parameter
* @params ui32DevAddr Target address where to do the DMAC operation
* @params ui32WordsToCopy How many word from <psDevMemToCopy> to be copied (byte_count / 4)
* @params bIsRead Type of DMA operation
* @return
*	- IMG_ERROR_MMU_PAGE_TABLE_FAULT if a page fault ever occur
*	- IMG_ERROR_BUSY if the DMAC is not inactive before setting it for the new transaction
*	- IMG_ERROR_TIMEOUT if the DMAC polling failed
*	- IMG_ERROR_FATAL if IRQ clearing failed
*	- IMG_ERROR_INVALID_PARAMETERS if burst size is not correct
*	- IMG_ERROR_OPERATION_PROHIBITED if transfer size is not correctly aligned
*	- IMG_ERROR_NOT_SUPPORTED if the channel parameter is invalid
*	- IMG_SUCCESS on normal completion
*/
static IMG_RESULT ltp_dmacTransfer(VXE_KM_FW_SOFT_IMAGE *psFWSoftImage, IMG_UINT32 ui32Channel, KM_DEVICE_BUFFER *psDevMemToCopy, IMG_UINT32 ui32SrcOffset,
	IMG_UINT32 ui32DevAddr, IMG_UINT32 ui32WordsToCopy, IMG_BOOL bIsRead)
{
	IMG_UINT32 ui32DMACIRQ;
	IMG_UINT32 ui32CountReg;
	IMG_HANDLE hDmacRegs;
	IMG_HANDLE hMMURegs = psFWSoftImage->hMMURegs;
	IMG_UINT32 ui32MMUStatus = 0;
	IMG_RESULT eRetPoll;

	IMG_UINT32 ui32DmacBurstSize = 2;	// 2 * 128 bits = 32 bytes
	IMG_UINT32 ui32ProcBurstSize = 4;	// 4 * 2 * 32 bits = 32 bytes

	/* Check the burst sizes */
	if (DMAC_BURSTSIZE_BYTES != ui32DmacBurstSize * 16)
	{
		IMG_ASSERT(DMAC_BURSTSIZE_BYTES == ui32DmacBurstSize * 16); (void)ui32DmacBurstSize;
		return IMG_ERROR_INVALID_PARAMETERS;
	}
	if (DMAC_BURSTSIZE_BYTES != ui32ProcBurstSize * 8)
	{
		IMG_ASSERT(DMAC_BURSTSIZE_BYTES == ui32ProcBurstSize * 8); (void)ui32ProcBurstSize;
		return IMG_ERROR_INVALID_PARAMETERS;
	}

	/* Check transfer size matches burst width (in 32 words) */
	if (0 != (ui32WordsToCopy & ((DMAC_BURSTSIZE_BYTES >> 2) - 1)))
	{
		IMG_ASSERT(0 == (ui32WordsToCopy & ((DMAC_BURSTSIZE_BYTES >> 2) - 1)));
		return IMG_ERROR_OPERATION_PROHIBITED;
	}

	/* Check DMA channel */
	if (ui32Channel >= DMAC_MAX_CHANNELS)
	{
		IMG_ASSERT(ui32Channel < DMAC_MAX_CHANNELS);
		return IMG_ERROR_NOT_SUPPORTED;
	}

	/* Check that no transfer is currently in progress */
	hDmacRegs = psFWSoftImage->hDMACRegs;
	TALREG_ReadWord32(hDmacRegs, IMG_SOC_DMAC_COUNT(ui32Channel), &ui32CountReg);
	IMG_ASSERT(0 == (ui32CountReg & (MASK_IMG_SOC_EN | MASK_IMG_SOC_LIST_EN)));

	/* Check we don't already have a page fault condition */
	TALREG_ReadWord32(hMMURegs, IMG_BUS4_MMU_STATUS0, &ui32MMUStatus);
	IMG_ASSERT(0 == ui32MMUStatus);

	if (ui32MMUStatus || (ui32CountReg & (MASK_IMG_SOC_EN | MASK_IMG_SOC_LIST_EN)))
	{
		/* DMA engine not idle or pre-existing page fault condition, so we immediately exit */
		psFWSoftImage->bInitialized = IMG_FALSE;
		return ui32MMUStatus ? IMG_ERROR_MMU_PAGE_TABLE_FAULT : IMG_ERROR_BUSY;
	}

	/* Clear status of any previous interrupts, since we know the DMAC is idle */
	TALREG_WriteWord32(hDmacRegs, IMG_SOC_DMAC_IRQ_STAT(ui32Channel), 0);

	/* Double check outstanding interrupts */
	TALREG_ReadWord32(hDmacRegs, IMG_SOC_DMAC_IRQ_STAT(ui32Channel), &ui32DMACIRQ);
	if (0 != ui32DMACIRQ)
	{
		IMG_ASSERT(0 == ui32DMACIRQ);
		return IMG_ERROR_FATAL;
	}

	/* Write System DMAC registers - per hold - allow HW to sort itself out */
	TALREG_WriteWord32(hDmacRegs, IMG_SOC_DMAC_PER_HOLD(ui32Channel), 16);
	/* Place the virtual address 28 first bits in the DMAC Setup register */
	writeMemoryRef(hDmacRegs, IMG_SOC_DMAC_SETUP(ui32Channel), psDevMemToCopy, ui32SrcOffset);

	/* Set Count reg : no bytes swap, 32 bits target, write operation, 4 bytes increment, number of words to copy but don't enable it */
	ui32CountReg = DMAC_VALUE_COUNT(DMAC_BSWAP_NO_SWAP, DMAC_PWIDTH_32_BIT, bIsRead, DMAC_PWIDTH_32_BIT, ui32WordsToCopy);
	ui32CountReg |= MASK_IMG_SOC_TRANSFER_IEN;	/* Generate an interrupt at end of transfer */
	TALREG_WriteWord32(hDmacRegs, IMG_SOC_DMAC_COUNT(ui32Channel), ui32CountReg);

	/* Auto inc address, set burst size + no delay */
	TALREG_WriteWord32(hDmacRegs, IMG_SOC_DMAC_PERIPH(ui32Channel), DMAC_VALUE_PERIPH_PARAM(DMAC_ACC_DEL_0, IMG_TRUE, ui32DmacBurstSize));

	/* Target correct proc DMAC port */
	TALREG_WriteWord32(hDmacRegs, IMG_SOC_DMAC_PERIPHERAL_ADDR(ui32Channel), ui32DevAddr);

	/* Finally, rewrite the count register with the enable bit set to kick off the transfer */
	TALREG_WriteWord32(hDmacRegs, IMG_SOC_DMAC_COUNT(ui32Channel), ui32CountReg | MASK_IMG_SOC_EN);

	/* Wait for it to finish */
#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_VerboseComment(hDmacRegs, "Wait for DMAC to finish");
#endif
	eRetPoll = TALREG_Poll32(hDmacRegs, IMG_SOC_DMAC_IRQ_STAT(ui32Channel), TAL_CHECKFUNC_ISEQUAL, F_ENCODE(1, IMG_SOC_TRANSFER_FIN), F_ENCODE(1, IMG_SOC_TRANSFER_FIN), 1000, DMAC_FW_LOAD_TIMEOUT);

	TALREG_ReadWord32(hDmacRegs, IMG_SOC_DMAC_COUNT(ui32Channel), &ui32CountReg);
	TALREG_ReadWord32(hMMURegs, IMG_BUS4_MMU_STATUS0, &ui32MMUStatus);

	if (ui32MMUStatus || (ui32CountReg & (MASK_IMG_SOC_EN | MASK_IMG_SOC_LIST_EN)))
	{
		/* DMA has failed or page faulted */
		psFWSoftImage->bInitialized = IMG_FALSE;
	}

	/* Clear the interrupt (both in the DMAC and multipipe banks) */
	TALREG_WriteWord32(hDmacRegs, IMG_SOC_DMAC_IRQ_STAT(ui32Channel), 0);
	TALREG_WriteWord32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_MULTIPIPE_INT_CLEAR, MASK_QUARTZ_TOP_INTCLR_DMAC);

	return eRetPoll;
}


/*!
* @function ltp_uploadfwByDMA
* @brief Usage the DMAC, this function will copy the content of the firmware in it
* @param psDevContext Pointer on the device context associated with the hardware (KM layer)
* @param psFWSoftImage Pointer to the context of the target LTP
*/
static IMG_RESULT ltp_uploadfwByDMAC(VXE_KM_DEVCONTEXT* psDevContext, VXE_KM_FW_SOFT_IMAGE* psFWSoftImage)
{
	/*
	* We only do the allocations for code and data memory once, so that on power transitions we only
	* do the update. This function will set all register value to use the DMAC to load code/data.
	* Ideally, the firmware would be able to program the DMAC itself to load its code and data, leaving
	* the KM only polling for its bootstatus register.
	*/
	KM_DEVICE_BUFFER *pText = NULL, *pData = NULL;
	IMG_UINT32 ui32TextSize = ((psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildTextSize + 15) &~15); /*MINIM alignment*/
	IMG_UINT32 ui32DataSize = psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildDataSize;
	IMG_RESULT eRet = IMG_SUCCESS;

	(void)psDevContext;

	/* We fill the copies */
	pText = (KM_DEVICE_BUFFER*)psFWSoftImage->pvText;
	pData = (KM_DEVICE_BUFFER*)psFWSoftImage->pvData;

	/* The Kernel allocation is kept, we only update what the device can see */
	updateDeviceMemory(pText);
	updateDeviceMemory(pData);

	/* Align the transfer size to the DMAC burst size to be sure we do a complete number of burst */
	ui32TextSize = VXE_ALIGN(ui32TextSize * 4, DMAC_BURSTSIZE_BYTES) / 4;
	ui32DataSize = VXE_ALIGN(ui32DataSize * 4, DMAC_BURSTSIZE_BYTES) / 4;

	if (ui32DataSize*4 > psFWSoftImage->ui32CoreDataRAM || ui32TextSize*4 > psFWSoftImage->ui32CoreCodeRAM)
	{
		IMG_ASSERT(ui32DataSize*4 <= psFWSoftImage->ui32CoreDataRAM && ui32TextSize*4 <= psFWSoftImage->ui32CoreCodeRAM);
		psFWSoftImage->bInitialized = IMG_FALSE;
		return IMG_ERROR_OUT_OF_MEMORY;
	}

	/* The upload of the firmware should only be the bootloader part, which will then access all from external memory */
#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_ConsoleMessage(psFWSoftImage->hLTPCodeRam, "Upload the firmware code in LTP RAM using DMAC");
#endif
	if (psFWSoftImage->bInitialized)
	{
		/* Transfer text section */
		eRet = ltp_dmacTransfer(psFWSoftImage, 0, pText, 0, QUARTZ_PROC_CODE_BASE_ADDR, ui32TextSize, IMG_FALSE);
		if (eRet != IMG_SUCCESS)
		{
			PRINT("ERROR - Firmware code section load failed with [%d]\n", eRet);
#if defined (DEBUG_REG_OUTPUT)
			DBG_dump_reg_and_page((void*)psDevContext);
#endif
			return eRet;
		}
	}
	if (psFWSoftImage->bInitialized)
	{
		/* Transfer data section */
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_ConsoleMessage(psFWSoftImage->hLTPCodeRam, "Upload the firmware data in LTP RAM using DMAC");
#endif
		eRet = ltp_dmacTransfer(psFWSoftImage, 0, pData, 0, QUARTZ_PROC_DATA_BASE_ADDR + sizeof(GENERAL_PURPOSE_DATA), ui32DataSize, IMG_FALSE);
		if (eRet != IMG_SUCCESS)
		{
			PRINT("ERROR - Firmware data section load failed with [%d]\n", eRet);
			return eRet;
		}
	}

	/* Flush the MMU table cache used during code download */
	QUARTZKM_MMUFlushMMUTableCache((void*)psDevContext);

	if (psFWSoftImage->bInitialized)
	{
		eRet = ltp_enableMinim(psFWSoftImage);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "MINIM instruction set could not be enabled");
			return eRet;
		}

#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_ConsoleMessage(psFWSoftImage->hLTPDataRam, "ltp_uploadfwByDMAC complete!");
#endif
	}

	return IMG_SUCCESS;
}


static IMG_RESULT ltp_uploadfwByBootloader(VXE_KM_DEVCONTEXT* psDevContext, VXE_KM_FW_SOFT_IMAGE* psFWSoftImage)
{
	/*
	* We only do the allocations for code and data memory once, so that on power transitions we only
	* do the update. This function will set some general purpose register value to inform the bootloader
	* on the FW side about where and how big the code/data regions are.
	*/
	KM_DEVICE_BUFFER *pText = NULL, *pData = NULL;
	IMG_UINT32 ui32TextSize = psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildTextSize;
	IMG_UINT32 ui32DataSize = psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildDataSize;

	(void)psDevContext;

	/* We fill the copies */
	pText = (KM_DEVICE_BUFFER*)psFWSoftImage->pvText;
	pData = (KM_DEVICE_BUFFER*)psFWSoftImage->pvData;

	/* The Kernel allocation is kept, we only update what the device can see */
	updateDeviceMemory(pText);
	updateDeviceMemory(pData);

	/* Align the transfer size to the DMAC burst size to be sure we do a complete number of burst */
	ui32TextSize = VXE_ALIGN(ui32TextSize * 4, DMAC_BURSTSIZE_BYTES) / 4;
	ui32DataSize = VXE_ALIGN(ui32DataSize * 4, DMAC_BURSTSIZE_BYTES) / 4;
	if (ui32DataSize * 4 > psFWSoftImage->ui32CoreDataRAM || ui32TextSize * 4 > psFWSoftImage->ui32CoreCodeRAM)
	{
		IMG_ASSERT(ui32DataSize * 4 <= psFWSoftImage->ui32CoreDataRAM && ui32TextSize * 4 <= psFWSoftImage->ui32CoreCodeRAM);
		psFWSoftImage->bInitialized = IMG_FALSE;
		return IMG_ERROR_OUT_OF_MEMORY;
	}

	/*
	* We will use data register space since the DMA'ing of it from external memory will override the four initial values we placed in
	* (it is a non intrusive way of sending these four key values to firmware)
	* Layout will be:
	* [code external start address][code section size][data external start address][data section size]
	*/

	/* Send the code first */
	writeMemoryRef(psFWSoftImage->hLTPDataRam, FW_FEEDBACK_FIFO_END, pText, 0);
	TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_FEEDBACK_FIFO_END + 0x4, ui32TextSize);

	/* Send the data */
	writeMemoryRef(psFWSoftImage->hLTPDataRam, FW_FEEDBACK_FIFO_END + 0x8, pData, 0);
	TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_FEEDBACK_FIFO_END + 0xc, ui32DataSize);

	/* Flush the MMU table cache used during code download */
	if (IMG_FALSE == QUARTZKM_MMUFlushMMUTableCache((void*)psDevContext))
	{
		return IMG_ERROR_MMU_PAGE_TABLE_FAULT;
	}

	if (psFWSoftImage->bInitialized)
	{
		IMG_RESULT eRet;
		IMG_UINT32 ui32Reg;
		eRet = ltp_enableMinim(psFWSoftImage);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "MINIM instruction set could not be enabled");
			return eRet;
		}

		/* Tell FW to use bootloader */
		TALREG_ReadWord32(psFWSoftImage->hLTPDataRam, FW_REG_FEEDBACK_CONSUMER, &ui32Reg);
		ui32Reg = F_INSERT(ui32Reg, 1, FW_USE_BOOTLOADER);
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_REG_FEEDBACK_CONSUMER, ui32Reg);

		/* Mark bootload setup as complete in pdump */
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_ConsoleMessage(psFWSoftImage->hLTPDataRam, "ltp_uploadfwByBootloader complete!");
#endif
	}

	return IMG_SUCCESS;
}


/************************************************* PUBLIC FUNCTIONS ********************************************************/

/*!
* @fn LTP_Initialize
* @brief Initialize the firmware image to prepare its load on the LTP embedded processor
* @param psFWSoftImage Pointer to the context of the target LTP
* @return
*	- IMG_SUCCESS on normal completion
*	- IMG_ERROR_NOT_INITIALISED if LTP is not initialised
*	- IMG_ERROR_MALLOC_FAILED if the register local copy can't be allocated
*/
IMG_RESULT LTP_Initialize(VXE_KM_FW_SOFT_IMAGE * psFWSoftImage)
{
	/* The firmware needs only one init */
	if (psFWSoftImage->bInitialized)
	{
		return IMG_ERROR_ALREADY_INITIALISED;
	}

	/* The core register current values need saving when the LTP processor is turned off */
	psFWSoftImage->pui32ProcRegisterCopy = TRACK_MALLOC(SAVED_REGISTERS_APM * sizeof(IMG_UINT32));
	if (!psFWSoftImage->pui32ProcRegisterCopy)
	{
		PRINT("LTP_Initialize() error: Core register copy allocation failed, power management will not be possible\n");
		/* Is this error a blocking problem or could it just disable the power management and inform the user? */
		return IMG_ERROR_MALLOC_FAILED;
	}
	IMG_MEMSET(psFWSoftImage->pui32ProcRegisterCopy, 0x0, SAVED_REGISTERS_APM * sizeof(IMG_UINT32));



	psFWSoftImage->bInitialized = IMG_TRUE;

	return IMG_SUCCESS;
}


/*!
* @fn LTP_Deinitialize
* @brief Deinitialize the FW loaded on the LTP embedded processor
* @param psFWSoftImage Pointer to the context of the target LTP
*/
IMG_VOID LTP_Deinitialize(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage)
{
	if (!psFWSoftImage->bInitialized)
	{
		/*
		* Earlier error conditions may have de-initialised the device to prevent its usage
		* but the memory mapping have been left untouched so the hardware will not page
		* fault and caused bursts of interrupts.
		* This function will be called to come back to a sane situation, and since everythin
		* is protected against double-free, it will be given a chance to execute.
		*/
		PRINT("Warning detected multi de-initializations\n");
	}



	/* Free the core registers' copy */
	if (psFWSoftImage->pui32ProcRegisterCopy)
	{
		TRACK_FREE(psFWSoftImage->pui32ProcRegisterCopy);
		psFWSoftImage->pui32ProcRegisterCopy = IMG_NULL;
	}

	{
		/* Free the text/data section copy */
		if (psFWSoftImage->pvText)
		{
			freeMemory((KM_DEVICE_BUFFER**)&psFWSoftImage->pvText);
			psFWSoftImage->pvText = IMG_NULL;
		}
		if (psFWSoftImage->pvData)
		{
			freeMemory((KM_DEVICE_BUFFER**)&psFWSoftImage->pvData);
			psFWSoftImage->pvData = IMG_NULL;
		}
	}

	/* Firmware is now deinitialized */
	psFWSoftImage->bInitialized = IMG_FALSE;
}


/*!
* @fn LTP_Start
* @brief Turn on the LTP embedded processor
* @param psFWSoftImage Pointer to the context of the target LTP
* @return
*	- IMG_SUCCESS on normal completion
*	- IMG_ERROR_NOT_INITIALISED if LTP is not initialised
*	- IMG_ERROR_TIMEOUT if LTP slave interface did not reply in time
*/
IMG_RESULT LTP_Start(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage)
{
	IMG_RESULT eRet;

	/* We wouldn't want to turn on an uninitialized processor */
	IMG_ASSERT(psFWSoftImage->bInitialized);
	if (!psFWSoftImage->bInitialized)
	{
		return IMG_ERROR_NOT_INITIALISED;
	}


	/* Turn on the thread */
#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "Turn on the LTP thread0");
#endif
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_CR_LTP_ENABLE, MASK_LTP_LTP_ENABLE);
	return eRet;
}


/*!
* @fn LTP_Stop
* @brief Stop the LTP embedded processor
* @param psFWSoftImage Pointer to the context of the target LTP
* @return
*	- IMG_SUCCESS on normal completion
*	- IMG_ERROR_NOT_INITIALISED if LTP is not initialised
*	- IMG_ERROR_TIMEOUT if LTP slave interface did not reply in time
*/
IMG_RESULT LTP_Stop(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage)
{
	IMG_UINT32 tmp;
	IMG_RESULT eRet;

	(void)tmp;

	/* We wouldn't want to turn off an uninitialized processor */
	if (!psFWSoftImage->bInitialized)
	{
		IMG_ASSERT(psFWSoftImage->bInitialized);
		return IMG_ERROR_NOT_INITIALISED;
	}


#if defined (SYSBRG_NO_BRIDGING) || (defined(IMG_KERNEL_MODULE) && (KM_VERBOSE_LEVEL > 0))
	/* Some check */
	eRet = ltp_slave_single_read(psFWSoftImage, LTP_CR_LTP_ACTCYC, &tmp); // cycle count
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}
	DEBUG_PRINT("active cycles = %d [%d]\n", tmp, F_DECODE(tmp, LTP_CYCLE_ACTIVE));

	eRet = ltp_slave_single_read(psFWSoftImage, LTP_CR_LTP_IDLCYC, &tmp); // cycle count
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}
	DEBUG_PRINT("idle cycles = %d [%d]\n", tmp, F_DECODE(tmp, LTP_CYCLE_IDLE));

	eRet = ltp_slave_single_read(psFWSoftImage, LTP_CR_LTP_CLKCTRL, &tmp); // clocks (cache clock too)
	if (IMG_SUCCESS != eRet)
	{
		return eRet;
	}
	DEBUG_PRINT("clock = %08x [d:%02x | i:%02x]\n", tmp, F_DECODE(tmp, LTP_DCACHE_CLK_CONTROL), F_DECODE(tmp, LTP_ICACHE_CLK_CONTROL));
#endif

	/* Access the LTP_ENABLE register to turn it off */
	TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "Turn off the LTP thread0");
	/* All other fields than ThreadEnable are read only, so we can safely write zero to it */
	eRet = ltp_slave_single_write(psFWSoftImage, LTP_CR_LTP_ENABLE, 0x0);

	return eRet;
}


/*!
* @fn LTP_EnableDisable
* @brief Abstracts real/fake firmware behaviour for enabling/disabling LTP (fake does nothing)
* @param psFWSoftImage Pointer to the context of the target LTP
* @param bEnable Should the LTP be enabled (1) or disabled (0)
* @return
*	- IMG_SUCCESS on normal completion
*/
IMG_RESULT LTP_EnableDisable(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage, IMG_BOOL bEnable)
{
	{
		return ltp_slave_single_write(psFWSoftImage, LTP_CR_LTP_ENABLE, bEnable);
	}
}


/*!
* @fn ltp_writeSoftReset
* @brief Wraps the LTP soft reset register write(s)
* @param psFWSoftImage Pointer to the context of the target LTP
* @return IMG_SUCCESS
*/
IMG_RESULT LTP_WriteSoftReset(VXE_KM_FW_SOFT_IMAGE * psFWSoftImage)
{
	//#define RESET_LTP_WITH_MULTICORE_BANK
	/* Write soft reset bit in the slave soft reset register */
	TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "Soft reset LTP through the slave interface");
	TALREG_WriteWord32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVSRST, MASK_LTP_SOFT_RESET);

	/* Wait at least 16 cycles (large margin by waiting 32 cycles) */
#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Wait 32 cycles before clearing the reset");
#endif
	TAL_Wait(psFWSoftImage->hLTPRegMemspace, 32);

	/* Clear soft reset bit */
	TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "Clear LTP soft reset");
	TALREG_WriteWord32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVSRST, 0);

	/* Following the soft reset, wait an extra 16 cycles to make sure */
#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Wait 16 cycles following the soft reset");
#endif
	TAL_Wait(psFWSoftImage->hLTPRegMemspace, 16);

	return IMG_SUCCESS;
}


/*!
* @fn LTP_Kick
* @brief Issue <ui32KickCount> kick(s) to the LTP core through its dedicated register (background kick)
* @param psFWSoftImage Pointer to the context of the target LTP
* @param ui32KickCount Number of kick to issue
* @details
* Using the background kick register, this function will issue a defined number of
* kicks. If multiple kicks at once are possible, in practice we only issue kick one-by-one.
* The <ui32KickCount> parameter will ever be 1.
* @return
*	- IMG_SUCCESS on normal completion
*	- IMG_ERROR_NOT_INITIALISED if LTP is not initialised
*/
IMG_RESULT LTP_Kick(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage, IMG_UINT32 ui32KickCount)
{
	/* We wouldn't want to kick an uninitialized processor */
	if (!psFWSoftImage->bInitialized)
	{
		IMG_ASSERT(psFWSoftImage->bInitialized);
		return IMG_ERROR_NOT_INITIALISED;
	}

#if ! defined (IMG_KERNEL_MODULE)
	TALPDUMP_ConsoleMessage(psFWSoftImage->hLTPRegMemspace, "Kick the LTP");
#endif
	TALREG_WriteWord32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVKICK0, ui32KickCount);

	return IMG_SUCCESS;
}


/*!
* @fn LTP_WaitForCompletion
* @brief Wait for the LTP embedded processor to shutdown
* @param psFWSoftImage Pointer to the context of the target LTP
* @return
*	- IMG_SUCCESS on normal completion
*	- IMG_ERROR_NOT_INITIALISED if LTP is not initialised
*	- IMG_ERROR_TIMEOUT if LTP slave interface did not reply in time
*/
IMG_RESULT LTP_WaitForCompletion(VXE_KM_FW_SOFT_IMAGE* psFWSoftImage)
{
	IMG_RESULT eRet;
	IMG_UINT32 ui32Tmp = 0;

	/* We wouldn't want to turn off an uninitialized processor */
	if (!psFWSoftImage->bInitialized)
	{
		IMG_ASSERT(psFWSoftImage->bInitialized);
		return IMG_ERROR_NOT_INITIALISED;
	}

	/* When using a fake fw, the code won't be loaded. If this field is not set we should exit straighaway */
	if (psFWSoftImage->eLoadMethod != LTP_LOADMETHOD_NONE)
	{
		/* Wait for the LTP_ENABLE register to acknowledge a complete shutdown */
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "Waiting for the shutdown completion");
#endif
		/* Poll the bit 1 of the LTP_ENABLE register */
		eRet = ltp_slave_single_read(psFWSoftImage, LTP_CR_LTP_ENABLE, &ui32Tmp);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}
#if ! defined (SYSBRG_NO_BRIDGING)
		if ((ui32Tmp & MASK_LTP_LTP_TOFF) == 0)
#endif
		{
#if ! defined (IMG_KERNEL_MODULE)
			TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Polling TOff bit to be 1 (triggering new transaction every time it is not)");
#endif
			eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAT, TAL_CHECKFUNC_ISEQUAL,
				MASK_LTP_LTP_TOFF, MASK_LTP_LTP_TOFF, SLAVE_INTERFACE_POLL_COUNT, SLAVE_INTERFACE_POLL_TIMEOUT);
			IMG_ASSERT(eRet == IMG_SUCCESS && "LTP has not been successfully turned off");
			if (IMG_SUCCESS != eRet)
			{
				return eRet;
			}
		}

#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_VerboseComment(psFWSoftImage->hLTPRegMemspace, "Checking TOff bit value after active polling");
#endif
		eRet = TALREG_Poll32(psFWSoftImage->hLTPRegMemspace, LTP_CR_MSLVDATAX, TAL_CHECKFUNC_ISEQUAL,
			MASK_LTP_LTP_TOFF, MASK_LTP_LTP_TOFF, SLAVE_INTERFACE_POLL_COUNT, SLAVE_INTERFACE_POLL_TIMEOUT);
		IMG_ASSERT(eRet == IMG_SUCCESS && "Poll failled on LTP Slave interface TOFF bit");
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}
	}

	return IMG_SUCCESS;
}


/*!
* @fn LTP_PopulateFirmwareContext
* @brief Set a number of required information to upload the firmware on device memory
* @param psFWSoftImage Pointer to the context of the target LTP
* @param eCodec Codec to be used for this firmware (comes from the codec selected when openning the socket)
* @return
*	- IMG_SUCCESS if the firmware context has been populated and a firmware build matches the requirement
*	- IMG_ERROR_GENERIC_FAILURE if the number of pipes is not correct
*/
IMG_RESULT LTP_PopulateFirmwareContext(IMG_HANDLE pvDevContext, VXE_CODEC eCodec)
{
	IMG_UINT32 ui32ProcConfigReg;
	VXE_KM_DEVCONTEXT *psDevContext;
	VXE_KM_FW_SOFT_IMAGE * psFWSoftImage;

	psDevContext = (VXE_KM_DEVCONTEXT*)pvDevContext;
	psFWSoftImage = &psDevContext->sFWSoftImage;

	/* Grant access to register bank required later */
	/* The FW software representation needs access to the multipipe region */
	psFWSoftImage->hQuartzMultipipeMemSpace = psDevContext->sDevSpecs.hQuartzMultipipeBank;
	psFWSoftImage->hLTPRegMemspace = psDevContext->sDevSpecs.hQuartzLTPBank;
	psFWSoftImage->hLTPDataRam = psDevContext->sDevSpecs.hLTPDataRam;
	psFWSoftImage->hLTPCodeRam = psDevContext->sDevSpecs.hLTPCodeRam;
	psFWSoftImage->hMMURegs = psDevContext->sDevSpecs.hQuartzMMUBank;
	psFWSoftImage->hDMACRegs = psDevContext->sDevSpecs.hQuartzDMACBank;

	TALREG_ReadWord32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_QUARTZ_CORE_REV, &(psFWSoftImage->ui32QuartzCoreRev));
	/* The QUARTZ_DESIGNER field is not of use for the driver */
	psFWSoftImage->ui32QuartzCoreRev &= (MASK_QUARTZ_TOP_QUARTZ_MAINT_REV | MASK_QUARTZ_TOP_QUARTZ_MINOR_REV | MASK_QUARTZ_TOP_QUARTZ_MAJOR_REV);

	TALREG_ReadWord32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_QUARTZ_CONFIG, &(psFWSoftImage->ui32QuartzConfig));
	/* The number of supported pipe is included in bit [2:0] of the QUARTZ_CONFIG register, no need to call TAL again */
	psFWSoftImage->ui8QuartzHwPipes = F_EXTRACT(psFWSoftImage->ui32QuartzConfig, QUARTZ_TOP_QUARTZ_NUM_ENCODER_PIPES);

	/* Check that the number of pipes is coherent */
	if (psFWSoftImage->ui8QuartzHwPipes > QUARTZ_MAX_PIPES)
	{
		/* This is very unlikely, and probably means that it is not a quartz HW */
		PRINT("ERROR: Quartz HW reported %i pipes, supported number of pipes [1:%i]", psFWSoftImage->ui8QuartzHwPipes, QUARTZ_MAX_PIPES - 1);
		return IMG_ERROR_GENERIC_FAILURE;
	}


	/* Extract code and data ram size for further reference */
	TALREG_ReadWord32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_QUARTZ_PROC_CONFIG, &ui32ProcConfigReg);
	psFWSoftImage->ui32CoreCodeRAM = F_EXTRACT(ui32ProcConfigReg, QUARTZ_TOP_LTP_INSTRUCTION_RAM_SIZE) * 1024;
	psFWSoftImage->ui32CoreDataRAM = F_EXTRACT(ui32ProcConfigReg, QUARTZ_TOP_LTP_DATA_RAM_SIZE) * 1024;

	/* No-one control the embedded processor yet */
	psFWSoftImage->bDriverHasProcCtrl = IMG_FALSE;
	/* No context is active yet */
	psFWSoftImage->ui16ActiveContextMask = 0;

	/* Select the firmware build that will suit our needs best */
	if (ltp_selectFirmwareBuild(psFWSoftImage, eCodec) != IMG_SUCCESS)
	{
		/* This is a fatal error, we reset everyhing and signal the error to upper layers */
		psFWSoftImage->bPopulated = IMG_FALSE;
		psFWSoftImage->bInitialized = IMG_FALSE;
		return IMG_ERROR_FATAL;
	}

	// First bytes of data are for general purpose
	psFWSoftImage->ui32CoreDataRAM -= sizeof(GENERAL_PURPOSE_DATA);

	/* Check that the code section fits */
	if ((psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildTextSize * 4) > psFWSoftImage->ui32CoreCodeRAM)
	{
		/* This is a fatal error, we reset everyhing and signal the error to upper layers */
		psFWSoftImage->bPopulated = IMG_FALSE;
		psFWSoftImage->bInitialized = IMG_FALSE;
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "LTP_PopulateFirmwareContext: ERROR - Firmware code section larger than code core memory");
#endif
		IMG_ASSERT((psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildTextSize * 4) > psFWSoftImage->ui32CoreCodeRAM && "Firmware code section larger than code core memory");
		return IMG_ERROR_OUT_OF_MEMORY;
	}
	/* Check that the data section fits */
	if ((psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildDataSize * 4) > psFWSoftImage->ui32CoreDataRAM)
	{
		/* This is a fatal error, we reset everyhing and signal the error to upper layers */
		psFWSoftImage->bPopulated = IMG_FALSE;
		psFWSoftImage->bInitialized = IMG_FALSE;
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "LTP_PopulateFirmwareContext: ERROR - Firmware data section larger than data core memory");
#endif
		IMG_ASSERT((psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildDataSize * 4) > psFWSoftImage->ui32CoreDataRAM && "Firmware data section larger than data core memory");
		return IMG_ERROR_OUT_OF_MEMORY;
	}

	/* The firmware build has been selected and all required information is available to load the firmware, process can continue */
	psFWSoftImage->bPopulated = IMG_TRUE;
	return IMG_SUCCESS;
}


/*!
* @fn LTP_LoadFirmware
* @brief After all information required have been set, this will perform the code copy where (and how) it has been defined on device memory
* @params hDevContext Handle on the device context (used for allocation mainly)
* @params psFWSoftImage Pointer to the context of the target LTP
* @params eLoadMethod How do we want to load the firmware
* @return
*	- IMG_ERROR_OUT_OF_MEMORY if one allocation failed
*	- IMG_ERROR_GENERIC_FAILURE if eLoadMethod is 'NONE'
*	- IMG_ERROR_DISABLED if the device init failed
*	- IMG_ERROR_TIMEOUT on poll timeout
*	- IMG_ERROR_NOT_INITIALISED if psFWSoftImage->bInitialized is 0
*	- IMG_ERROR_FATAL if the firmware PC is not set correctly
*	- IMG_SUCCESS on normal completion
*/
IMG_RESULT LTP_LoadFirmware(IMG_HANDLE hDevContext, VXE_KM_FW_SOFT_IMAGE * psFWSoftImage, LOAD_METHOD eLoadMethod)
{
	IMG_RESULT eRet;
	IMG_VOID *pvKMAddrText, *pvKMAddrData;
	IMG_BOOL bRes;
	IMG_UINT32 ui32TextSize = psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildTextSize;
	IMG_UINT32 ui32DataSize = psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildDataSize;
	VXE_KM_DEVCONTEXT* psDevContext = (VXE_KM_DEVCONTEXT*)hDevContext;
#ifdef LOAD_FW_VIA_LINUX
    const struct firmware * firmware_image;
    IMG_CHAR *H264_H265_FW_ALL_pipes_3_define_names_array[] = {
        "FW_TOTAL_DUET_PIPES",
        "CACHE_ENABLED",
    };
    IMG_UINT32 H264_H265_FW_ALL_pipes_3_define_values_array[] = {
        3,
        1,
    };
#endif

	/* We wouldn't want to load an uninitialized firmware */
	if (!psFWSoftImage->bInitialized)
	{
		IMG_ASSERT(psFWSoftImage->bInitialized && "Firmware not initialised");
		return IMG_ERROR_NOT_INITIALISED;
	}

#if defined(SYSBRG_NO_BRIDGING)
	{
		if (g_bFWUseBootloader)
		{
			eLoadMethod = LTP_LOADMETHOD_BOOTLOADER;
		}
	}
#endif

	/* We want to load the firmware this way */
	psFWSoftImage->eLoadMethod = eLoadMethod;

#if ! defined (IMG_KERNEL_MODULE)
	/* Marker around code load */
	TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "START_CODE_LOAD");
#endif

#ifdef LOAD_FW_VIA_LINUX
#if LINUX_VERSION_CODE >= KERNEL_VERSION(3,18,102)
        if ((eRet = request_firmware_direct( &firmware_image, firmware_name, psDevContext->hSysDevHandle->native_device )) == 0)
#else
        if ((eRet = request_firmware( &firmware_image, firmware_name, psDevContext->hSysDevHandle->native_device )) == 0)
#endif
        {
            const char* memptr = (IMG_VOID *)firmware_image->data;

            // Copy in header
            IMG_MEMCPY( (void*)(&(psFWSoftImage->sFirmwareBuildInfos)), memptr, sizeof(struct _FIRMWARE_BUILD_));

            // Move past header and set Text pointer
            memptr += 64; // Size hard coded in firmware build process
            psFWSoftImage->sFirmwareBuildInfos.pui32FWText = (IMG_VOID *)memptr;

            // Get correct code sizes
            ui32TextSize = psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildTextSize;
            ui32DataSize = psFWSoftImage->sFirmwareBuildInfos.ui32SelectedFWBuildDataSize;

            // Move past text and get Data pointer
            memptr += ui32TextSize * 4;
            psFWSoftImage->sFirmwareBuildInfos.pui32FWData = (IMG_VOID *)memptr;
            
            // Hard code some values here (see declaration)
			psFWSoftImage->sFirmwareBuildInfos.ui32FWDefinesLength = 2;
            psFWSoftImage->sFirmwareBuildInfos.ppszFWDefineNames = H264_H265_FW_ALL_pipes_3_define_names_array;
            psFWSoftImage->sFirmwareBuildInfos.pui32FWDefinesValues = H264_H265_FW_ALL_pipes_3_define_values_array;
			psFWSoftImage->sFirmwareBuildInfos.ui32FWSupportedCodecs = 0x00000090; /* support H264 and H265 */
            psFWSoftImage->sFirmwareBuildInfos.ui32FWNumContexts = FW_TOTAL_CONTEXT_SUPPORT;
                   
        }
        else
        {
            PRINT("Error from request_firmware %d\n", eRet);
            return IMG_ERROR_GENERIC_FAILURE;
        }
#endif
	
                /* If we never allocated the memories, we do it the first time [is bSaveRestore really working?] */
	if ((psFWSoftImage->eLoadMethod != LTP_LOADMETHOD_NONE) && (psFWSoftImage->eLoadMethod != LTP_LOADMETHOD_COPY) && (psFWSoftImage->pvText == IMG_NULL) && (psFWSoftImage->pvData == IMG_NULL))
	{
		IMG_UINT32 ui32AllocSize;

		/* Allocate memory to hold code/data [every time since not saved on power transitions: to be checked!] */
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_ConsoleMessage(psFWSoftImage->hLTPCodeRam, "Allocate device memory for FW code/data load");
#endif

		/* Text section first */
		ui32AllocSize = ((ui32TextSize + 15) &~15) * 4 + DMAC_BURSTSIZE_BYTES;
		bRes = allocMemory(
			psDevContext,
			ui32AllocSize,									/* Memory is for the text section */
			64,												/* Aligned on cache miss size */
			IMG_TRUE,										/* Saved on power transitions, we avoid reallocation everytime */
			(KM_DEVICE_BUFFER**) &psFWSoftImage->pvText,
                        IMG_MAP_HOST_KM|IMG_MAP_FIRMWARE);
		if (!bRes)
		{
			psFWSoftImage->bInitialized = IMG_FALSE;
			return IMG_ERROR_OUT_OF_MEMORY;
		}

		/* Data section after */
		ui32AllocSize = ui32DataSize * 4 + DMAC_BURSTSIZE_BYTES;
		if (psFWSoftImage->eLoadMethod == LTP_LOADMETHOD_BOOTLOADER)
		{
			/* Give one page margin to hold the stack (in external memory) */
			ui32AllocSize = VXE_ALIGN(ui32AllocSize, QUARTZ_MAX_DATA_SIZE) + LTP_EXTERNAL_MEM_STACK_SIZE;
		}

		bRes = allocMemory(
			psDevContext,
			ui32AllocSize,									/* Memory is for the data section */
			64,												/* Aligned on cache miss size */
			IMG_TRUE,										/* Saved on power transitions, we avoid reallocation everytime */
			(KM_DEVICE_BUFFER**) &psFWSoftImage->pvData,
                        IMG_MAP_HOST_KM|IMG_MAP_FIRMWARE);
		if (!bRes)
		{
			freeMemory((KM_DEVICE_BUFFER**)&psFWSoftImage->pvText);
			psFWSoftImage->bInitialized = IMG_FALSE;
			return IMG_ERROR_OUT_OF_MEMORY;
		}

#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_ConsoleMessage(psFWSoftImage->hLTPCodeRam, "Copy firmware code/data using DMAC");
#endif

		pvKMAddrText = getKMAddress(psFWSoftImage->pvText);
		IMG_MEMCPY(pvKMAddrText, psFWSoftImage->sFirmwareBuildInfos.pui32FWText, ui32TextSize * 4);
		pvKMAddrData = getKMAddress(psFWSoftImage->pvData);
		IMG_MEMCPY(pvKMAddrData, psFWSoftImage->sFirmwareBuildInfos.pui32FWData, ui32DataSize * 4);
	}


	switch (psFWSoftImage->eLoadMethod)
	{
	case LTP_LOADMETHOD_COPY:
		eRet = ltp_uploadfwByCopy(psDevContext, psFWSoftImage);
		break;
	case LTP_LOADMETHOD_DMA:
		eRet = ltp_uploadfwByDMAC(psDevContext, psFWSoftImage);
		break;
	case LTP_LOADMETHOD_BOOTLOADER:
		eRet = ltp_uploadfwByBootloader(psDevContext, psFWSoftImage);
		break;
	case LTP_LOADMETHOD_NONE:
	default:
		eRet = IMG_ERROR_GENERIC_FAILURE;
		break;
	}

#if ! defined (IMG_KERNEL_MODULE)
	/* Marker around code load */
	TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "END_CODE_LOAD");
#endif

#ifdef LOAD_FW_VIA_LINUX
        // firmware copied - release associated memory
        release_firmware(firmware_image);
#endif

	/* If we have had any failures up to this point then return now */
	if (!psFWSoftImage->bInitialized)
	{
		return IMG_ERROR_DISABLED;
	}

	/* Update the core register and set the PC start address */
	if (psFWSoftImage->eLoadMethod != LTP_LOADMETHOD_NONE)
	{
		IMG_UINT8 ui8CoreRegIdx;
		IMG_UINT32 ui32PCReg;
		IMG_UINT32 ui32PCCheckValue = PC_START_ADDRESS;

		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}

#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "Initialise registers D0.5, D0.6 and D0.7");
#endif
		for (ui8CoreRegIdx = 5; ui8CoreRegIdx < 8; ui8CoreRegIdx++)
		{
			/* D0 registers are in the unit 0001, so we set the target to 0x1 */
			eRet = ltp_writeCoreReg(psFWSoftImage, 0x1 | (ui8CoreRegIdx << SHIFT_LTP_LTP_RSPECIFIER), 0);
			if (IMG_SUCCESS != eRet)
			{
				return eRet;
			}
		}

#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "Initialise registers D1.5, D1.6 and D1.7");
#endif
		// Restore 8 Registers of D1 Bank
		// D1Re0, D1Ar5, D1Ar3, D1Ar1, D1RtP, D1.5, D1.6 and D1.7
		for (ui8CoreRegIdx = 5; ui8CoreRegIdx < 8; ui8CoreRegIdx++)
		{
			/* D1 registers are in the unit 0002, so we set the target to 0x2 */
			eRet = ltp_writeCoreReg(psFWSoftImage, 0x2 | (ui8CoreRegIdx << SHIFT_LTP_LTP_RSPECIFIER), 0);
			if (IMG_SUCCESS != eRet)
			{
				return eRet;
			}
		}

		/* If using bootloader, PC will point somewhere in external memory */
		if (psFWSoftImage->eLoadMethod == LTP_LOADMETHOD_BOOTLOADER)
		{
			TALREG_ReadWord32(psFWSoftImage->hLTPDataRam, FW_FEEDBACK_FIFO_END, &ui32PCCheckValue);

			/* Target the bootloader location (divide by 2 because using MINIM halves the code size by two) */
			ui32PCCheckValue += (psFWSoftImage->sFirmwareBuildInfos.ui32FWBootStrap - PC_START_ADDRESS) / 2;

			/* Computation borrowed from <metag_folder>/share/example/bootimage/asm/start_t1.s, used to convert PC to MINIM PC :
			*	#define METAG_PCMINIM( LinVal )											\
			*	(																		\
			*		(((LinVal) & 0x00980000) == 0x00880000) ?							\
			*			(((LinVal) & 0xFFE00000) + (((LinVal) & 0x000FFFFE)<<1)) :		\
			*		(((LinVal) & 0x00C00000) == 0x00000000) ?							\
			*			(((LinVal) & 0xFF800000) + (((LinVal) & 0x003FFFFE)<<1)) : 0	\
			*	)
			*/
			ui32PCCheckValue = (ui32PCCheckValue & 0xffe00000) + ((ui32PCCheckValue & 0x000ffffe) << 1);
		}

		// Set Starting PC address
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "--");
		TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "Set Starting PC address");
#endif
		eRet = ltp_writeCoreReg(psFWSoftImage, LTP_PC, ui32PCCheckValue);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "--");
#endif

		// Verify Starting PC
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "Verify Starting PC");
#endif
		eRet = ltp_readCoreReg(psFWSoftImage, LTP_PC, &ui32PCReg);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}

		DEBUG_PRINT("PC_START_ADDRESS = 0x%08X\n", ui32PCReg);
		if (ui32PCReg != ui32PCCheckValue)
		{
			IMG_ASSERT(ui32PCReg == ui32PCCheckValue);
			return IMG_ERROR_FATAL;
		}

		return IMG_SUCCESS;
	}

	/* Load method being "NONE" is a generic failure (in fake fw it is considered a "normal" error) */
	return IMG_ERROR_GENERIC_FAILURE;
}


/*!
* @fn LTP_GetFWConfigIntValue
* @brief Get the value of #define pszDefineName for the firmware represented by $psFWSoftImage
* @params psFWSoftImage Pointer to the context of the target LTP
* @params pszDefineName Name of the define to be found
* @return The value of the define on success, -1 if not found (alls constant are expected positive)
*/
IMG_INT32 LTP_GetFWConfigIntValue(const VXE_KM_FW_SOFT_IMAGE * const psFWSotfImage, const IMG_CHAR * const pszDefineName)
{
	/* Hard code limit to 1024 characters being read */
	const size_t maxLength = 1024;
	IMG_UINT32 ui32CurrentDefine;

	if (psFWSotfImage->sFirmwareBuildInfos.ui32SelectedFWBuildTextSize == 0)
	{
		/* This is update once a proper FW build has been found, otherwise it is zero */
		IMG_ASSERT("FW context is not initialized, nor firmware build has been selected\n");
		return -1;
	}

	for (ui32CurrentDefine = 0; ui32CurrentDefine < psFWSotfImage->sFirmwareBuildInfos.ui32FWDefinesLength; ++ui32CurrentDefine)
	{
		if (strncmp(psFWSotfImage->sFirmwareBuildInfos.ppszFWDefineNames[ui32CurrentDefine], pszDefineName, maxLength) == 0)
		{
			return psFWSotfImage->sFirmwareBuildInfos.pui32FWDefinesValues[ui32CurrentDefine];
		}
	}

	IMG_ASSERT("Define requested has not been found in the firmware build!");
	return -1;
}


/************************************************* POWER MANAGEMENT ********************************************************/


/*!
* @function LTP_SaveState
* @brief Active Power Management routine to save the LTP internal state
* @param psFWSoftImage Pointer to the context of the LTP target
* @return
*	- IMG_SUCCESS on normal completion
*/
IMG_RESULT LTP_SaveState(VXE_KM_FW_SOFT_IMAGE *psFWSoftImage)
{
	IMG_RESULT eRet = IMG_SUCCESS;
	IMG_UINT32 *pui32Regs = psFWSoftImage->pui32ProcRegisterCopy, ui32CommandFIFOState;

	/* We only save the state of an active core */
	if (psFWSoftImage->bInitialized)
	{
		/* Read the command FIFO producer */
		TALREG_ReadWord32(psFWSoftImage->hLTPDataRam, FW_HW_FIFO_WRITER, &ui32CommandFIFOState);
		/* Wait for consumer to catch up (meaning the FIFO is empty) */
		eRet = TALREG_Poll32(psFWSoftImage->hLTPDataRam, FW_HW_FIFO_READER, TAL_CHECKFUNC_ISEQUAL, ui32CommandFIFOState, 0xffffffff, 1000, 500);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(IMG_SUCCESS == eRet && "Command FIFO consumer did not catch up in time");
			return eRet;
		}

		/* Let's wait for the HW to go in idle state before saving its state */
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hLTPDataRam, "LTP_SaveState: Wait for HW idle state");
#endif
		eRet = TALREG_Poll32(psFWSoftImage->hLTPDataRam, FW_SCRATCHREG_IDLE, TAL_CHECKFUNC_ISEQUAL, F_ENCODE(FW_IDLE_STATUS_IDLE, FW_IDLE_REG_STATUS), MASK_FW_IDLE_REG_STATUS, 1000, 500); // 1000 polls with 500ms in between each
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "Poll failed waiting for FW IDLE");
			return eRet;
		}
		/* Make sure that core_idle is set */
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hLTPDataRam, "LTP_SaveState: Wait for core_idle in idle_pwr_man (couple of cycles later)");
#endif
		eRet = TALREG_Poll32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_MULTIPIPE_IDLE_PWR_MAN, TAL_CHECKFUNC_ISEQUAL, F_ENCODE(1, QUARTZ_TOP_CORE_IDLE), F_ENCODE(1, QUARTZ_TOP_CORE_IDLE), 1000, 500); // 1000 polls with 500ms in between each
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "Poll failed waiting for core_idle in idle_pwr_man");
			return eRet;
		}

		/* Keep track on the current feedback indexes where we were before the power transition */
		TALREG_ReadWord32(psFWSoftImage->hLTPDataRam, FW_REG_FEEDBACK_PRODUCER, &pui32Regs[SAVED_FW_FEEDBACK_PRODUCER]);
		TALREG_ReadWord32(psFWSoftImage->hLTPDataRam, FW_REG_FEEDBACK_CONSUMER, &pui32Regs[SAVED_FW_FEEDBACK_CONSUMER]);

		/* Wait for the memory transactions from LTP to complete */
		eRet = ltp_waitCleanState(psFWSoftImage);
		IMG_ASSERT(eRet == IMG_SUCCESS && "LTP slave port state is unstable/errorneous");
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}

		/* Turn off the core */
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "LTP_SaveState: Stop the LTP");
#endif
		eRet = LTP_Stop(psFWSoftImage);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}
		eRet = LTP_WaitForCompletion(psFWSoftImage);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}

		/* Soft reset the LTP core to let it in the cleanest state possible */
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hQuartzMultipipeMemSpace, "Soft reset LTP after turning it off to guarantee clean state");
#endif
		eRet = LTP_WriteSoftReset(psFWSoftImage);
		IMG_ASSERT(eRet == IMG_SUCCESS && "LTP soft reset (after stopping it) was unsuccessful");
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}

		/* Store required register to reboot properly when exiting low power */
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hMMURegs, "LTP_SaveState: Storing MMU Control register states");
#endif
		/* Store MMU setup registers */
		TALREG_ReadWord32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_DIR_BASE_ADDR(0), &pui32Regs[SAVED_IMG_BUS4_MMU_DIR_BASE_ADDR_0]);

#if !defined(IMG_KERNEL_MODULE)
		if (g_bDoingPdump)
		{
			TALPDUMP_Comment(psFWSoftImage->hMMURegs, "LTP_SaveState: Save a copy of MMU_DIR_LIST_BASE(0) in a pdump register to restore it later");
			/* If we are pdumping we can't just read and write this register */
			TALINTVAR_ReadFromReg32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_DIR_BASE_ADDR(0), psFWSoftImage->hMMURegs, 1);
		}
#endif


		TALREG_ReadWord32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_TILE_CFG(0), &pui32Regs[SAVED_IMG_BUS4_MMU_TILE_CFG_0]);
		TALREG_ReadWord32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_TILE_CFG(1), &pui32Regs[SAVED_IMG_BUS4_MMU_TILE_CFG_1]);
		TALREG_ReadWord32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_ADDRESS_CONTROL, &pui32Regs[SAVED_IMG_BUS4_MMU_ADDRESS_CONTROL]);
		TALREG_ReadWord32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_CONTROL0, &pui32Regs[SAVED_IMG_BUS4_MMU_CONTROL0]);

		TALREG_ReadWord32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_MULTIPIPE_HOST_INT_ENAB, &pui32Regs[SAVED_MULTICORE_INTEN]);
	}

	/* clear the firmware boot status register for clarity*/
	TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_REG_FW_BOOTSTATUS, 0);

	return IMG_SUCCESS;
}


/*!
* @function LTP_RestoreState
* @brief Active Power Management routine to restore the LTP internal state
* @params hDevContext Handle on the device context containing the LTP target context
* @returns:		- IMG_SUCCESS on normal completion
*				- IMG_ERROR_DISABLED if trying to re-enable HW when there is nothing left to do
*/
IMG_RESULT LTP_RestoreState(IMG_HANDLE hDevContext)
{
	IMG_UINT32 ui32ResetRegVal;
	VXE_KM_DEVCONTEXT *psDevContext = (VXE_KM_DEVCONTEXT*)hDevContext;
	VXE_KM_FW_SOFT_IMAGE *psFWSoftImage = &psDevContext->sFWSoftImage;
	IMG_UINT32 *pui32Regs = psFWSoftImage->pui32ProcRegisterCopy;
	IMG_RESULT eRet;

	/* Only resume an already initialized core */
	if (psFWSoftImage->bInitialized)
	{
		/** 1 - Clear some registers used for firmware-KM communication: HW FIFO, feedback FIFO and bootstatus **/
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_HW_FIFO_READER, 0x0);
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_HW_FIFO_WRITER, 0x0);
#if ! defined (IMG_KERNEL_MODULE)
		/* in a test environment we call tell the firmware to only use the specified number of pipes, regardless of how many pipes it can see */
		TALPDUMP_Comment(psFWSoftImage->hLTPDataRam, "Tell Firmware how many pipes to expect");
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_REG_FW_BOOTSTATUS, psFWSoftImage->ui8QuartzHwPipes);
#else
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_REG_FW_BOOTSTATUS, 0x0);
#endif
		//
		for (ui32ResetRegVal = FW_PIPELOWLATENCYINFO_START; ui32ResetRegVal < FW_PIPELOWLATENCYINFO_END; ui32ResetRegVal += 4)
		{
			TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, ui32ResetRegVal, 0x0);
		}

		// CHECKME: Secure upload was here before: MMU bypass


		/** 2 - Proper LTP/core/MMU soft-reset **/
#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "LTP_RestoreState: Software of the LTP, cores and MMU");
#endif
		/* Disable the embedded processor (accessing the core reg LTP_ENABLE) */
		eRet = ltp_slave_single_write(psFWSoftImage, LTP_CR_LTP_ENABLE, 0x0);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}

		/* Soft reset the embedded processor (soft reset to one, then to zero: traversing the layers takes enough time) */
		TALREG_WriteWord32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, MASK_QUARTZ_TOP_PROC_SOFT_RESET);
		TALREG_WriteWord32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, 0x0);

		/* Soft reset of the encoder pipes (all four cores), the features' soft reset of each pipe is automatic */
		ui32ResetRegVal = MASK_QUARTZ_TOP_ENCODER_PIPE_SOFT_RESET(0) | MASK_QUARTZ_TOP_ENCODER_PIPE_SOFT_RESET(1) | MASK_QUARTZ_TOP_ENCODER_PIPE_SOFT_RESET(2) | MASK_QUARTZ_TOP_ENCODER_PIPE_SOFT_RESET(3);
		TALREG_WriteWord32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, ui32ResetRegVal);
		TALREG_WriteWord32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_MULTIPIPE_SOFT_RESET, 0x0);

#if ! defined (IMG_KERNEL_MODULE)
		TALPDUMP_Comment(psFWSoftImage->hMMURegs, "Wait for MMU to be idle before resetting it");
#endif
		eRet = TALREG_Poll32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_MEM_EXT_OUTSTANDING, TAL_CHECKFUNC_ISEQUAL, 0, 0xffff, 200, 500);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "MMU outstanding memory accesses didn't go to zero");
			return eRet;
		}

#if ! defined (IMG_KERNEL_MODULE)	
		TALPDUMP_Comment(psFWSoftImage->hMMURegs, "Wait for MMU burst requests to go to zero");
#endif		
		eRet = TALREG_Poll32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_MEM_REQ, TAL_CHECKFUNC_ISEQUAL, 0, MASK_IMG_BUS4_TAG_OUTSTANDING, 200, 500);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "MMU burst requests didn't go to zero");
			return eRet;
		}

		/* Soft reset the MMU (BIF) - it will automatically update to 0 when the MMU reset is complete */
		TALREG_WriteWord32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_CONTROL1, MASK_IMG_BUS4_MMU_SOFT_RESET);

#if ! defined (IMG_KERNEL_MODULE)	
		TALPDUMP_Comment(psFWSoftImage->hMMURegs, "Wait for MMU reset to complete");
#endif		
		eRet = TALREG_Poll32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_CONTROL1, TAL_CHECKFUNC_ISEQUAL, 0, MASK_IMG_BUS4_MMU_SOFT_RESET, MMU_SOFT_RESET_POLL_COUNT, MMU_SOFT_RESET_TIMEOUT);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "MMU soft reset did not complete in time");
			return eRet;
		}

		/** 3 - Reset the LTP **/
#if ! defined (IMG_KERNEL_MODULE)	
		TALPDUMP_Comment(psFWSoftImage->hLTPRegMemspace, "LTP_RestoreState: Reset the LTP core");
#endif		
		eRet = ltp_reset(psFWSoftImage);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}

		/* Feedback indexes are restored in the same state they were before power transition */
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_REG_FEEDBACK_PRODUCER, pui32Regs[SAVED_FW_FEEDBACK_PRODUCER]);
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_REG_FEEDBACK_CONSUMER, pui32Regs[SAVED_FW_FEEDBACK_CONSUMER]);

		TALREG_WriteWord32(psFWSoftImage->hQuartzMultipipeMemSpace, QUARTZ_TOP_MULTIPIPE_HOST_INT_ENAB, pui32Regs[SAVED_MULTICORE_INTEN]);

		// CHECKME: Secure upload was here before: Load code and data with MMU bypassed

#if SECURE_MMU
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_COMMAND_FIFO_START + 0x00, VXE_COMMAND_CONFIGURE_MMU);
#if defined (IMG_KERNEL_MODULE)
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_COMMAND_FIFO_START + 0x04, psDevContext->sDevSpecs.sMMURegConfig.DIR_BASE_ADDR0);
#else
		/* in nonbridging case we dont know the physical address of the page tables but we stored it in a TAL internal register earlier */
		TALINTVAR_WriteToReg32(psFWSoftImage->hLTPDataRam, FW_COMMAND_FIFO_START + 0x04, psDevContext->sDevSpecs.hQuartzMultipipeBank, 1);
#endif
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_COMMAND_FIFO_START + 0x08, psDevContext->sDevSpecs.sMMURegConfig.ADDRESS_CONTROL);
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_COMMAND_FIFO_START + 0x0c, psDevContext->sDevSpecs.sMMURegConfig.MMU_CONTROL0);
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_COMMAND_FIFO_START + 0x10, psDevContext->sDevSpecs.sMMURegConfig.TILE_CFG0);
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_COMMAND_FIFO_START + 0x14, psDevContext->sDevSpecs.sMMURegConfig.TILE_MAX_ADDR0);
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_COMMAND_FIFO_START + 0x18, psDevContext->sDevSpecs.sMMURegConfig.TILE_MIN_ADDR0);
		TALREG_WriteWord32(psFWSoftImage->hLTPDataRam, FW_COMMAND_FIFO_START + 0x1c, psDevContext->sDevSpecs.sMMURegConfig.DIR_BASE_ADDR0);
#else
		TALREG_WriteWord32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_DIR_BASE_ADDR(0), pui32Regs[SAVED_IMG_BUS4_MMU_DIR_BASE_ADDR_0]);

#if !defined(IMG_KERNEL_MODULE)
		if (g_bDoingPdump)
		{
			TALPDUMP_Comment(psFWSoftImage->hMMURegs, "LTP_RestoreState: The IMG_BUS4_MMU_DIR_BASE_ADDR(0) register is an address and can't simply be written with an immediate value");
			/* If we are pdumping we can't just read and write this register */
			TALINTVAR_WriteToReg32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_DIR_BASE_ADDR(0), psFWSoftImage->hMMURegs, 1);
		}
#endif

		TALREG_WriteWord32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_TILE_CFG(0), pui32Regs[SAVED_IMG_BUS4_MMU_TILE_CFG_0]);
		TALREG_WriteWord32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_TILE_CFG(1), pui32Regs[SAVED_IMG_BUS4_MMU_TILE_CFG_1]);
		TALREG_WriteWord32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_ADDRESS_CONTROL, pui32Regs[SAVED_IMG_BUS4_MMU_ADDRESS_CONTROL]);

		// CHECKME: Secure code was here before: write the content of CONTROL0 in the HW FIFO for the firmware to handle it, otherwise do what is done below


		TALREG_WriteWord32(psFWSoftImage->hMMURegs, IMG_BUS4_MMU_CONTROL0, pui32Regs[SAVED_IMG_BUS4_MMU_CONTROL0]);

		/* We have just rewritten the page table directory address, a MMU cache flush should follow */
		QUARTZKM_MMUFlushMMUTableCache(hDevContext);
#endif /* SECURE_MMU */
		/* Load code and data section now that registers are set*/
		eRet = LTP_LoadFirmware(psDevContext, psFWSoftImage, psFWSoftImage->eLoadMethod);
		if (IMG_SUCCESS != eRet)
		{
			IMG_ASSERT(eRet == IMG_SUCCESS && "Firmware could not be loaded");
			return eRet;
		}

		/* Turn LTP on and kick it */
		eRet = LTP_Start(psFWSoftImage);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}
		eRet = LTP_Kick(psFWSoftImage, 1);
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}

#if ! defined (IMG_KERNEL_MODULE)	
		TALPDUMP_Comment(psFWSoftImage->hLTPDataRam, "Verify that firmware started booting");
#endif		
		if (LTP_LOADMETHOD_BOOTLOADER == psFWSoftImage->eLoadMethod)
		{
			/* Bootloader needs to bring 64k of code + 32k of data using dmac, therefore it needs more time to get to the firmware's entry point */
			eRet = TALREG_Poll32(psFWSoftImage->hLTPDataRam, FW_REG_FW_BOOTSTATUS, TAL_CHECKFUNC_GREATEREQ, 0x10, 0xffffffff, VXE_TIMEOUT_RETRIES, VXE_TIMEOUT_WAIT_FOR_FW_BOOT);
		}
		else
		{
			eRet = TALREG_Poll32(psFWSoftImage->hLTPDataRam, FW_REG_FW_BOOTSTATUS, TAL_CHECKFUNC_GREATEREQ, 0x10, 0xffffffff, 400, 10);
		}

		IMG_ASSERT(IMG_SUCCESS == eRet && "Checking that firmware started booting");
		if (IMG_SUCCESS != eRet)
		{
			return eRet;
		}
	}

	return IMG_SUCCESS;
}

