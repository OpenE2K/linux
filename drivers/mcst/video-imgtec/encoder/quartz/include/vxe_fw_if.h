/*!
 *****************************************************************************
 *
 * @File       vxe_fw_if.h
 * @Title      VXE Firmware Interface Definitions
 * @Description    Definitions used by the VXE encoder host-firmware interface
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

#ifndef _VXE_FW_IF_H_
#define _VXE_FW_IF_H_

#include "coreflags.h"
#include "VXE_Enc_GlobalDefs.h"
#include "vxe_common.h"

/* It might me helpful to carefully check the padding in structure for this file which is shared between the firmware and the host */
#if defined (WIN32)
#pragma warning ( 1: 4820 )
#else
#pragma GCC diagnostic warning "-Wpadded"
#endif

#define SECURE_MMU (0)


#define NUM_COMMANDS 10
#define CALC_OPTIMAL_COMMANDS_ENCODE(numcores) (numcores * NUM_COMMANDS)

#define CMDDEVMEMBLOCKSIZEBYTES			VXE_ALIGN_64(64)

//#define LOW_LATENCY_USING_FIFO 1
#define CTU_RAM_SIZE 0x2FFC

#define HEADER_TABLE_ENTRY_SIZE 256		//!< The offset amount between header entries in memory (also the maximum header size)
#define MAX_PICTURE_HEADER_CNT MAX_NUM_TILE_SETUPS		//!< The API limit on the number of picture headers (PPS_Ids) and association tile mappings that can be sent at a time (actual limits in HEVC Spec is 64, H264 Spec is 256)





#define FAKE_SIM_FREQ_MAX_KHZ 2000

/* When mopping up the kernel module (if the user mode went away), we need to wait for the stream to be aborted properly first */
#define WAIT_FOR_ABORT_RETRIES 100 // Don't change this as it's also used in KM_WaitForDeviceIdle() with a different timeout

#define WAIT_FOR_ABORT_TIMEOUT_SILICON 2
#define WAIT_FOR_ABORT_TIMEOUT_FPGA 20
#define WAIT_FOR_ABORT_TIMEOUT_SIM 200
#define WAIT_FOR_ABORT_TIMEOUT_VIRTPLATFORM 201

#define CALC_ABORT_TIMEOUT(ui32ClkFreqkHz)\
		(ui32ClkFreqkHz > 50000 ? WAIT_FOR_ABORT_TIMEOUT_SILICON : \
		(ui32ClkFreqkHz > FAKE_SIM_FREQ_MAX_KHZ ? WAIT_FOR_ABORT_TIMEOUT_FPGA : \
		(ui32ClkFreqkHz == FAKE_SIM_FREQ_MAX_KHZ ?  WAIT_FOR_ABORT_TIMEOUT_SIM :	WAIT_FOR_ABORT_TIMEOUT_VIRTPLATFORM)))






/* Allow compilation static asserts to trigger while building real fw */
#ifndef STATIC_ASSERT__H 
#define STATIC_ASSERT__H
#define ASSERT_CONCAT_(a, b) a##b
#define ASSERT_CONCAT(a, b) ASSERT_CONCAT_(a, b)
/* These can't be used after statements in c89. */
#ifdef __COUNTER__
/* microsoft */
#define STATIC_ASSERT(e) enum { ASSERT_CONCAT(static_assert_, __COUNTER__) = 1/(!!(e)) }
#else
/* This can't be used twice on the same line so ensure if using in headers
* that the headers are not included twice (by wrapping in #ifndef...#endif)
* Note it doesn't cause an issue when used on same line of separate modules
* compiled with gcc -combine -fwhole-program.  */
#define STATIC_ASSERT(e) enum { ASSERT_CONCAT(assert_line_, __LINE__) = 1/(!!(e)) }
#endif
/* http://msdn.microsoft.com/en-us/library/ms679289(VS.85).aspx */
#endif

/****************************************************** DEFINES ************************************************************/
// We want to use the imgvideo shared errors, but some are missing to truly represent what happened, some have been added here
// If it is a problem, then we could just remove them and use a less appropriate one from imgvideo
#define IMG_ERROR_COMM_RETRY					(32)	/**< @brief Required operation in the kernel to firmware communication layer failed */
#define IMG_ERROR_COMM_COMMAND_NOT_QUEUED		(33)	/**< @brief The command queue buffer is already full */
#define IMG_ERROR_MAX_ENCODE_ON_FLY				(34)	/**< @brief Maximum number of encode already sent through */



// Simulated HW FIFO depth
#define HW_FIFO_SIZE							(32)
// 4 words per command in the HW FIFO
#define HW_FIFO_WORDS_PER_COMMANDS				(4)

#define FEEDBACK_FIFO_MAX_COMMANDS				(32)

#define FEEDBACK_FIFO_WORD_PER_COMMANDS			(2)



/* We use a chunk of the uncached LTP ram for our general purpose requirements, these define the size of it */
#define FW_GENERAL_PURPOSE_REGISTERS			(16)
// Command FIFO used to send commands from the kernel to the firmware
#define FW_HW_FIFO_MEM_TOTAL_SIZE (HW_FIFO_SIZE * HW_FIFO_WORDS_PER_COMMANDS * 4/*sizeof(IMG_UINT32)*/)
// Feedback FIFO used to send feeback from the firmware to the kernel

#define FW_FEEDBACK_MEM_TOTAL_SIZE (FEEDBACK_FIFO_MAX_COMMANDS * FEEDBACK_FIFO_WORD_PER_COMMANDS * 4/*sizeof(IMG_UINT32)*/)

#define PIPELOWLATENCYINFO_MEM_TOTAL_SIZE (QUARTZ_MAX_PIPES * 4/*sizeof(IMG_UINT32)*/)

/*
* We reserve the start of the FW data section for the communication between the KM and the FW (because it is uncached)
* The total number of register used only to communicate between the FW and the driver
* Our register map is as follows:
* [0x0000] : FW_HW_FIFO_READER			=> Index informing about the firmware consumption of input message
* [0x0004] : FW_HW_FIFO_WRITER			=> Index informing about the kernel command issuing
* [0x0008] : FW_SCRATCHREG_IDLE			=> Firmware current state
* [0x000c] : FW_SCRATCHREG_FWTRACE		=> Buffer memory location used when FW_LOGGING is on
* [0x0010] : FW_REG_FW_BOOTSTATUS		=> Firmware bootstatus
* [0x0014] : FW_REG_FEEDBACK_PRODUCER	=> Feedback producer index (firmware increments it)
* [0x0018] : FW_REG_FEEDBACK_CONSUMER	=> Feedback consumer index (kernel increments it)
* [0x001c] : FW_REG_FW_FEEDBACK			=> Last command id executed by the firmware
* [0x0020] : FW_REG_TRACE_BASEADDR		=> Base address that firmware should log events to
* [0x0024] : FW_REG_TRACE_SIZE			=> Size of buffer for firmware to log events to
* [0x0028] : FW_REG_TRACE_WOFF			=> Next offset into event log that will be written by firmware
*/
#define FW_REG_SECTION_START			(0x0000)
#define FW_HW_FIFO_READER				(FW_REG_SECTION_START)					// + 0x0000	(FW Write-Only) 
#define FW_HW_FIFO_WRITER				(FW_HW_FIFO_READER			+ 0x0004)	// + 0x0004	(KM Write-Only)
#define FW_SCRATCHREG_IDLE				(FW_HW_FIFO_WRITER			+ 0x0004)	// + 0x0008	(FW Write-Only)
#define FW_SCRATCHREG_FWTRACE			(FW_SCRATCHREG_IDLE			+ 0x0004)	// + 0x000c	(KM Write-Only)
#define FW_REG_FW_BOOTSTATUS			(FW_SCRATCHREG_FWTRACE		+ 0x0004)	// + 0x0010	(FW Write-Only)
#define FW_REG_FEEDBACK_PRODUCER		(FW_REG_FW_BOOTSTATUS		+ 0x0004)	// + 0x0014	(FW Write-Only)
#define FW_REG_FEEDBACK_CONSUMER		(FW_REG_FEEDBACK_PRODUCER	+ 0x0004)	// + 0x0018	(KM Write-Only)
#define FW_REG_FW_FEEDBACK				(FW_REG_FEEDBACK_CONSUMER	+ 0x0004)	// + 0x001c	(FW Write-Only)
#define FW_REG_TRACE_BASEADDR			(FW_REG_FW_FEEDBACK			+ 0x0004)	// + 0x0020	(KM Write-Only)
#define FW_REG_TRACE_SIZE				(FW_REG_TRACE_BASEADDR		+ 0x0004)	// + 0x0024	(KM Write-Only)
#define FW_REG_TRACE_WOFF				(FW_REG_TRACE_SIZE			+ 0x0004)	// + 0x0028	(FW Write-Only)


#define FW_PIPELOWLATENCYINFO_START	(FW_REG_TRACE_WOFF + 4)
#define FW_PIPELOWLATENCYINFO_END	(FW_PIPELOWLATENCYINFO_START + PIPELOWLATENCYINFO_MEM_TOTAL_SIZE)

#define FW_REG_SECTION_END				(FW_REG_SECTION_START + (FW_GENERAL_PURPOSE_REGISTERS*4)) // guard (15 registers - 4bytes each)
STATIC_ASSERT(FW_PIPELOWLATENCYINFO_END <= FW_REG_SECTION_END);

#define FW_CTXT_STATUS_COUNTERS_START	(FW_REG_SECTION_END)					// + 0x0040
#define FW_CTXT_STATUS_COUNTERS_SIZE	(FW_TOTAL_CONTEXT_SUPPORT*4)
#define FW_CTXT_STATUS_COUNTERS_END		(FW_CTXT_STATUS_COUNTERS_START + FW_CTXT_STATUS_COUNTERS_SIZE)					

#define FW_CTXT_STATUS_COUNTER(ctxt_num)	(FW_CTXT_STATUS_COUNTERS_START + 4*(ctxt_num))

/* Command FIFO starts after the register region */
#define FW_COMMAND_FIFO_START			(FW_CTXT_STATUS_COUNTERS_END)					// + 0x0080


#define FW_COMMAND_FIFO_END				(FW_COMMAND_FIFO_START + FW_HW_FIFO_MEM_TOTAL_SIZE) // guard
/* Feedback FIFO start after the command FIFO */
#define FW_FEEDBACK_FIFO_START			(FW_COMMAND_FIFO_END)					// + 0x0280
#define FW_FEEDBACK_FIFO_END			(FW_FEEDBACK_FIFO_START + FW_FEEDBACK_MEM_TOTAL_SIZE) // guard

/* The total size of each firmware context can't be calculated here as it includes hidden FW only structures */
#define VXE_FW_CTXT_SIZE	(10*1024 /*sizeof(INTERNAL_FW_CONTEXT_STRUCTURES)*/)


/* Hardware capabilities */
	#define	QUARTZ_MAX_RECON				16
/* Context features */
#define SHIFT_FW_FEATURES_LINE_COUNTER_ON			(0)
#define SHIFT_FW_FEATURES_BIT_DEPTH_TEN				(1)
#define SHIFT_FW_FEATURES_LOW_LATENCY_ENCODE		(2)
#define SHIFT_FW_FEATURES_LINKED_LIST_ENABLED		(3)
#define SHIFT_FW_FEATURES_LINKED_LIST_BUS_MODE		(4)
#define SHIFT_FW_FEATURES_SPATIAL_DIRECT			(5)
#define SHIFT_FW_FEATURES_UPDATE_ON_SLICE_MODE		(6)
#define SHIFT_FW_FEATURES_OUTPUT_HW_IF				(7)
#define SHIFT_FW_FEATURES_INSERTING_HEADERS			(8)
#define SHIFT_FW_FEATURES_DYNAMIC_SLICE_INSERT		(9)
#define SHIFT_FW_FEATURES_VCMHW_UPDATE_PER_BU		(13)
#define SHIFT_FW_FEATURES_REPEAT_SEQUENCE_HEADER	(14)
#define SHIFT_FE_FEATURES_ENABLE_LINESTORE_OFFSET   (15)



/************************************************* HOST TO FIRMWARE ********************************************************/

/*
* Host to firmware command structure:
* [0:5]: command type (may be less if we only send the command type)
* [6:13]: socket id (mirrors fw context id)
* [14]: command generates an interrupt on write back
* [15]: command must be skipped (only relevant for encode commands)
*/
#define MASK_FW_COMMAND_COMMAND_TYPE	0x0000003f
#define SHIFT_FW_COMMAND_COMMAND_TYPE	0
#define MASK_FW_COMMAND_SOCKET_ID		0x00003fc0
#define SHIFT_FW_COMMAND_SOCKET_ID		6
#define MASK_FW_COMMAND_WB_INTERRUPT	0x00004000
#define SHIFT_FW_COMMAND_WB_INTERRUPT	14
#define MASK_FW_COMMAND_TO_SKIP			0x00008000
#define SHIFT_FW_COMMAND_TO_SKIP		15


/*********************************************** COMMAND SPECIFIC INPUTS ***************************************************/

/*
* VXE_ACTIVATE_CONTEXT
* [0:7] : Index of the dev mempool block containing the initial parameter given with API call
* [8] : Flag to specify whether (1) or not (0) the context is re-activated after low power
*/
#define MASK_VXE_ACTIVATE_CONTEXT_BLOCK_IDX				0xff
#define SHIFT_VXE_ACTIVATE_CONTEXT_BLOCK_IDX			0
#define MASK_VXE_ACTIVATE_CONTEXT_ALREADY_ACTIVATED		0x100
#define SHIFT_VXE_ACTIVATE_CONTEXT_ALREADY_ACTIVATED	8


/*
* VXE_ENCODE_FRAME
* [0] : Flag to specify if we send a normal encode command (0) or if we expect the hw to go in idle state (1)
*/
#define MASK_VXE_ENCODE_FRAME_POWER_TRANS			0x1
#define SHIFT_VXE_ENCODE_FRAME_POWER_TRANS			0

#ifndef REMOVE_4K1080PARALLEL_SCHEDULING
#define MASK_VXE_ENCODE_FRAME_PIPEZEROSHARED	0x2
#define SHIFT_VXE_ENCODE_FRAME_PIPEZEROSHARED	1
#endif

/*
* VXE_INSERT_HEADER
* [0:3] : Header id from #Header_Type enum below
*/
#define MASK_VXE_INSERT_HEADER_HEADER_TYPE			0x0000000f
#define SHIFT_VXE_INSERT_HEADER_HEADER_TYPE			0


/*
* VXE_FENCE
* [0:15] : Fence identifier: user space will give one in order to sync, kernel will use a signature of the unique command id
* [16] : Flag specifying whether the fence is the end of an abort (1) or purely a fence requested by user (0)
*/
#define MASK_VXE_FENCE_UNIQUE_ID					0x0000ffff
#define SHIFT_VXE_FENCE_UNIQUE_ID					0
#define MASK_VXE_FENCE_IS_END_OF_ABORT				0x00010000
#define SHIFT_VXE_FENCE_IS_END_OF_ABORT				16


/************************************************* FIRMWARE TO HOST ********************************************************/

/*
* FW to host feedback first word
* [0:1] : message type [VXE_FWMSG_ACK, VXE_FWMSG_CODED_BUFFER, VXE_FWMSG_FRAME_LOWLATENCY_INIT, or VXE_FWMSG_ERROR]
* [2:5] : command type for ACK and ERROR (max 32)
* [6] : flag to mark whether the command has not been processed (result of an abort for instance)
* [7:23] : command unique identifier (max 131,072)
* [24:31] : context id (max 256)
*/
#define MASK_FW_FEEDBACK_MSG_TYPE			0x00000003
#define SHIFT_FW_FEEDBACK_MSG_TYPE			0
#define MASK_FW_FEEDBACK_COMMAND_TYPE		0x0000003c
#define SHIFT_FW_FEEDBACK_COMMAND_TYPE		2
#define MASK_FW_FEEDBACK_COMMAND_SKIPPED	0x00000040
#define SHIFT_FW_FEEDBACK_COMMAND_SKIPPED	6
#define MASK_FW_FEEDBACK_COMMAND_ID			0x00ffff80
#define SHIFT_FW_FEEDBACK_COMMAND_ID		7
#define MASK_FW_FEEDBACK_CONTEXT_ID			0xff000000
#define SHIFT_FW_FEEDBACK_CONTEXT_ID		24


/*
* FW to host feedback second word - error
* [0:4] : error type (max 32)
*/
#define MASK_FW_FEEDBACK_E_ERROR	0x0000001f
#define SHIFT_FW_FEEDBACK_E_ERROR	0

/*
* FW to host feedback second word - coded buffer
* [0] : Full header return flag
* [1] : Last Coded buffer flag
* [2:3] : Coded Buffer linked list index
* [4:13] : Extra Info feedback Index (Max value: 0x1FF, 9 bits)
*/
#define MASK_FW_FEEDBACK_FULLHEADERRETURN				0x00000001  //(Max val: 0x1, 1 bit)
#define SHIFT_FW_FEEDBACK_FULLHEADERRETURN				0
#define MASK_FW_FEEDBACK_FINALCODEDOUTPUTFLAG			0x00000002	//(Max val: 0x1, 1 bit)
#define SHIFT_FW_FEEDBACK_FINALCODEDOUTPUTFLAG			1
#define MASK_FW_FEEDBACK_CBLISTINDEX					0x0000000C	//(Max val: 0x3, 2 bits)
#define SHIFT_FW_FEEDBACK_CBLISTINDEX					2
#define MASK_FW_FEEDBACK_EXTRAINFOWORD					0x00001FF0	//(Max val: 0x1FF, 9 bits)
#define SHIFT_FW_FEEDBACK_EXTRAINFOWORD				4

#define CMD_ID_MASK 0xFFFF
#define IDX_LOWLATENCY_NOT_STARTED (CMD_ID_MASK + 1)

/********************************************** COMMAND SPECIFIC FEEDBACK **************************************************/

/*
* ACTIVATE_CONTEXT command second word
* [0:7] : Context parameter unique block id, likely to be a small number since it occurs just after context activation
* [8] : Flag to check if this is a first activation or re-activation of the context 
*/
#define MASK_FW_FEEDBACK_ACTIVATE_CONTEXT_FW_PARAMS_BLOCK_ID	0x000000ff
#define SHIFT_FW_FEEDBACK_ACTIVATE_CONTEXT_FW_PARAMS_BLOCK_ID	0
#define MASK_FW_FEEDBACK_CONTEXT_FIRST_ACTIVATED				0x00000100
#define SHIFT_FW_FEEDBACK_CONTEXT_FIRST_ACTIVATED				8


/*
* UPDATE_PARAMETERS command second word
* [0] : Flag indicating there was an extra block of data associated with this update
*/
#define MASK_FW_FEEDBACK_UPDATE_WITHOUT_EXTRA_BLOCK				0x00000001
#define SHIFT_FW_FEEDBACK_UPDATE_WITHOUT_EXTRA_BLOCK			0

/*
* FENCE
* [0] : Flag signalling if this fence acknowledges the end of an abort (1) or not (0)
*/
#define MASK_FW_FEEDBACK_FENCE_IS_END_OF_ABORT					0x00000001
#define SHIFT_FW_FEEDBACK_FENCE_IS_END_OF_ABORT					0


/********************************************** FW/KERNEL SYNCHRONISATION **************************************************/
// Consumer/producer logic to maintain synchronisation between FW and kernel

/* Index range is [0, fifo_size - 1] */
#define MAX_PROD_AND_CONS_IDX (FEEDBACK_FIFO_MAX_COMMANDS - 1)

/*
* FW to host consumer (written by KM) [#FW_REG_FEEDBACK_CONSUMER]
* [16:21] : current consumer index in the feedback FIFO
* Firmware flags driven by KM:
* [22] : firmware should use bootloader method
*/
#define SHIFT_FW_FEEDBACK_CONSUMER_ID		16
#define MASK_FW_FEEDBACK_CONSUMER_ID		/*0x3f0000*/(MAX_PROD_AND_CONS_IDX /*0x3f*/ << SHIFT_FW_FEEDBACK_CONSUMER_ID)
#define SHIFT_FW_USE_BOOTLOADER				22
#define MASK_FW_USE_BOOTLOADER				0x00400000

/*
* FW to host producer (written by FW) [#FW_REG_FEEDBACK_PRODUCER]
* [0:15] : last command unique id saw by the main FW dispatch thread
* [16:21] : current producer index in the feedback FIFO
*/
#define SHIFT_FW_FEEDBACK_PRODUCER_CMDID	0
#define MASK_FW_FEEDBACK_PRODUCER_CMDID		0x0000ffff

#define SHIFT_FW_FEEDBACK_PRODUCER_LOWLATENCYBITS 16
#define MASK_FW_FEEDBACK_PRODUCER_LOWLATENCYBITS 0xF0000

#define SHIFT_FW_FEEDBACK_PRODUCER_ID		20
#define MASK_FW_FEEDBACK_PRODUCER_ID		/*0x3f0000*/(MAX_PROD_AND_CONS_IDX /*0x3f*/ << SHIFT_FW_FEEDBACK_PRODUCER_ID)


/* Firmware state */
#define FW_IDLE_STATUS_IDLE				(1)
#define FW_IDLE_STATUS_HW_ACTIVE		(2)
#define FW_IDLE_STATUS_BUSY				(3)
#define MASK_FW_IDLE_REG_STATUS			(0x3)
#define SHIFT_FW_IDLE_REG_STATUS		(0)

/* Restriction on the DMAC about size and alignement */
#define DMAC_BURSTSIZE_BYTES			(32)
#define DMAC_ALIGNMENT_BYTES			(64)
/*! The maximum number of channels in the SoC */
#define DMAC_MAX_CHANNELS       (1)




// NOTE: Real tiles only apply to HEVC
#define TILE_MIN_COL_SIZE_LUMA_SAMPLES 256
#define TILE_MIN_ROW_SIZE_LUMA_SAMPLES 64

/* In order to sync API and firmware, this defines the number of qp level we support [0..max_level] */
#define MAX_GOP_DEPTH (5)



#define LL_NODE_FULL_TYPE	1
#define LL_CODED_HEADER_TYPE	2

#define SHIFT_FW_PIPELOWLATENCYINFO_SEND					0			// Signifies a FIFO message should be mocked up and sent to API (0: None, 1: Node Full, 2: Coded Header)
#define MASK_FW_PIPELOWLATENCYINFO_SEND						0xf			// 4 bits

// Register fields ordered in priority order (CtxId used on register, LowLatency_Send used in stored version of register)
// |ID = Frame | Head = Tile/Slice | NodeCnt | CtxId (masked out in pdump replay checking) |
#define SHIFT_FW_PIPELOWLATENCYINFO_CTX						0			// Used to ID encode context generating buffer msg in low latency mode
#define MASK_FW_PIPELOWLATENCYINFO_CTX						0xf			// 4 bits

#define SHIFT_FW_PIPELOWLATENCYINFO_NODECNTTHISHEADER		4			// Incrementing signature used to detect a change in nodes filled in a given slice/tile (between two coded headers)
#define MASK_FW_PIPELOWLATENCYINFO_NODECNTTHISHEADER			0x7ff0		// 11bits


#define SHIFT_FW_PIPELOWLATENCYINFO_HEADCNT					15			// Absolute count of coded headers filled so far, used in low latency mode
#define MASK_FW_PIPELOWLATENCYINFO_HEADCNT					0x3ff8000	// 11 bits

#define	SHIFT_FW_PIPELOWLATENCYINFO_CMDID_SIG				26			// Cmdid signature (cmdids are unique per ctxt frame) generated by KM and used to ensure a low latency message is destined for the frame being output by KM (the full cmdid value is stored in the socket when the low latency mode is initialised using the VXE_FWMSG_FRAME_LOWLATENCY_INIT command)
#define	MASK_FW_PIPELOWLATENCYINFO_CMDID_SIG				0xfc000000	// 6 bits


/*************************************************** DMAC RELATED **********************************************************/

typedef enum _DMAC_eAccDel_
{
	DMAC_ACC_DEL_0 = 0x0,			//!< Access delay zero clock cycles
	DMAC_ACC_DEL_256 = 0x1,			//!< Access delay 256 clock cycles
	DMAC_ACC_DEL_512 = 0x2,			//!< Access delay 512 clock cycles
	DMAC_ACC_DEL_768 = 0x3,			//!< Access delay 768 clock cycles
	DMAC_ACC_DEL_1024 = 0x4,		//!< Access delay 1024 clock cycles
	DMAC_ACC_DEL_1280 = 0x5,		//!< Access delay 1280 clock cycles
	DMAC_ACC_DEL_1536 = 0x6,		//!< Access delay 1536 clock cycles
	DMAC_ACC_DEL_1792 = 0x7,		//!< Access delay 1792 clock cycles
} DMAC_eAccDel;

typedef enum _DMAC_eBSwap_
{
	DMAC_BSWAP_NO_SWAP = 0x0,		//!< No byte swapping will be performed.
	DMAC_BSWAP_REVERSE = 0x1,		//!< Byte order will be reversed.
} DMAC_eBSwap;

typedef enum _DMAC_eBurst_
{
	DMAC_BURST_0 = 0x0,				//!< burst size of 0
	DMAC_BURST_1 = 0x1,				//!< burst size of 1
	DMAC_BURST_2 = 0x2,				//!< burst size of 2
	DMAC_BURST_3 = 0x3,				//!< burst size of 3
	DMAC_BURST_4 = 0x4,				//!< burst size of 4
	DMAC_BURST_5 = 0x5,				//!< burst size of 5
	DMAC_BURST_6 = 0x6,				//!< burst size of 6
	DMAC_BURST_7 = 0x7,				//!< burst size of 7
} DMAC_eBurst;

typedef enum _DMAC_eDir_
{
	DMAC_DIR_MEM_TO_PERIPH = 0x0,	//!< Data from memory to peripheral.
	DMAC_DIR_PERIPH_TO_MEM = 0x1,	//!< Data from peripheral to memory.
} DMAC_eDir;

#define DMAC_VALUE_COUNT(BSWAP,PW,DIR,PERIPH_INCR,COUNT)			 \
	(((BSWAP) << SHIFT_IMG_SOC_BSWAP)	& MASK_IMG_SOC_BSWAP) | \
	(((PW) << SHIFT_IMG_SOC_PW)	& MASK_IMG_SOC_PW) | \
	(((DIR) << SHIFT_IMG_SOC_DIR)	& MASK_IMG_SOC_DIR) | \
	(((PERIPH_INCR) << SHIFT_IMG_SOC_PI)	& MASK_IMG_SOC_PI) | \
	(((COUNT) << SHIFT_IMG_SOC_CNT)	& MASK_IMG_SOC_CNT)
#define DMAC_VALUE_PERIPH_PARAM(ACC_DEL,INCR,BURST)					 \
	(((ACC_DEL) << SHIFT_IMG_SOC_ACC_DEL)	& MASK_IMG_SOC_ACC_DEL) | \
	(((INCR) << SHIFT_IMG_SOC_INCR)		& MASK_IMG_SOC_INCR) | \
	(((BURST) << SHIFT_IMG_SOC_BURST)		& MASK_IMG_SOC_BURST)

typedef enum _DMAC_ePW_
{
	DMAC_PWIDTH_32_BIT = 0x0,		//!< Peripheral width 32-bit.
	DMAC_PWIDTH_16_BIT = 0x1,		//!< Peripheral width 16-bit.
	DMAC_PWIDTH_8_BIT = 0x2,		//!< Peripheral width 8-bit.
} DMAC_ePW;


/*************************************************** UTILITY MACROS ********************************************************/

#define F_MASK(basename)  (MASK_##basename)
#define F_SHIFT(basename) (SHIFT_##basename)
#define F_BITS(basename) (NBITS_##basename)
/* Extract a value from an instruction word */
#define F_EXTRACT(val,basename) (((val) & (F_MASK(basename))) >> (F_SHIFT(basename)))
/* Mask and shift a value to the position of a particular field */
#define F_ENCODE(val,basename)  (((val) << (F_SHIFT(basename))) & (F_MASK(basename)))

#define F_DECODE(val,basename)  (((val)&(F_MASK(basename)))>>(F_SHIFT(basename)))

/* Get the maximum value*/
#define F_MAX(basename)  ((1 << (F_BITS(basename))) - 1)

/* Insert a value into a word */
#define F_INSERT(word,val,basename) (((word)&~(F_MASK(basename))) | (F_ENCODE((val),basename)))


/****************************************************** TYPEDEF ************************************************************/
/**
 * \file vxe_fw_if.h
 * \enum VXE_COMMAND_TYPE
 * \brief List of commands sent firmware commands
**/
typedef enum _VXE_COMMAND_TYPE_
{
	/* Basic commands */
	VXE_COMMAND_ENCODE_FRAME,		//!< Encode a single frame
	VXE_COMMAND_ACTIVATE_CONTEXT,	//!< Activate a single FW context (to match a new API context)
	VXE_COMMAND_ABORT_CONTEXT,		//!< Destroy a single FW context (associated API context should also be destroyed)
	VXE_COMMAND_DEACTIVATE_CONTEXT,	//!< Remove the entry in the global array of external memory pointers holding contexts
	VXE_COMMAND_FENCE,				//!< Issue an interrupt when cmd is completed (associated with the command number)
	VXE_COMMAND_INSERT_HEADER,		//!< Perform firmware header insertion for the sequence to encode
	VXE_COMMAND_UPDATE_PARAMETERS,	//!< Update a defined subset of the context structure part-way through the encode

	/* Advanced commands */
	VXE_COMMAND_FIRMWARE_READY,		//!< More a feedback than a command but this will share a common interface with the other commands' feedback, hence it is defined in this enum
	VXE_COMMAND_LIST_OVERFLOW,		//!< Signals that an overflow occurred on a linked list
	VXE_COMMAND_CONFIGURE_MMU,		//!< Can only be sent as the first command and it must be there when the firmware boots

	VXE_COMMAND_COUNT				//!< Keeps track of the total number of commands
} VXE_COMMAND_TYPE;
STATIC_ASSERT(VXE_COMMAND_COUNT <= (1 + (MASK_FW_FEEDBACK_COMMAND_TYPE >> SHIFT_FW_FEEDBACK_COMMAND_TYPE))); /* we have a limitation on the number of bits we can use */

/**
* \file vxe_fw_if.h
* \enum VXE_ERROR_TYPE
* \brief List of error code sent by firmware
**/
typedef enum _VXE_ERROR_TYPE_
{
	VXE_ERROR_DISCARDED_COMMAND,	//!< Command has been discarded (by the main dispatch) because of an abort

	VXE_ERROR_COUNT					//!< Keeps track of the total number of errors
} VXE_ERROR_TYPE;


/**
 * \file vxe_fw_if.h
 * \enum VXE_FWUPDATE_TYPE
 * \brief When sending an update parameter command, inform about which kind it is
**/
typedef enum _VXE_FWUPDATE_TYPE_
{
	VXE_FWUPDATE_BATCHES = 0,				//!< Batches => using extra data as a region to memcpy/DMA
	
	VXE_FWUPDATE_CONTEXT,
	VXE_FWUPDATE_REGISTERS,
	VXE_FWUPDATE_FIXED_SEQ_PAR,
//	VXE_FWUPDATE_RC,
	VXE_FWUPDATE_RC_PARAMS,
	VXE_FWUPDATE_INTRA_REFRESH_MODE,		// two values : type and number of CTU to refresh
	VXE_FWUPDATE_IN_SLICE_RPS,
	VXE_FWUPDATE_LONGTERM_RPS,
//	VXE_FWUPDATE_GOP_STRUCT,				// to be determined: number of B, hierarchy, ..

	VXE_FWUPDATE_SINGLES,					//<! Single => update of only one value in the context

	VXE_FWUPDATE_DISABLE_STUFFING,
	VXE_FWUPDATE_ENC_BITRATE,				// HRD regen
	VXE_FWUPDATE_BUF_BITRATE,				// RC information
	VXE_FWUPDATE_FRAMERATE,
	VXE_FWUPDATE_MAX_QP,					// RC constraints
	VXE_FWUPDATE_MIN_QP,					// RC constraints
	VXE_FWUPDATE_INIT_QP,
	VXE_FWUPDATE_BUFFER_TENTHS,
	VXE_FWUPDATE_RC_CFS_MAX_MARGIN_PERC,
	VXE_FWUPDATE_FRAME_SKIPPING,
	VXE_FWUPDATE_SCENE_DETECT_DISABLE,
	VXE_FWUPDATE_BASIC_UNIT_SIZE,			// Not updated directly but its value depends on other variables updated dynamically
	VXE_FWUPDATE_BPP,						// Not updated directly but its value depends on other variables updated dynamically	
	VXE_FWUPDATE_BITS_PER_FRAME_AND_BU,		// Not updated directly but its value depends on other variables updated dynamically
	VXE_FWUPDATE_BUFFER_SIZE_IN_FRAMES,		// Not updated directly but its value depends on other variables updated dynamically
	VXE_FWUPDATE_INITIAL_LEVEL,				// Not updated directly but its value depends on other variables updated dynamically
	VXE_FWUPDATE_PRED_GOP_INIT_FRAME_SIZE,	// Not updated directly but its value depends on other variables updated dynamically
	VXE_FWUPDATE_PRED_GOP_INIT_PROP_RANGE,	// Not updated directly but its value depends on other variables updated dynamically
	VXE_FWUPDATE_INTRACNT,					// A subset of the GOP structure
	VXE_FWUPDATE_MAX_SLICE_SIZE,			// one register value
	VXE_FWUPDATE_HOST_HEADER,				// not generation of vps, sps, pps by hardware (so we can regenerate them of the fly), bool or flag to disable header insert in FW
    VXE_FWUPDATE_SRC_STRIDE,
    VXE_FWUPDATE_SRC_FORMAT,

	VXE_FWUPDATE_TOTAL_COUNT
} VXE_FWUPDATE_TYPE;

#define VXE_FWUPDATE_TOTAL_SINGLES		(VXE_FWUPDATE_TOTAL_COUNT - VXE_FWUPDATE_SINGLES)
#define VXE_FWUPDATE_TOTAL_RC_SINGLES	(VXE_FWUPDATE_PRED_GOP_INIT_PROP_RANGE - VXE_FWUPDATE_SINGLES)


#define FW_MMU_CONFIG_SIZE 0x2 /* size of MMU CONFIG data in units of standard FW command (which is 4x32bits) */

/**
 * \file vxe_fw_if.h
 * \enum VXE_FWMESSAGE_TYPE
 * \brief List of the commands received from the firmware
**/
typedef enum _VXE_FWMESSAGE_TYPE_
{
	VXE_FWMSG_ACK,						//!< Command has been executed
	VXE_FWMSG_CODED_BUFFER,				//!< Coded buffer is available
	VXE_FWMSG_FRAME_LOWLATENCY_INIT,	//!< Low latency start notification message (FW to KM only)
	VXE_FWMSG_ERROR						//!< An error occured
} VXE_FWMESSAGE_TYPE;


enum Header_Type
{
	HEADER_VPS = 0,
	HEADER_SPS,
	HEADER_SLICE_START_FIRST,
	HEADER_SLICE_END,
	HEADER_SLICE_I,
	HEADER_SLICE_P,
	HEADER_SLICE_B,
	HEADER_SLICE_IDR,
	HEADER_SLICE_START_NOT_FIRST,
	HEADER_AUD,
	HEADER_PREFIX_BUFFERING_PERIOD_SEI_MSG,
	HEADER_PREFIX_PIC_TIMING_SEI_MSG,
	HEADER_SUFFIX_SEI_DPH_MSG,
	HEADER_FILLER_DATA,
	// We can send multiple Picture Headers, this final enum is actually the start of an array (ensure this remains the final enum)
	HEADER_PPS_x,

	HEADER_ENDOFENUM		//This must be at the end of the enum - used to calculate max table sizes
};


/*HRD (and SEI) message flags*/
#define FW_INTERNALS_HRD_AUD									(0x00000001) // parsing of AUD SEI messages is activated
#define FW_INTERNALS_HRD_SEI_PREFIX_BUFFERING_PERIOD			(0x00000002) // parsing of buffer period SEI messages is activated
#define FW_INTERNALS_HRD_SEI_PREFIX_PIC_TIMING					(0x00000004) // parsing of picture timing SEI messages is activated
#define FW_INTERNALS_HRD_SEI_SUFFIX_DECODED_PICTURE_HASH		(0x00000008) // parsing of decoded_picture_hash SEI message is activated


typedef struct _VXE_DEVMEM_LINKED_LIST_NODE_
{
	IMG_UINT32	ui32DevMem;
	IMG_UINT32	ui32LinkedListNext;
} VXE_DEVMEM_LINKED_LIST_NODE;


/**
 * \file vxe_fw_if.h
 * \struct IMG_FRAME_ENCODE_FW_PARAMS
 * \brief Encode parameters to send with an VXE_COMMAND_ENCODE_FRAME command
**/

typedef struct _VXE_FW_SRCFRAME_
{

	IMG_UINT32 ui32DevAddrYPlane_Field0; //!< Source pic dev virt addr (Y plane, Field 0)
	IMG_UINT32 ui32DevAddrUPlane_Field0; //!< Source pic dev virt addr (U plane, Field 0)
	IMG_UINT32 ui32DevAddrVPlane_Field0; //!< Source pic dev virt addr (V plane, Field 0)
	IMG_UINT32 ui32FrameNumber;			 //!< Picture order count
	IMG_UINT32 ui32FrameCount;			 //!< Header field counting frames used for reference
	IMG_UINT32 ui32EncodeOrder;
	IMG_BOOL	bIsLongTermRef;
	IMG_UINT32	ui32LtrUsed;			//!< Long term reference used for encode
	IMG_UINT8	long_term_idx;				//!< If bIsLongTermRef is set, then this contains the value to be written to long_term_frame_idx syntax element
	IMG_BYTE padding[3];			 
} VXE_FW_SRCFRAME;




typedef struct _VXE_FW_CTU_CONTROL_DATA_
{
	IMG_UINT32	ui32DevAddrCTUControlInput;			//!< Dev Virt Addr of CTU Level Control Input Memory (mapped for a single frame)
	IMG_UINT32	ui32DevAddrEncodeDecisionOutput;	//!<Dev Vir Addr of CTU Encode Decision Output Memory (mapped for a single frame)
	IMG_UINT32	ui32EncodeDecisionOutputCtrl;		//!< Control structure containing ENCODE_DECISION_OUTPUT_CONTROL flags
	IMG_UINT16	ui16OutputSizePerCTU;				//!< Size of an individual CTU Encode Decision Output Element (as defined by the ui32EncodeDecisionOutputCtrl field and the current frame type)
	IMG_UINT8	ui8CTULevelInputCtrl;				//!< Control structure containing CTU_LEVEL_CONTROL flags
	IMG_UINT8	ui8InputSizePerCTU;					//!< Size of an individual CTU Encode Decision  Output Element (as defined by the ui32EncodeDecisionOutputCtrl field)
} VXE_FW_CTU_CONTROL_DATA;
STATIC_ASSERT((sizeof(VXE_FW_CTU_CONTROL_DATA) & 0x3) == 0);


typedef struct _VXE_FW_CTU_INPUT_DATA_
{
	IMG_UINT32	ui32DevAddrCTUControlInput;			//!< Dev Virt Addr of CTU Level Control Input Memory (mapped for a single frame)
	IMG_UINT8	ui8CTULevelInputCtrl;				//!< Control structure containing CTU_LEVEL_CONTROL flags
	IMG_UINT8	ui8InputSizePerCTU;					//!< Size of an individual CTU Encode Decision  Output Element (as defined by the ui32EncodeDecisionOutputCtrl field)
	IMG_UINT16	ui16InputSizePerBuffer;				//!< Size of an individual CTU Input Buffer (CTUSize * kicksize)
} VXE_FW_CTU_INPUT_DATA;
STATIC_ASSERT((sizeof(VXE_FW_CTU_INPUT_DATA) & 0x3) == 0);


typedef struct VXE_FW_CTU_OUTPUT_DATA_
{
	IMG_UINT32	ui32DevAddrEncodeDecisionOutput;	//!<Dev Vir Addr of CTU Encode Decision Output Memory (mapped for a single frame)
	IMG_UINT32	ui32EncodeDecisionOutputCtrl;		//!< Control structure containing ENCODE_DECISION_OUTPUT_CONTROL flags
	IMG_UINT16	ui16OutputSizePerCTU;				//!< Size of an individual CTU Encode Decision Output Element (as defined by the ui32EncodeDecisionOutputCtrl field and the current frame type)
	IMG_UINT16	ui16OutputSizePerBuffer;			//!< Size of an individual CTU Output Buffer (CTUSize * kicksize)
} VXE_FW_CTU_OUTPUT_DATA;
STATIC_ASSERT((sizeof(VXE_FW_CTU_OUTPUT_DATA) & 0x3) == 0);


typedef struct _VXE_FW_RECFRAME_
{
	IMG_UINT32 ui32DevAddrYPlane_Field0; //!< Source pic dev virt addr (Y plane, Field 0)
	IMG_UINT32 ui32DevAddrUPlane_Field0; //!< Source pic dev virt addr (U plane, Field 0)
	IMG_UINT32 ui32DevAddrVPlane_Field0; //!< Source pic dev virt addr (V plane, Field 0)
} VXE_FW_RECFRAME;


typedef struct _VXE_FW_REFFRAME_
{
	IMG_UINT32 ui32DevAddrYPlane_Field0; //!< Source pic dev virt addr (Y plane, Field 0)
	IMG_UINT32 ui32DevAddrUPlane_Field0; //!< Source pic dev virt addr (U plane, Field 0)
	IMG_UINT32 ui32DevAddrVPlane_Field0; //!< Source pic dev virt addr (V plane, Field 0)

	IMG_UINT32 ui32FramePOC;
	IMG_UINT32 ui32FrameEnc;
	IMG_UINT32 ui32FrameBufIdx;
	IMG_BOOL   bIsLTR;
} VXE_FW_REFFRAME;


typedef enum _VXE_P_CONFIG_
{
	VXE_P_ISDOUBLEREF = 1 << 0,//!< Double reference P picture
	VXE_ISTRAIL = 1 << 1,      //!< Forces frame to be trailing
	VXE_NEED_IN_SLICE_RPS = 1 << 2,
	VXE_REFS_SWAPPED = 1 << 3,
	VXE_CODE_FRAME_AS_SKIPPED = 1 << 4
} VXE_P_CONFIG;



//Contains information relating to and accumulated for the current coded message since the start of the encode task on this pipe
typedef struct _FW_LIST_CODED_EXTRA_INFO_
{
	FW_CODED_DATA_HDR sThisCBExtraInfo;
	IMG_UINT32 ui32DevAddrThisCodedDataHdr;
	IMG_UINT16 ui16ExtraInfoIdx;
	IMG_UINT16 ui16Pad[1];
} FW_LIST_CODED_EXTRA_INFO;

typedef struct _IMG_FRAME_ENCODE_FW_PERPIPE_INFO_
{
	IMG_UINT32 ui32LinkedListInfo;
	IMG_UINT32 ui32SliceMapOffset;
	IMG_UINT32 ui32DevAddrCodedExtraInfo;
	VXE_DEVMEM_LINKED_LIST_NODE sCodedFrame;	//!< Coded Output buffer device virtual address followed by the dev address of the next VXE_DEVMEM_LINKED_LIST_NODE to be used (if linked list mode is active, otherwise will be NULL? or point back to it's own VXE_DEVMEM_LINKED_LIST_NODE?)
	IMG_BYTE aPad[4];							//!< Padding here because when max_pipes_to_use changes, the IMG_FRAME_ENCODE_FW_PARAMS::aPerPipeParams could have side effect in the node alignements
} IMG_FRAME_ENCODE_FW_PERPIPE_INFO;
STATIC_ASSERT((sizeof(IMG_FRAME_ENCODE_FW_PERPIPE_INFO) & 0x7) == 0);


typedef struct _IMG_CODEDLISTINFO_
{
//	IMG_UINT32 ui32TotalBytesAvailableForList;	//!< The total coded buffer bytes available for the list ( = ui16ListNodeSizeDiv1024 * 1024 * Number Of Nodes Per Coded List)
	IMG_UINT16 ui16CodedListCnt;
	IMG_BYTE aPad[2];
//	IMG_UINT16 ui16ListNodeSizeDiv1024;
} IMG_CODEDLISTINFO;

typedef struct reordering_info_s
{
	IMG_UINT16 gop_spec				;	/**< 0: cmdline gop. 1: config file gop*/
	IMG_UINT16 need_reorder			;
	IMG_UINT16 NumPicTotalCurr		;
	IMG_UINT16 list_entry_l0		;
	IMG_UINT16 list_entry_l1		;
	IMG_UINT16 num_ref_id_l0_active ;
	IMG_UINT16 num_ref_id_l1_active ;
	IMG_BYTE padding[2];
} reordering_info_t;

typedef struct _IMG_FRAME_ENCODE_FW_PARAMS_
{
	VXE_FRAME_TYPE 	eFrameType;							//!< Frame type to be encoded
	VXE_FW_SRCFRAME sSrcFrame;
	VXE_FW_RECFRAME sRecFrame;
	VXE_FW_REFFRAME asRefFrame[MAX_POSSIBLE_REFERENCE_FRAMES];

	VXE_FW_CTU_CONTROL_DATA sCTUControlData;

	IMG_UINT32		ui32_DIST_SCALE_FACT_COL1;			//!< Needs to be compute per frame but involves a division
	IMG_UINT32		ui32_DIST_SCALE_FACT_COL0;			//!< Needs to be compute per frame but involves a division
	IMG_UINT32		ui32_DIST_SCALE_FACT_PIC_TO_PIC;
	IMG_UINT32		ui32SliceMapDevAddr;				//!< One DEV address containing slice maps for each pipe
	IMG_UINT32		ui32SliceMapSize;					//!< Total size of slice map structure containing all slicemaps
	IMG_CODEDLISTINFO sCodedListInfo;
	IMG_UINT8		ui8FrameQp;							//!< Qp to use if rate control is not enabled
	IMG_UINT8		ui8RefIdx;							//!< Precomputed reference frame index, used for the slice headers
	IMG_UINT8		ui8RefIdxNal;						//!< Precomputed reference frame index, used for NALs
	IMG_UINT8		ui8TLayer;							//!< Temporal layer of the frame to be encoded
	IMG_UINT32		ui32QPFactor;						//!< QP factor used for SAD, SSQE, etc. (20 bits used)

	IMG_UINT16		ui16IdrPicId;						//!< Identify an IDR frame
	IMG_BOOL8		ui8QpOffset;
	IMG_BYTE		ui8FrameBufferIdx;					//!< Buffer index used by current frame
	IMG_UINT32		ui32LastIDR;						//!< POC of last IDR picture
	IMG_UINT32		ui32CollocatedOut;					//!< Address of collocated out
	IMG_UINT32		ui32CollocatedIn;					//!< Address of collocated in
	IMG_UINT8		ui8InloopControlLSB;				//!< Depending on recon_output_enable state, bits [0..6] may change, especially used when reconstructed is output only for reference frame
	IMG_BOOL8		b8OutputRecon;						//!< Should the reconstructed be output for this frame
	IMG_UINT8		ui8FrameConfig;						//!< Bitfield: multiple_references_P | Trailing_pic
	IMG_UINT8		ui8GopDepth;						//!< Which layer (not temporal) the frame is located on
	IMG_BOOL8		b8IsUsedForReference;				//!< Is this frame used as a reference
	IMG_BOOL8		ab8CollocatedLTR[2];				//!< True when the reference picture of the collocated picture is a long term reference.
	IMG_UINT8		ui8Padding;
	IMG_UINT32		eCacheMode;

	///////////////////////////////////////////////////////////////////////////////////////////////////
	// Because we have linked list nodes below that needs to have 8 byte aligned start addresses
	// everything from this point onwards needs to be 8 byte aligned
	//////////////////////////////////////////////////////////////////////////////////////////////////
	VXE_FRAME_TYPE	eLeftRefType;						//!< From this type depends the temporal colocated read register field

	// The linked list node addresses have to be multiple of 8 bytes, so we guarantee (&aPerPipeParams[0]+7&7 == &aPerPipeParams[0])
	IMG_FRAME_ENCODE_FW_PERPIPE_INFO aPerPipeParams[MAX_CODED_LISTS_PER_ENCODE]; //!< Information for each pipe (includes coded buffer list pointer and slicemap pointer)

	IMG_UINT32		ui32CBSizeBytes;					//!< Coded Buffer Size

	IMG_UINT8		ui8SequencerConfigMSB;				//!< Holds PIC0_AND_PIC1_POC_LT0 and COLLOCATED_FROM_L0 MSB

	IMG_UINT8		ui8MarkAsUnused;

	IMG_UINT8		ref_pic_set_id;
	IMG_UINT8		nal_unit_type;
	reordering_info_t reorder_info;
	IMG_UINT8		lambda_qp_offset;
	IMG_UINT8		enc_id_in_gop_table;

	IMG_INT8		difference_of_pic_nums_minus1;
	IMG_UINT8		ui8PPSHdrIdx;						//!< The index of the PPS header use for this frame
	IMG_BOOL8		motion_search_on_left_ref;
	IMG_UINT8		num_bits_4_list_entry; //!< Number of bits used to represent the list_entry_l0/l1 in ref_pic_lists_modification(). = to Ceil(Log2(NumPicTotalCurr)).
	IMG_BOOL8		bInterScaleUpdateByQp;				//!< Inter Scale using Qp update
	IMG_BYTE		paddingEnd[5];//paddingEnd[8-(sizeof(struct _IMG_FRAME_ENCODE_FW_PARAMS_)%8)];

} IMG_FRAME_ENCODE_FW_PARAMS;
STATIC_ASSERT(offsetof(IMG_FRAME_ENCODE_FW_PARAMS, eLeftRefType) % 8 == 0); // See comment on aPerPipeParams
STATIC_ASSERT(sizeof(IMG_FRAME_ENCODE_FW_PARAMS) % 8 == 0);


#define DECLARE_REGISTER(REGISTER_NAME) IMG_UINT32 reg_ ## REGISTER_NAME
typedef struct _REGISTER_STORAGE_
{
	//DECLARE_REGISTER(MULTIPIPE_HOST_INT_ENAB);
	DECLARE_REGISTER(SECURE_CONFIG);
//	DECLARE_REGISTER(INT_ENABLE_PROC);
	DECLARE_REGISTER(INT_ENABLE_HOST);
	DECLARE_REGISTER(SCALER_INPUT_SIZE);
	DECLARE_REGISTER(SCALER_PITCH);
	DECLARE_REGISTER(SCALER_CROP);
	DECLARE_REGISTER(FRONT_END_MODE);
	DECLARE_REGISTER(SEQ_CUR_PIC_CONFIG);
	DECLARE_REGISTER(SEQ_CUR_PIC_SIZE);
//	DECLARE_REGISTER(FIELD_PARITY); // firmware patches it so no real need to precompute it
	DECLARE_REGISTER(SEQ_CUR_PIC_ROW_STRIDE);
	DECLARE_REGISTER(SCALER_VER_LUMA_COEFFS_0);
	DECLARE_REGISTER(SCALER_VER_LUMA_COEFFS_1);
	DECLARE_REGISTER(SCALER_VER_LUMA_COEFFS_2);
	DECLARE_REGISTER(SCALER_VER_LUMA_COEFFS_3);
	DECLARE_REGISTER(SCALER_VER_CHROMA_COEFFS_0);
	DECLARE_REGISTER(SCALER_VER_CHROMA_COEFFS_1);
	DECLARE_REGISTER(SCALER_VER_CHROMA_COEFFS_2);
	DECLARE_REGISTER(SCALER_VER_CHROMA_COEFFS_3);
	DECLARE_REGISTER(SCALER_HOR_LUMA_COEFFS_0);
	DECLARE_REGISTER(SCALER_HOR_LUMA_COEFFS_1);
	DECLARE_REGISTER(SCALER_HOR_LUMA_COEFFS_2);
	DECLARE_REGISTER(SCALER_HOR_LUMA_COEFFS_3);
	DECLARE_REGISTER(SCALER_HOR_CHROMA_COEFFS_0);
	DECLARE_REGISTER(SCALER_HOR_CHROMA_COEFFS_1);
	DECLARE_REGISTER(SCALER_HOR_CHROMA_COEFFS_2);
	DECLARE_REGISTER(SCALER_HOR_CHROMA_COEFFS_3);
	DECLARE_REGISTER(CSC_SOURCE_MOD_Y_0);
	DECLARE_REGISTER(CSC_SOURCE_MOD_Y_1);
	DECLARE_REGISTER(CSC_SOURCE_MOD_Y_2);
	DECLARE_REGISTER(CSC_SOURCE_CB_CR_0);
	DECLARE_REGISTER(CSC_SOURCE_CB_CR_1);
	DECLARE_REGISTER(CSC_SOURCE_CB_CR_2);
	DECLARE_REGISTER(CSC_OUTPUT_COEFF_0);
	DECLARE_REGISTER(CSC_OUTPUT_COEFF_1);
	DECLARE_REGISTER(CARC_CONTROL_0);
	DECLARE_REGISTER(CARC_CONTROL_1);
	DECLARE_REGISTER(SEQUENCER_CONFIG);
	DECLARE_REGISTER(WAVEFRONT_CONFIG);
	DECLARE_REGISTER(ME_CONFIG);
	DECLARE_REGISTER(PREFETCH_LIMIT_MV);
	DECLARE_REGISTER(IME_LIMIT_MV);
	DECLARE_REGISTER(CACHE_BANDWIDTH_LIMIT);
	DECLARE_REGISTER(WEIGHTED_PRED_CONTROL);
	DECLARE_REGISTER(ENCODE_DECISION_CONFIG);
	DECLARE_REGISTER(ENCODE_DECISION_CONFIG_2);
	DECLARE_REGISTER(QPCB_QPCR_OFFSET);
	DECLARE_REGISTER(VIDEO_CONF_CONTROL_0);
	DECLARE_REGISTER(VLC_IPCM_CONTROL);
	DECLARE_REGISTER(VLC_IPCM_0);
	DECLARE_REGISTER(VLC_IPCM_1);
	DECLARE_REGISTER(VLC_SLICE_CTRL_0);
	DECLARE_REGISTER(VLC_SLICE_CTRL_1);
	DECLARE_REGISTER(VLC_SLICE_CTRL_2);
	DECLARE_REGISTER(ENCODE_DECISION_OUTPUT_CONTROL);
//	DECLARE_REGISTER(ENCODE_DECISION_OUTPUT_ADDR); // changes every kick so not computed
	DECLARE_REGISTER(INLOOP_CONTROL);
	DECLARE_REGISTER(VLC_OUTPUT_CONTROL);
//	DECLARE_REGISTER(VLC_WRITE_ADDR);
	DECLARE_REGISTER(VLC_FLUSH_CONTROL);
	DECLARE_REGISTER(QUARTZ_MULTICONTEXT_CONFIG);
	DECLARE_REGISTER(FRAME_BUFFER_COMPRESSION_ENABLE);
	DECLARE_REGISTER(FRAME_BUFFER_COMPRESSION_SETUP);
} REGISTERS_HOST_STORAGE;


/**
* Different elements the firmware can insert
*/
typedef enum e_HEADER_ELEMENT_TYPE
{
	ELEMENT_EOS = 0,								//!< Last element of structure
	ELEMENT_QP,										//!< Insert the H264 Picture Header QP parameter
	ELEMENT_SQP,									//!< Insert the H264 Slice Header QP parameter
	ELEMENT_INSERTBYTEALIGN,
	ELEMENT_TRAILING,
	ELEMENT_FILLER_DATA,							//!< Insert filler data NAL unit (nal_unit_type=12 for H.264 / nal_unit_type=38 for H.265)

	// SEI Buffering Period parameters
	ELEMENT_INITIAL_CPB_REMOVAL_DELAY,
	ELEMENT_INITIAL_CPB_REMOVAL_OFFSET,
	ELEMENT_INITIAL_ALT_CPB_REMOVAL_DELAY,			//!< May not be needed
	ELEMENT_INITIAL_ALT_CPB_REMOVAL_OFFSET,			//!< May not be needed

	ELEMENT_VCL_INITIAL_CPB_REMOVAL_DELAY,
	ELEMENT_VCL_INITIAL_CPB_REMOVAL_OFFSET,

	ELEMENT_CPB_REMOVAL_DELAY,
	ELEMENT_DPB_OUTPUT_DELAY,

	ELEMENT_AU_CPB_REMOVAL_DELAY_MINUS1,
	ELEMENT_PIC_DPB_OUTPUT_DELAY,
	ELEMENT_PIC_DPB_OUTPUT_DU_DELAY,


	// Slice parameters
	//ELEMENT_FIRSTSLICE,								//!< First slice segment of the picture in decoding order ?
	ELEMENT_DEPENDENT_SLICE,						//!< Slice dependant to previous one ? May be removed later, following ELEMENT_FIRSTSLICE
	ELEMENT_SLICE_FIRST_CTB,						//!< ONLY first slice. Address of the first coding tree block (Ceil(Log2(PicSizeInCtbsY) bits))
	ELEMENT_PRIOR_PIC_OUT,							//!< Output previous frames if on BLA/RSV NAL
	ELEMENT_SLICE_NAL,						    	//!< Slice NAL
	
	// Non-dependent slice parameters
	ELEMENT_SLICE_TYPE,								//!< B->0, P->1, I->2
	ELEMENT_ORDER_CNT,								//!< Picture order count modulo MaxPicOrderCntLsb aka frame_num
	//ELEMENT_SPS_REF_SET_ID,							//!< SPS reference set
	ELEMENT_STRPS,									//!< Short term reference pic set 
	ELEMENT_REORDERING,								//!< Slice reference picture list reordering 
	ELEMENT_LONG_TERM_SPS,							//!< Number of ltrp from SPS
	ELEMENT_LONG_TERM_SLICE,						//!< Number of ltrp in slice header
	ELEMENT_LONG_TERM_BLOC,							//!< Write long term ref in coded output
	ELEMENT_TEMPORAL_MVP_IDX,						//!< Reference index of the collocated picture used for temporal motion vector prediction
	ELEMENT_QP_DELTA_Y,								//!< QpY used for the coding blocks

	ELEMENT_SAO_FLAGS,


	// h264 slice

	ELEMENT_CURRMBNR,
	ELEMENT_QS_DELTA,
	ELEMENT_FRAME_NUM,
	ELEMENT_BOTTOM_FIELD,
	ELEMENT_IDR_PIC_ID,
	ELEMENT_DIRECT_SPATIAL_MV_FLAG,
	ELEMENT_ALPHA_C0_OFFSET_DIV2,
	ELEMENT_BETA_OFFSET_DIV2,
	ELEMENT_REFMARKING,								//<! Mark frame as long term ref (or not)
	ELEMENT_REFNUM,									//<! Used to decrease ref_pic_list0 idx
	ELEMENT_TEMPORAL_LAYER,
	ELEMENT_TEMPORAL_H264,							//<! Using nal_ref_idc for h264 temporal layers
	ELEMENT_LAST,

	//decoded_picture_hash
	ELEMENT_PICTURE_CHECKSUM_LUMA,
	ELEMENT_PICTURE_CHECKSUM_CR,
	ELEMENT_PICTURE_CHECKSUM_CB,

	ELEMENT_ST_RPS_SPS_FLAG,

} HEADER_ELEMENT_TYPE;


typedef enum e_nal_unit_type_h265
{
	TRAIL_N = 0,
	TRAIL_R,
	TSA_N,
	TSA_R,
	STSA_N,
	STSA_R,
	RADL_N,
	RADL_R,
	RASL_N,
	RASL_R,
	RSV_VCL_N10 = 10,
	RSV_VCL_N12 = 12,
	RSV_VCL_N14 = 14,
	RSV_VCL_R11 = 11,
	RSV_VCL_R13 = 13,
	RSV_VCL_R15 = 15,
	BLA_W_LP = 16,
	BLA_W_RADL, /* 17 */
	BLA_N_LP,
	IDR_W_RADL,
	IDR_N_LP,
	CRA_NUT,
	RSV_IRAP_VCL22,
	RSV_IRAP_VCL23,

	RSV_VCL24,
	RSV_VCL25,
	RSV_VCL26,
	RSV_VCL27,
	RSV_VCL28,
	RSV_VCL29,
	RSV_VCL30,
	RSV_VCL31,

	VPS_NUT,
	SPS_NUT,
	PPS_NUT,
	AUD_NUT,
	EOS_NUT,
	EOB_NUT,
	FD_NUT,
	PREFIX_SEI_NUT,
	SUFFIX_SEI_NUT,
	RSV_NVCL41,
	RSV_NVCL42,
	RSV_NVCL43,
	RSV_NVCL44,
	RSV_NVCL45,
	RSV_NVCL46,
	RSV_NVCL47,
	UNSPEC48,
	UNSPEC49,
	UNSPEC50,
	UNSPEC51,
	UNSPEC52,
	UNSPEC53,
	UNSPEC54,
	UNSPEC55,
	UNSPEC56,
	UNSPEC57,
	UNSPEC58,
	UNSPEC59,
	UNSPEC60,
	UNSPEC61,
	UNSPEC62,
	UNSPEC63,
} NAL_UNIT_TYPE_H265;


/*!
* \enum e_nal_unit_type_h264
* \typedef NAL_UNIT_H264
* \brief NAL unit value as per ITU-H264 spec. dated 2013-04 p62
*/
typedef enum e_nal_unit_type_h264
{
	H264_UNSPEC0 = 0,
	H264_CODED_S_NON_IDR,
	H264_CODED_S_PART_A,
	H264_CODED_S_PART_B,
	H264_CODED_S_PART_C,
	H264_CODED_S_IDR,
	H264_SEI,
	H264_SPS,
	H264_PPS,
	H264_AUD,
	H264_END_OF_SEQ,
	H264_END_OF_STREAM,
	H264_FILLER_DATA,
	H264_SPS_EXTENSION,
	H264_PREFIX_NAL_UNIT,
	H264_SUBSET_SPS,
	H264_RSV16,
	H264_RSV17,
	H264_RSV18,
	H264_SLICE_LAYER_WO_PARTITIONING,
	H264_SLICE_EXTENSION,
	H264_SLICE_EXTENSION_FOR_DEPTH_VIEW_COMP,
	H264_RSV22,
	H264_RSV23,
	H264_UNSPEC24,
	H264_UNSPEC25,
	H264_UNSPEC26,
	H264_UNSPEC27,
	H264_UNSPEC28,
	H264_UNSPEC29,
	H264_UNSPEC30,
	H264_UNSPEC31,
} NAL_UNIT_H264;


/******************************************************************************
 *
 * @details    RC_UPDATE - IMG_V_RCUpdate parameters
 *
 * @brief      RC update parameters
 *
 ****************************************************************************/
//typedef struct tag_IMG_PICMGMT_RC_UPDATE_DATA
//{
//	IMG_UINT32		ui32BitsPerFrame;		//!< Number of bits in a frame
//} IMG_PICMGMT_RC_UPDATE_DATA;


/* The number of FW contexts that can fit inside the embedded core memory */
#define FW_CORE_CONTEXTS (3)


/***************************************************** FIRMWARE CONTEXT PARAMETERS *****************************************************/


// Predefined GOPs
#define RC_WRONG_QP_OFFSET							(-64)

#define RC_MAX_NUM_LEVELS							4
#define RC_MAX_MINIGOP_FRAMES						8		// Modify as needed

#define RC_MINIGOP_PROP_SCALE						10

#define RC_MINIGOP_PROP_QP_LOW						20
#define RC_MINIGOP_PROP_QP_HIGH						35

/*!
* @enum _IMG_RC_PROP_RANGE_
* @brief Frame proportion range
*/
typedef enum _IMG_RC_MINIGOP_PROP_
{
	IMG_RC_MINIGOP_PROP_QP_LOW = 0,
	IMG_RC_MINIGOP_PROP_QP_MID = 1,
	IMG_RC_MINIGOP_PROP_QP_HIG,
	IMG_RC_MINIGOP_PROP_NUMRANGES
} IMG_RC_MINIGOP_PROP;

/*!
* @struct _VXE_MINIGOP_DATA_
* @brief MiniGopData structure
*/
typedef struct _IMG_RC_MINIGOP_DATA_
{
	VXE_RC_GOP_TYPE	eRcGopType;										//!< Gop Type

	IMG_INT32		i32PredefinedGOPIFrameSize;						//!< Predefined GOPs

	IMG_UINT16		ui16MiniGopFrameProp[IMG_RC_MINIGOP_PROP_NUMRANGES][RC_MAX_NUM_LEVELS];	// Frame proportions array. One value per level/offset, in decreasing order
	IMG_UINT16		ui16PicOnLevel[RC_MAX_NUM_LEVELS];				// Number of pictures in every level
	
	//IMG_INT8		i8MiniGopQpOffset[RC_MAX_MINIGOP_FRAMES];		// Qp offsets array. One value per frame, in the encoding order
	IMG_INT8		i8QpOffsetOfLevel[RC_MAX_NUM_LEVELS];			// Qp offsets in levels order. i8QpOffsetOfLevel[i] allocates the QP offset used in the level i
	IMG_UINT8		ui8MiniGopNumFrames;							// MiniGop length in frames
	IMG_UINT8		ui8MiniGopNumIFrames;							// MiniGop number of I frames
	IMG_UINT8		ui8MiniGopNumPFrames;							// MiniGop number of P frames
	IMG_UINT8		ui8MiniGopNumBFrames;							// MiniGop number of B frames
	IMG_UINT8		ui8MiniGopNumLevels;							// Number of levels used by the MiniGOP. One level per each QP offset value
	IMG_UINT8		ui8MiniGopCurrFrmPropRange;						// Current frame proportion range

	IMG_BOOL8		b8NeedsReordering;								// True when the Gop needs reordering
	IMG_BOOL8		b8PredefinedGopComp;							// Unknown gop compatible with Predefined GOPs

	//IMG_BYTE		padding[2];
} IMG_RC_MINIGOP_DATA;


/*!
* @struct _VXE_IREFRESH_DATA_
* @brief IRefreshData structure
*/
typedef struct _IMG_RC_IREFRESH_DATA_
{
//    IMG_INT32   i32MinQP;               //!< Minimum QP
    IMG_INT32   i32RcBufferSize;        //!< Buffer size
    IMG_INT32   i32RcBufferSizeFrames;  //!< Buffer size in frames
    IMG_INT32   i32InitialLevel;        //!< Initial level
    IMG_INT32   i32InitialDelay;        //!< Initial delay
    IMG_INT32   i32BitsPerFrm;          //!< Bits per frame

    IMG_UINT32  ui32Enc_Bitrate;        //!< Bitrate
    IMG_UINT32  ui32Buf_BitRate;        //!< Transfer rate
    IMG_UINT32  ui32BitsPerBU;          //!< Bits per BU
    IMG_UINT32  ui32RCScaleFactor;      //!< Scale factor

//    IMG_INT16   i16InitQP;              //!< Initial QP
//    IMG_INT16   i16SeInitQPI;           //!< Sequence QP

    IMG_BYTE      padding[4];
} IMG_RC_IREFRESH_DATA;


/*!
* @struct _VXE_FW_RC_PARAMS_
* @brief Related information that firmware (RC) requires
*/
typedef struct _RC_PARAMS_
{
	IMG_UINT64				ui64ClockDivBitrate;					//!< Clock Div Bitrate

	IMG_RC_MINIGOP_DATA		sMiniGopData;							//!< MiniGopData structure
	IMG_RC_IREFRESH_DATA	sIRefreshData;							//!< IRefreshData structure
	IMG_RC_IREFRESH_DATA	sNoIRefreshData;						//!< NoIRefreshData structure
	VXE_RC_MODE				eRCMode;								//!< RC mode
	IMG_RC_VCM_MODE			eRCVcmMode;								//!< RC VCM flavour
	
	IMG_INT32				i32BitsPerFrm;							//!< Bits per frame
	IMG_INT32				i32InitialLevel;						//!< Initial Level of Buffer
	IMG_INT32				i32InitialDelay;						//!< Initial Delay of Buffer
	IMG_INT32				i32RcBufferSizeFrames;					//!< Size of Buffer in frames, to be used in VCM
	IMG_INT32				i32RcBufferSize;						//!< Buffer size

	IMG_UINT32				ui32MaxBufferMultClockDivBitrate;		//!< Max Buffer Mult Clock Div Bitrate
	IMG_UINT32				ui32InitialCPBremovaldelayoffset;		//!< Initial CPB removal delay offset
	IMG_UINT32				ui32IntraCnt;							//!< Intra period
	IMG_UINT32				ui32BitsPerBU;							//!< Bits per BU
	IMG_UINT32				ui32Bitrate;							//!< Encode target bit rate
	IMG_UINT32				ui32FrameRate;							//!< Frame rate
	IMG_UINT32				ui32TransferRate;						//!< Rate at which bits are sent from encoder to the output after each frame finished encoding
	IMG_UINT32				ui32RCScaleFactor;						//!< RC scale factor
	IMG_UINT32				ui32RCCfsMaxMarginPerc;					//!< Percentage of max frame size allowed to exceed in CFS mode
	IMG_UINT32				ui32MBPerBU;							//!< MBs per BU
	IMG_UINT32				ui32SEI_AUDCount;						//!< Unit value for picture_timing SEI values, counter

	IMG_UINT32				ui32MBPerFrm;							//!< MB per frame
	IMG_UINT16				ui16BUPerFrm;							//!< BU per frame
	IMG_UINT16				ui16MBPerRow;							//!< MBs per row
	IMG_UINT16				ui16MBPerCTU;							//!< MBs per CTU

	IMG_INT16				i16InitQP;								//!< Initial QP
	IMG_INT16				i16SeInitQPI;							//!< Initial Sequence QP
	IMG_INT16				i16MinQPVal;							//!< Min QP
	IMG_INT16				i16MaxQPVal;							//!< Max QP

	IMG_UINT8				ui8SEI_AUDTimeUnits;					//!< Unit value for picture_timing SEI values
	IMG_BOOL8				bDisableFrameSkipping;					//!< Disable frame skipping
	IMG_BOOL8				bDisableStuffing;						//!< Disable bit stuffing
	IMG_BOOL8				bSceneDetectDisable;					//!< Disable scene change detection
	IMG_BOOL8				bHierarchical;							//!< Hierarchical B frames
	IMG_BOOL8				bCFSonIFrames;							//!< CFS mode

	IMG_UINT8				ui8KicksPerBU;							//!< How many HW kicks per BU

	IMG_BOOL8				bRCreset;								//!< RC full reset

	IMG_BYTE				padding[2];
} RC_PARAMS;
//STATIC_ASSERT(sizeof (struct _RC_PARAMS_) <= 64);			// Having substructures smaller than a cache miss is a plus

/*!
* @struct _INTRA_REFRESH_
* @brief Intra refresh mode related parameters
*/
struct _INTRA_REFRESH_
{
	IMG_UINT16				ui16IntraRefreshCTUsPerFrame;			//!< No of CTU Rows or Columns to force to intra each frame
	IMG_UINT16				ui16IntraRefreshCTUIncrement;			//!< No of CTU rows or columns to increment the intra region by each frame
    IMG_UINT32              ui32IntraRefreshPeriod;                 //!< Intra refresh period (if column or cyclic refresh active)
	VXE_INTRA_REFRESH_MODE	eIntraRefreshMode;						//!< Specifies Intra Refresh mode
	IMG_INT16				i16IntraRefreshQpDelta;					//!< Qp Delta to apply to intra refresh CTUs
	IMG_BOOL8				bResetIRCounter;						//!< Reset the counters related to intra refresh when the changes are applied
	IMG_BOOL8				bUseInternalSliceFrameNum;				//!< H264 POV Type 2 mode only - Signals the firmware to use an internal frame counter for the slice frame_num (this can then be reset to 0 on each GDR frame reset)
};
STATIC_ASSERT(sizeof (struct _INTRA_REFRESH_) <= 64);	// Having substructures smaller than a cache miss is a plus

typedef struct _LONG_TERM_RPS_
{
	IMG_UINT32 poc[MAX_LTR_BUFFERS];
	IMG_BOOL8 used_by_current_pic_lt_flag[MAX_LTR_BUFFERS];
	IMG_BOOL8 delta_poc_msb_present_flag[MAX_LTR_BUFFERS];
	IMG_UINT16 delta_poc_msb_cycle_lt[MAX_LTR_BUFFERS];
	IMG_UINT8 num_long_term_pics;
	IMG_BYTE padding[3];
}LONG_TERM_RPS;
STATIC_ASSERT(sizeof (struct _LONG_TERM_RPS_) <= 64);	// Having substructures smaller than a cache miss is a plus

typedef struct _IN_SLICE_RPS_
{
	// Array num_negative_pics long
	IMG_UINT8 delta_poc_s0[NUM_ELEMENTS_RPS_ARRAYS];
	IMG_UINT8 used_by_curr_pic_s0_flag[NUM_ELEMENTS_RPS_ARRAYS];

	// Array num_positive_pics long
	IMG_UINT8 delta_poc_s1[NUM_ELEMENTS_RPS_ARRAYS];
	IMG_UINT8 used_by_curr_pic_s1_flag[NUM_ELEMENTS_RPS_ARRAYS];
	IMG_UINT8 num_negative_pics;
	IMG_UINT8 num_positive_pics;
	IMG_BYTE padding[2];
} IN_SLICE_RPS;
STATIC_ASSERT(sizeof (struct _IN_SLICE_RPS_) <= 64);	// Having substructures smaller than a cache miss is a plus
/*!
* @struct _INITIAL_PARAMS_
* @brief Generic parameters needed to start a firmware context
*/
struct _INITIAL_PARAMS_
{
	IMG_UINT8				ui8FirstPipeToUse;						//!< First pipe index to be used for this context
	IMG_UINT8				ui8LastPipeToUse;						//!< Last pipe index to be used for this context
	IMG_UINT8				ui8PipesToUse;							//!< Pipe usage for this context (bit to 1 means used)
	IMG_UINT8				ui8Codec;								//!< Codec to be used for the created/activated context (no more than 255 and address the padding at the same time)
	IMG_UINT8				ui8PPSHdrCnt;							//!< Number of PPS headers to write to the stream
	IMG_UINT8				uPad1[3];

	/* Context features support */
	IMG_UINT32				ui32ContextFeatures;					//!< Which features does this context support (as flags)
	IMG_UINT16				ui16FrameWidthCTUs;						//!< The width of the frame in CTUs
	IMG_UINT16				ui16FrameHeightCTUs;					//!< The height of the frame in CTUs

	/* Intra Refresh related*/
	struct _INTRA_REFRESH_	intra_refresh_params;

	VXE_RC_MODE				eRCMode;								//!< Rate Control Mode

	IMG_BOOL8			b8VcmHwUpdatebyBU;							//!< VCMHW using BU or Frame Level Update
	IMG_UINT8			log2_max_pic_order_cnt_lsb;					//!< To tell to the FW what value to write to the SPS on log2_max_pic_order_cnt_lsb_minus4 (we substract 4 in the FW)
	IMG_BOOL8			uPad2[2];								
	IMG_UINT32			ui32VcmHwUMaxLevel;				 			//!< VCMHW maxium level

	IMG_UINT32				ui32TestingFeatures;					//!< Some additional testing features that will not be present in later releases
	IMG_UINT32				ui32HRDFlags;							//!< A set of flags informing about the actions required for parsing SEI messages
	IMG_UINT32			ui32ReferenceMemOffset;						//!< Dev Mem offset (from header memory) of reference memory
};
STATIC_ASSERT(sizeof (struct _INITIAL_PARAMS_) <= 64);	// Having substructures smaller than a cache miss is a plus

/*!
* @struct _SEQUENCE_PARAMS_
* @brief Parameter that are fixed per sequence, filled after the slice map generation
*/
struct _SEQUENCE_PARAMS_
{
	/* Fixed-by-sequence frame information */
	IMG_UINT16		ui16TilesPerFrame;
	IMG_UINT16		ui16SlicesPerFrame;
	IMG_UINT32		ui32CTUPerFrame;
	IMG_UINT16		num_bits_4_st_rps_id;
	IMG_UINT16		num_short_term_ref_pic_sets;
	/* Rate control related */
	



};
STATIC_ASSERT(sizeof (struct _SEQUENCE_PARAMS_) <= 64);	// Having substructures smaller than a cache miss is a plus

/* Firmware context structure contains only parameters setup by the driver at start of day.  */
typedef struct _VXE_CTXT_PARAMS_
{
	struct _INITIAL_PARAMS_ initial_params;
	struct _SEQUENCE_PARAMS_ fixed_per_seq;
} VXE_CTXT_PARAMS;


/* Only this file is checked for the padding */
#if defined (WIN32)
#pragma warning ( disable: 4820 )
#else
#pragma GCC diagnostic ignored "-Wpadded"
#endif


#endif /* _VXE_FW_IF_H_ */

