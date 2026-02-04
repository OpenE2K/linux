/*!
 *****************************************************************************
 *
 * @File       vxe_KM.h
 * @Title      Kernel Module code used for driving the VXE Encoder
 * @Description    This file contains the QUARTZ Kernel Mode component.
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

#ifndef _VXE_KM_H_
#define _VXE_KM_H_

/* Exposed api */
#include "vxe_km_api_quartz.h"

#include "proc_FwIF.h"

#include <sysdev_utils.h>


#if defined (IMG_KERNEL_MODULE)
/* Verbose level (0: only PRINT, 1: PRINT and DEBUG_PRINT, 2: PRINT, DEBUG_PRINT and DEBUG_VERBOSE_PRINT*/
#if defined (DEBUG)
#define KM_VERBOSE_LEVEL (1)
#else
#define KM_VERBOSE_LEVEL (0)
#endif

#define PRINT printk
#define SPRINT sprintf

/* Verbose level 1 */
#if KM_VERBOSE_LEVEL > 0
#define DEBUG_PRINT PRINT
#else
#define DEBUG_PRINT(...)
#endif
/* Verbose level 2 */
#if KM_VERBOSE_LEVEL > 1
#define DEBUG_VERBOSE_PRINT PRINT
#else
#define DEBUG_VERBOSE_PRINT(...)
#endif

#define FPRINT(a, ...) printk(__VA_ARGS__)
#define FCLOSE(a)

#include <linux/kthread.h>
#include <linux/delay.h>

#else /*defined (IMG_KERNEL_MODULE)*/
#define PRINT printf
#define SPRINT sprintf

#include <stdarg.h>
static void debug_print(char *fmt, ...)
{
	if (!gbDebugOutputHidden)	// it is the only reason we would hide this
	{
		// Just send to stdout for now with default colours
		va_list myargs;
		va_start(myargs, fmt);

		vprintf(fmt, myargs);
		// OR vsprintf + COMM_PdumpComment

		va_end(myargs);
	}
}
#define DEBUG_PRINT debug_print
#define DEBUG_VERBOSE_PRINT DEBUG_PRINT
#define FPRINT(...) fprintf(__VA_ARGS__)
#define FCLOSE fclose
#endif /*defined (IMG_KERNEL_MODULE)*/


/* Not all features in the stream flag are relevant for the simplified device version */
#define DEVICE_LEVEL_FEATURES			(MASK_VXEKMAPI_ENCDIM_FEATURE | MASK_VXEKMAPI_ENCRES_FEATURE | MASK_VXEKMAPI_HWINPUT_FEATURE | MASK_VXEKMAPI_COLUMN_STORE_ON | MASK_VXEKMAPI_FBC_FEATURE)


/* Enable the debugging features at a global level (so we can turn everything off at once) */
#define INCLUDE_DEBUG_FEATURES (1)

#if defined (INCLUDE_DEBUG_FEATURES)
/* Debug fs may not be present in kernel build */
#if defined (CONFIG_DEBUG_FS)
#define DEBUG_FS_SUPPORT (1)
#endif

/* Some debugging features are kernel module only */
#if defined (IMG_KERNEL_MODULE)
/* Page table walk and register dump */
//#define DEBUG_REG_OUTPUT
#endif /*defined (IMG_KERNEL_MODULE)*/
#endif /*defined (INCLUDE_DEBUG_FEATURES)*/

//#define OUTPUT_COMM_STATS
#if defined (OUTPUT_COMM_STATS)
/* The extended information cannot come without #OUTPUT_COMM_STATS */
//#define OUTPUT_COMM_STATS_EXTENDED
#endif


#if ! defined (SYSBRG_NO_BRIDGING)
#define TALPDUMP_VerboseComment(hBank, pszComment) /*don't overload the out2.txt*/
#if defined (TALPDUMP_Comment)
#undef TALPDUMP_Comment
#endif
#define TALPDUMP_Comment(hBank, pszComment) /*make sure we remove all of them*/
#if defined (TALPDUMP_ConsoleMessage)
#undef TALPDUMP_ConsoleMessage
#endif
#define TALPDUMP_ConsoleMessage(hBank, pszMsg) /*strip them out*/

/* If not given, we provide default values */
#if ! defined (VXE_KM_DEFAULT_PPM)
#define VXE_KM_DEFAULT_PPM (0)
#endif
#if ! defined (VXE_KM_DEFAULT_MMU_FLAGS)
#define VXE_KM_DEFAULT_MMU_FLAGS (0x00000001/*use_mmu_flag*/ | 0x00000002/*tiled_flag*/ | 0x00000004 /* 40 bit physical addressing */)
#endif
#if ! defined (VXE_KM_DEFAULT_SCHED_MODEL)
#define VXE_KM_DEFAULT_SCHED_MODEL (e_NO_SCHEDULING_SCENARIO)
#endif
#endif /*! defined (SYSBRG_NO_BRIDGING)*/


/****************************************************** DEFINES ************************************************************/

/* Maximum number of usable sockets for the KM <=> FW communication */
#define VXE_MAX_SOCKETS (FW_TOTAL_CONTEXT_SUPPORT)
/* We allow the socket objects (in the kernel) to queue up to 32 commands if the HW cannot handle them */
#define VXE_KM_COMMAND_BUFFER_SIZE (32)
/* Each command is composed of four words */
#define VXE_KM_COMMAND_BUFFER_WIDTH (4)
/* The maximum number of encode command we want to issue to the firmware */
#define VXE_KM_MAX_ENCODE_ISSUED (4)
/* A default balanced round-robin scheduling */
#define VXE_KM_DEFAULT_SCHED_THRESHOLD (2)
/* Unusable value for the indirection "context idx in model" <=> "socket idx" */
#define VXE_KM_SCHEDULING_ORDER_DEFAULT (0xbaadf00d)

/**
* \defgroup stream_events Bit-mask of kernel stream object events
* @{
*/
#define VXE_KM_STREAM_EVENTS_IRREGULAR_ABORT            (0x00000001) /*!< The stream is aborted because of an erroneous condition, it is a kernel decision */
#define VXE_KM_STREAM_EVENTS_CLEANUP_ABORT_SENT         (0x00000002) /*!< Abort command comes from cleaned code path, user mode process has probably been killed */
#define VXE_KM_STREAM_EVENTS_CLEANUP_ABORT_SEEN         (0x00000004) /*!< ISR acknowledged the cleanup abort */
#define VXE_KM_STREAM_EVENTS_FENCE_END_ABORT            (0x00000008) /*!< Fence sent at the end of the abort has completed */
#define VXE_KM_STREAM_EVENTS_FEEDBACK_LOST              (0x00000010) /*!< ISR could not queue the feedback because the stream's FIFO was full */
#define VXE_KM_STREAM_EVENTS_NORM_ABORT_HIGH            (0x00000020) /*!< User-space (or device de-init cleanup) has requested an abort of the current stream (NORM stands for normal, expected) */
#define VXE_KM_STREAM_EVENTS_DEACTIVATE_SENT            (0x00000040) /*!< A Deactivate command has been sent to the firmware so no other commands can be sent for this context (until an activate) */
/** @}*/

/****************************************************** TYPEDEF ************************************************************/

typedef enum _VXE_KM_POWER_STATE_
{
	e_HW_ACTIVE = 0,		/*!< HW fully functional */
	e_HW_LOW_POWER,			/*!< HW ready to be turned off */
	e_HW_ALREADY_OFF,		/*!< HW does not need to be turned back on since no streams are active */
	e_HW_IDLE				/*!< HW completely off */
} VXE_KM_POWER_STATE;


/**
* \struct _VXE_KM_SCHED_PARAMS_ Specifies required parameters to implement a scheduling model
* \typedef VXE_KM_SCHED_PARAMS Specifies required parameters to implement a scheduling model
* \brief A set of parameter which are enough to define how the kernel scheduling model should behave
**/
typedef struct _VXE_KM_SCHED_PARAMS_
{
	IMG_VOID				*pvAllocation;				/*!< Keep a reference on the allocation so we don't leak it */
	IMG_UINT32				*pui32CtxFeatures;			/*!< What is supported by each context of this model (actually is a IMG_UINT32[ui32NumberOfContexts] but this needs to be dynamically allocated) */
	IMG_UINT32				*pui32SchedulingOrder;		/*!< How the contexts should be selected */
	IMG_UINT32				*pui32SchedulingOrderToFWCtxtId;		/*!< Array values will match Socket->ui8FWCtxtId that match the given the schedule order number as the array index  pui32SchedulingOrderToFWCtxtId[sched order number] = Socket->ui8FWCtxtId */
	IMG_UINT32				*pui32RoundRobinWeight;		/*!< Which round robin should be apply at the device context level */

	IMG_UINT8				*pui8FirstPipeIdx;			/*!< All first pipe index (ui32NumberOfContexts entries) */
	IMG_UINT8				*pui8LastPipeIdx;			/*!< All last pipe index (ui32NumberOfContexts entries) */
	IMG_UINT8				*pui8RoundRobinThresh;		/*!< All round robin threshold (ui32NumberOfContexts entries) */
	IMG_BOOL8				*pb8ContextAllocated;		/*!< When a context features' flag is matching, an '1' entry will be added */

	VXE_KM_SCHEDULING_MODEL	eSchedModel;				/*!< Are we expecting a defined set of contexts? */
	IMG_UINT32				ui32NumberOfContexts;		/*!< How many contexts are included in the model */
	IMG_UINT32				ui32NumberOfPipes;			/*!< This model will need a specific number of pipes to work correctly */

	IMG_UINT16				ui16ScheduleMax;
	IMG_UINT16				ui16ScheduleIdx;
} VXE_KM_SCHED_PARAMS;


/**
* \struct _PAIR_ENC_CMD_STATE_ Keep track whether the encode command (identified by its id) has been seen by stream object
* \typedef PAIR_ENC_CMD_STATE Keep track whether the encode command (identified by its id) has been seen by stream object
**/
typedef struct _PAIR_ENC_CMD_STATE_
{
	IMG_BOOL bFrameReadyForProvision;			/*!< When using direct input, we need to know when the firmware is ready to consume the data and inform upper layer that pixel provision is required */
	IMG_BOOL bEncodeHasBeenSeen;				/*!< The command has been acknowledged by the firmware */
	IMG_UINT32 ui32UniqueCmdId;					/*!< Unique encode command identifier */
} PAIR_ENC_CMD_STATE;


#if defined (POLL_FOR_INTERRUPT)
struct _VXE_KM_DEVCONTEXT_;
/**
* \struct _VXE_KM_ISR_CONTROL_ Polling ISR thread control structure
* \typdef VXE_KM_ISR_CONTROL Polling ISR thread control structure
* \brief Structure controling the state of the ISR thread, when interrupts are polled
**/
typedef struct _VXE_KM_LISR_CONTROL_
{
	struct _VXE_KM_DEVCONTEXT_*		psKMDevContext;	//!< ISR poller requires the device context
	IMG_BOOL						bSignalHISR;	//!< If the HISR has been de-initialised, we should not try to signal it
	IMG_BOOL						bExit;			//!< Should the ISR polling thread shutdown ?
} VXE_KM_LISR_CONTROL;
#endif


/**
* \struct _PENDING_ABORT_ Holds enough information to abort a stream and handles subsequent commands
* \typedef PENDING_ABORT Holds enough information to abort a stream and handles subsequent commands
**/
typedef struct _PENDING_ABORT_
{
	IMG_UINT32 ui32Command1stWord;		/*!< see #km_SendCommandToFW::eCommand */
	IMG_UINT32 ui32Command2ndWord;		/*!< see #km_SendCommandToFW::ui32DevMemBlock */
	IMG_UINT32 ui32Command3rdWord;		/*!< see #km_SendCommandToFW::ui32CommandData */
	IMG_UINT32 ui32UniqueCmdId;			/*!< Command fourth word */
	IMG_BOOL bAbortSent;				/*!< Abort command has been sent to the firmware */
	IMG_BOOL bAbortPending;				/*!< Only one abort needs to be sent to the firmware */
} PENDING_ABORT;


typedef struct _MMU_REG_CONFIG_
{
	IMG_UINT32 DIR_BASE_ADDR0;
	IMG_UINT32 ADDRESS_CONTROL;
	IMG_UINT32 MMU_CONTROL0;
	IMG_UINT32 TILE_CFG0;
	IMG_UINT32 TILE_MAX_ADDR0;
	IMG_UINT32 TILE_MIN_ADDR0;
}MMU_REG_CONFIG;

/**
* \struct _VXE_KM_DEVICE_SPECIFIC_INFO_ Device specific set of information
* \typedef VXE_KM_DEVICE_SPECIFIC_INFO Device specific set of information
* \brief Self-contained set of information required to use an instance of a device
* \details Some may be a copy of a global setting but some are different accross all devices
**/
typedef struct _VXE_KM_DEVICE_SPECIFIC_INFO_
{
	// Multicore context identifier
	IMG_UINT32 ui32CoreDevIdx;				/*!< Device index in #as_quartz_device*/

	IMG_UINT32 ui32SupportedFeaturesFlag;	/*!< Simplified version of what the device supports*/

	// Specific register values
	VXE_HW_CONFIG sHWConfig;

	IMG_UINT32 ui32NumberOfPipes;

	// Register banks
	IMG_HANDLE hQuartzMultipipeBank;
	IMG_HANDLE hQuartzMMUBank;
	IMG_HANDLE hQuartzDMACBank;
	IMG_HANDLE hQuartzLTPBank;
	IMG_HANDLE hSysMemId;
	IMG_HANDLE hLTPDataRam;
	IMG_HANDLE hLTPCodeRam;
	
	// MMU related
	IMG_HANDLE hMMUTemplate;
	struct Quartz_CoreMMUContext hQuartz_CoreMMUContext;				/*!< Handle used internally by MMU layer */
	TALMMU_sHeapInfo asMMU_HeapInfo[HEAP_ID_NO_OF_HEAPS];				/*!< Describes the memory heap layout */
	TALMMU_sDevMemInfo	sMMU_DeviceMemoryInfo;							/*!< Describes the device memory model */
	IMG_HANDLE g_hMemmgrMutex;
#if SECURE_MMU
	MMU_REG_CONFIG sMMURegConfig;
#endif
	// Parameters
	IMG_UINT32 ui32MMUFlags;
	IMG_BOOL bUseTiledMemory;
	IMG_BOOL bUseInterleavedTiling;
	IMG_BOOL bUseAlternateTiling;
	IMG_BOOL bUseExtendedAddressing;
	IMG_UINT32 ui32MMUTileStride;
	IMG_BOOL bUseSecureFwUpload;
	IMG_BOOL bKMPPM;

#if defined (POLL_FOR_INTERRUPT)
	// Control structure required for #POLL_FOR_INTERRUPT mode
	VXE_KM_LISR_CONTROL g_sLISRControl;
#if defined(IMG_KERNEL_MODULE)
	struct task_struct *KM_LISRThreadHandle;
#else
	IMG_HANDLE KM_LISRThreadHandle;
#endif /*defined(IMG_KERNEL_MODULE)*/
#endif /*defined (POLL_FOR_INTERRUPT)*/
} VXE_KM_DEVICE_SPECIFIC_INFO;


/**
* \typdef VXE_KM_COMM_SOCKET FW context representation used in the KM layer
**/
typedef struct _VXE_KM_COMM_SOCKET_ VXE_KM_COMM_SOCKET;

/**
* \struct _VXE_KM_DEVCONTEXT_ Device context used in the KM layer
* \typdef VXE_KM_DEVCONTEXT Device context used in the KM layer
* \brief A per device data (hardware occurence) held by kernel module
**/
typedef struct _VXE_KM_DEVCONTEXT_
{
	IMG_CHAR *				pszDeviceName;			/*!< Device name. */
	SYSDEVU_sInfo *			hSysDevHandle;			/*!< SYSDEVKM device handle */
	IMG_HANDLE				hResBHandle;			/*!< Resource bucket handle */
	IMG_HANDLE				hDMANDevHandle;			/*!< DMANKM device context handle */
	IMG_UINT32				ui32ConnId;				/*!< Hold the unique connection id inside the structure so we can expose it when required */
	IMG_UINT32				bInitialised;			/*!< Indicates that the device driver has been initialised */
	IMG_UINT32				ui32LastCmdID;			/*!< Unique last command id that the kernel sent to the firmware */
	IMG_UINT32				ui32LastLowPowerCmdId;	/*!< When doing APM, point in time where the last DEACTIVATE_COMMAND has been issued */
	IMG_UINT32				ui32UsedSockets;		/*!< Number of openned socket (in use) */
	VXE_KM_COMM_SOCKET		*apsDeviceSockets[VXE_MAX_SOCKETS];
	VXE_KM_FW_SOFT_IMAGE	sFWSoftImage;			/*!< Software representation of the firmware (as a whole structure to be usable directly) */

	IMG_HANDLE				hCommTxLock;			/*!< Mutex protecting access to the active flag: ioctl send() call reactivate a stream (workqueue does same), seeing a deactivate feedback deactivates */
	IMG_HANDLE				hCommAccessStreamsLock;	/*!< Mutex protecting access to apsDeviceSockets[]: ioctl open() call adds one entries, workqueue read entries */
	IMG_HANDLE				hCheckAndScheduleLock;	/*!< Mutex protecting against both HISR and user-mode calling KM_CheckAndSchedule() at the same time*/
	IMG_BOOL				bSuspendHISR;			/*!< Suspend the workqueue when doing Active Power Management */
	VXE_KM_POWER_STATE		eLowPowerState;			/*!< Current state of the hardware (might be off when doing power management) */
	IMG_UINT32				ui32IdleSockets;		/*!< When doing active power management, we place sockets in idle state one after another until all of them are idle */
	IMG_UINT32				ui32IdleSocketsFlag;	/*!< Together with the count of idle sockets, we keep track on which socket index is inactive */
	IMG_BOOL				bMMUFaultSeen;			/*!< Keep track about eventual page fault hapening in the system */
	IMG_BOOL				bMMUFaultToSignal;		/*!< Keep track about eventual page fault hapening in the system */
	IMG_BOOL				bCoreNeedsToClose;		/*!< Once we have had a page fault the device needs to be restarted */
	IMG_UINT32				ui32MMUFaultReg0;		/*!< Last value for the MMU fault status reg (in case of fault) */
	IMG_UINT32				ui32MMUFaultReg1;		/*!< Last value for the MMU fault status reg (in case of fault) */
	IMG_BOOL				bCommandsWaiting;		/*!< Indicates whether the HW Fifo was full last time a CheckAndSchedule tried to add a command */

	IMG_UINT32	aui32RoundRobinWeights[VXE_MAX_SOCKETS];		/*!< Weights used for round-robin scheduling */
	IMG_UINT16	aui16PipesAllocation[QUARTZ_MAX_PIPES];			/*!< Whenever a pipe is given to a context, this is updated to reflect its occupancy (aiming to balance the work distribution evenly) */

	VXE_KM_SCHED_PARAMS				sSchedModel;	/*!< Substruct used for scheduling model representation */

	VXE_KM_DEVICE_SPECIFIC_INFO		sDevSpecs;		/*!< Device specific information (lowest layer of the kernel module) */

#if defined (USE_FW_TRACE)
	IMG_HANDLE				hFwTraceBuffer;
	IMG_UINT32				ui32FwTraceSize;
#endif

} VXE_KM_DEVCONTEXT;

/**
* \typdef VXE_KM_CONNDATA Data used for the connection
* \brief Data required by the KM to handle communication with the FW (RMAN bucket handle for instance)
**/
typedef struct _VXE_KM_CONNDATA_
{
	IMG_HANDLE				hResBHandle; /*!< Resource bucket handle */
} VXE_KM_CONNDATA;

/**
* \struct _VXE_KM_COMM_SOCKET_ FW context representation used in the KM layer
* \brief A per context data (also named stream, FW supports a defined number of it) help by kernel component 
**/
struct _VXE_KM_COMM_SOCKET_
{
	IMG_HANDLE			hFWMessageAvailable_Sem;	//!< When some feedback came back from the firmware, this is signalled
	VXE_KM_DEVCONTEXT	*psDevContext;				//!< Reference on the parent device context
	VXE_KM_CONNDATA		*psConnData;				//!< Reference on the connection resource data (see #VXE_KM_CONNDATA)
	IMG_HANDLE			hResBHandle;				//!< Handle on the resource bucket

	PENDING_ABORT		sPendingAbort;				//!< When a stream is aborted, this structure is used to handle the other pending commands gracefully

	IMG_UINT8			ui8FWCtxtId;				//!< Firmware Context Index
	IMG_BOOL8			b8StreamAborted;			//!< The stream has been aborted and resource cannot be free'd before abort came back (only when #IMG_KERNEL_MODULE# is defined)
	IMG_UINT8			ui8RoundRobinThresh;		//!< Used by the KM scheduler, if the 'weight' of this socket goes over this value, it will be reset to zero (aim to prevent starvation by infinite incrementation)
	IMG_BOOL8			b8StreamWaiting;			//!< Feedback may come back for this stream
	IMG_BOOL			bStreamIdle;				//!< The stream does not issue incoming commands and is just waiting for feedback
	IMG_BOOL			bStreamShutdown;			//!< The stream has seen the final deactivation and is planning to shutdown completely

	IMG_UINT32			ui32CmdSent;				//!< When #POLL_FOR_INTERRUPT is on, used to delay the feedback explicit waiting to guarantee single threaded serialization (issued command)
	IMG_UINT32			ui32AckRecv;				//!< When #POLL_FOR_INTERRUPT is on, used to delay the feedback explicit waiting to guarantee single threaded serialization (seen feedback)

	IMG_UINT32 			ui32EncCmdCount;			//!< Total number of encode command that have been sent
	IMG_UINT32			ui32ContextMemory;			//!< Firmware context memory (used on power transitions)
	VXE_CODEC			eCodec;						//!< Codec used for this socket

	// Buffer between the ISR and the UM holding feedback
	IMG_UINT32			aui32OutgoingFIFO [FEEDBACK_FIFO_MAX_COMMANDS * FEEDBACK_FIFO_WORD_PER_COMMANDS];
	IMG_UINT8			ui8OutgoingFIFOConsumer;	//!< The UM level feedback thread will consume messages from here
	IMG_UINT8			ui8OutgoingFIFOProducer;	//!< The KM level feedback (LISR) will queue messages in here
	// Incomming command UM => KM are queued here in case the HW cannot accept them or two encodes have already been sent to the FW context
	IMG_UINT8			ui8CmdQueueProducer;		//!< Next command to be queued from UM to KM
	IMG_UINT8			ui8CmdQueueConsumer;		//!< Next command to be dequeued from KM to HW FIFO
	IMG_UINT32			aui32KernelCmdQueue [VXE_KM_COMMAND_BUFFER_SIZE * VXE_KM_COMMAND_BUFFER_WIDTH];

	IMG_UINT32			ui32PrevHeaderNodeInfo;
	IMG_UINT32			ui32PrevNodeCnt;
	IMG_UINT32			ui32CurCodedList;
	IMG_UINT32			ui32CurCmdId;
#ifndef REMOVE_LL_COUNTERS
	IMG_UINT32			ui32LowLatencyMsgsSentFromKM;
	IMG_UINT32			ui32LowLatencyMsgsReceivedAndSentToAPI;
#endif

	IMG_UINT16			ui16CtxIdxInSchedModel;		//!< Keeps track of the index in psDevContext->sSchedModel->pb8ContextAllocated so it will be cleared when the socket is closed

	IMG_UINT32			ui32ResourceId;				//!< Unique resource (=socket) identifier
	IMG_UINT32			ui32FeaturesFlag;			//!< Reduced set of features for this socket driving its priority over other context in term of pipe allocation and scheduling time/order

	PAIR_ENC_CMD_STATE	asEncCmdHistory[VXE_KM_MAX_ENCODE_ISSUED];
	IMG_UINT8			ui8EncCmdHistoryProd;
	IMG_UINT8			ui8EncCmdHistoryCons;

	IMG_UINT8			ui8FirstPipeIdx;			//!< First pipe allocated to this context
	IMG_UINT8			ui8LastPipeIdx;				//!< Last pipe allocated to this context

	IMG_UINT32			ui32StreamStateFlags;		//!< A bit mask of event which happened for this stream
};


/****************************************************** GLOBALS ************************************************************/


/************************************************* PUBLIC FUNCTIONS ********************************************************/

/**
* \fn QUARTZ_KM_RequestPipes
* \brief Query the kernel module to know which pipe(s) a context may use
* \params [in] psSocket Reference on socket, connected to a target device from which we will get the pipes
* \params [in] ui8Ideal UM requested that many pipes
* \params [out] pui8FirstPipe First pipe index to use
* \params [out] pui8LastPipe Last pipe index to use
* \return The number of pipes KM gave to this UM context
**/
IMG_UINT8 QUARTZ_KM_RequestPipes(VXE_KM_COMM_SOCKET *psSocket, IMG_UINT8 ui8Ideal, IMG_UINT8 *pui8FirstPipe, IMG_UINT8 *pui8LastPipe);


/**
* \fn QUARTZ_KM_GetNumberOfPipes
* \brief Access the register holding the number of pipe that the hardware supports
* \param psDevContext Device we want to read register from
* \return The number of pipes read from the multipipe registers bank
**/
IMG_UINT32 QUARTZ_KM_GetNumberOfPipes(VXE_KM_DEVCONTEXT *psDevContext);


/**
* \fn KM_WaitForDeviceIdle
* \brief Wait for a device to have nothing left to do
* \param psDevContext Device to be checked
* \return IMG_TRUE if the device could successfully reach its idle state in time, IMG_FALSE otherwise
**/
IMG_BOOL KM_WaitForDeviceIdle(VXE_KM_DEVCONTEXT* psDevContext);

/**
* \fn km_AbortAllContexts
* \brief 
* \param psDevContext Device  
**/
IMG_VOID km_AbortAllContexts(VXE_KM_DEVCONTEXT* psDevContext);

/********************************************* QUARTZ SPECIFIC FUNCTIONS ***************************************************/

#if defined (INCLUDE_DEBUG_FEATURES)
extern void DBG_dump_reg_and_page(void *pvDevContext);
extern void DBG_dump_reg(void *pvDevContext);

extern int create_debugfs_vxekm(void);
extern void destroy_debugfs_vxekm(void);
extern void debugfs_write_last_feedback(unsigned dev_id, unsigned fb_1, unsigned fb_2);
extern void debugfs_write_last_cmd(unsigned dev_id, unsigned w1, unsigned w2, unsigned w3, unsigned w4);
extern int debugfs_link_context_to_debugfs(VXE_KM_DEVCONTEXT *psContext);
extern int debugfs_unlink_context_to_debugfs(VXE_KM_DEVCONTEXT *psContext);
#endif /*defined (INCLUDE_DEBUG_FEATURES)*/

#if defined (OUTPUT_COMM_STATS)
extern void Output_COMM_Stats_To_File(VXE_KM_COMM_SOCKET *psSocket, unsigned char *ucLabel, IMG_INT id, unsigned char *FileName);
extern void Output_COMM_Stats_Line_To_File(unsigned char *ucLabel, IMG_UINT32 ui32FirstWord, IMG_UINT32 ui32SecondWord, const char *FileName, IMG_UINT32 ui32HwFifoConsumer);
extern void Output_COMM_General_Line(unsigned char *ucLabel, const char *FileName);
extern void Output_COMM_Stats_Msg_To_File(VXE_KM_COMM_SOCKET *psSocket, unsigned char *ucLabel, IMG_UINT32 ui32CmdInfo, IMG_UINT32 ui32CmdData, IMG_UINT32 ui32WBValue, const char *FileName);
#endif

#endif
