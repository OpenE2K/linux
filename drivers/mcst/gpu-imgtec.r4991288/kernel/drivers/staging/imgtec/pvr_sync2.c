/* -*- mode: c; indent-tabs-mode: t; c-basic-offset: 8; tab-width: 8 -*- */
/* vi: set ts=8 sw=8 sts=8: */
/*************************************************************************/ /*!
@File           pvr_sync.c
@Title          Kernel driver for Android's sync mechanism
@Codingstyle    LinuxKernel
@Copyright      Copyright (c) Imagination Technologies Ltd. All Rights Reserved
@License        Dual MIT/GPLv2

The contents of this file are subject to the MIT license as set out below.

Permission is hereby granted, free of charge, to any person obtaining a copy
of this software and associated documentation files (the "Software"), to deal
in the Software without restriction, including without limitation the rights
to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
copies of the Software, and to permit persons to whom the Software is
furnished to do so, subject to the following conditions:

The above copyright notice and this permission notice shall be included in
all copies or substantial portions of the Software.

Alternatively, the contents of this file may be used under the terms of
the GNU General Public License Version 2 ("GPL") in which case the provisions
of GPL are applicable instead of those above.

If you wish to allow use of your version of this file only under the terms of
GPL, and not to allow others to use your version of this file under the terms
of the MIT license, indicate your decision by deleting the provisions above
and replace them with the notice and other provisions required by GPL as set
out in the file called "GPL-COPYING" included in this distribution. If you do
not delete the provisions above, a recipient may use your version of this file
under the terms of either the MIT license or GPL.

This License is also included in this distribution in the file called
"MIT-COPYING".

EXCEPT AS OTHERWISE STATED IN A NEGOTIATED AGREEMENT: (A) THE SOFTWARE IS
PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR IMPLIED, INCLUDING
BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY, FITNESS FOR A PARTICULAR
PURPOSE AND NONINFRINGEMENT; AND (B) IN NO EVENT SHALL THE AUTHORS OR
COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY, WHETHER
IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM, OUT OF OR IN
CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE SOFTWARE.
*/ /**************************************************************************/

/* General TODO:
 * - check if OSAcquireBridgeLock/OSReleaseridgeLock is still necessary?
 * - can the deferred freeing made simpler now?
 * - remove pool (after timeline moved to DevVars)? */

#include "pvr_sync.h"
#include "pvr_fd_sync_kernel.h"
#include "services_kernel_client.h"
#include "pvrsrv_sync_km.h"
#include "sync_checkpoint_external.h"

#include <linux/slab.h>
#include <linux/file.h>
#include <linux/module.h>
#include <linux/uaccess.h>
#include <linux/version.h>
#include <linux/syscalls.h>
#include <linux/miscdevice.h>
#include <linux/anon_inodes.h>

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 10, 0))
#include <linux/sync.h>
#ifndef CONFIG_SW_SYNC_USER
#include <linux/sw_sync.h>
#endif
#else
#include <../drivers/staging/android/sync.h>
#ifndef CONFIG_SW_SYNC_USER
#include <../drivers/staging/android/sw_sync.h>
#endif
#endif

#include "kernel_compatibility.h"

#if (LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0))

static inline struct sync_timeline *sync_pt_parent(struct sync_pt *pt)
{
	return pt->parent;
}

static inline int sync_pt_get_status(struct sync_pt *pt)
{
	return pt->status;
}

#define for_each_sync_pt(s, f, c) \
	list_for_each_entry((s), &(f)->pt_list_head, pt_list)

#else /* (LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)) */

static inline int sync_pt_get_status(struct sync_pt *pt)
{
	/* No error state for raw dma-buf fences */
	return fence_is_signaled(&pt->base) ? 1 : 0;
}

#define for_each_sync_pt(s, f, c) \
	for ((c) = 0, (s) = (f)->num_fences == 0 ? \
		NULL : (struct sync_pt *)(f)->cbs[0].sync_pt; \
	     (c) < (f)->num_fences; \
	     (c)++,   (s) = (c) < (f)->num_fences ? \
		(struct sync_pt *)(f)->cbs[c].sync_pt : NULL)

#endif /* (LINUX_VERSION_CODE < KERNEL_VERSION(3, 17, 0)) */

/* #define DEBUG_OUTPUT 1 */

#ifdef DEBUG_OUTPUT
#define DPF(fmt, ...) pr_err("pvr_sync2: " fmt "\n", __VA_ARGS__)
#else
#define DPF(fmt, ...) do {} while (0)
#endif

#define PVR_DUMPDEBUG_LOG(pfnDumpDebugPrintf, pvDumpDebugFile, fmt, ...) \
	do { \
		if (pfnDumpDebugPrintf) { \
			pfnDumpDebugPrintf(pvDumpDebugFile, fmt, __VA_ARGS__); \
		} else { \
			pr_info("pvr_sync2: " fmt, __VA_ARGS__); \
		} \
	} while (0)

#define SYNC_MAX_POOL_SIZE 10

enum {
	SYNC_TL_TYPE = 0,
	SYNC_PT_FENCE_TYPE = 1,
	SYNC_PT_CLEANUP_TYPE = 2,
	SYNC_PT_FOREIGN_FENCE_TYPE = 3,
	SYNC_PT_FOREIGN_CLEANUP_TYPE = 4,
};

struct pvr_sync_append_data {
	u32					nr_updates;
	struct _RGXFWIF_DEV_VIRTADDR_		*update_ufo_addresses;
	u32					*update_values;
	u32					nr_checks;
	struct _RGXFWIF_DEV_VIRTADDR_		*check_ufo_addresses;
	u32					*check_values;

	/* The cleanup list is needed for rollback (as that's the only op
	 * taken).
	 */
	u32					nr_cleanup_syncs;
	struct pvr_sync_native_sync_prim	**cleanup_syncs;

	/* A FD is reserved in append_fences, but is not associated with
	 * the update fence until pvr_sync_get_update_fd().
	 */
	int					update_fence_fd;

	/* Keep the sync points around for fput and if rollback is needed */
	struct sync_fence			*update_fence;
	struct pvr_sync_native_sync_checkpoint	*update_sync;
	struct pvr_sync_native_sync_prim	*update_timeline_sync;
	struct sync_fence			*check_fence;
};

/* Services client sync prim wrapper. This is used to hold debug information
 * and make it possible to cache unused syncs.
 */
/* TODO: this needs to go */
struct pvr_sync_native_sync_prim {
	/* List for the sync pool support. */
	struct list_head list;

	/* Base services sync prim structure */
	struct PVRSRV_CLIENT_SYNC_PRIM *client_sync;

	/* The next queued value which should be used */
	u32 next_value;

	/* Every sync data will get some unique id */
	u32 id;

	/* FWAddr used by the client sync */
	u32 vaddr;

	/* The type this sync is used for in our driver. Used in
	 * pvr_sync_debug_request().
	 */
	u8 type;

	/* A debug class name also printed in pvr_sync_debug_request(). */
	char class[32];
};

struct pvr_sync_native_sync_checkpoint {
	/* List for the sync pool support. */
	struct list_head list;

	/* Base services sync checkpoint */
	PSYNC_CHECKPOINT client_sync_checkpoint;

	/* Every sync data will get some unique id */
	u32 id;

	/* FWAddr used by the client sync */
	u32 vaddr;

	/* The type this sync is used for in our driver. Used in
	 * pvr_sync_debug_request().
	 */
	u8 type;

	/* A debug class name also printed in pvr_sync_debug_request(). */
	char class[32];
};

/* This is the actual timeline metadata. We might keep this around after the
 * base sync driver has destroyed the pvr_sync_timeline_wrapper object.
 */
struct pvr_sync_timeline {
	/* Back reference to the sync_timeline. Not always valid */
	struct sync_timeline *obj;

	/* Global timeline list support */
	struct list_head list;

	/* Timeline sync */
	struct pvr_sync_timeline_kernel_pair *kernel;

	/* Reference count for this object */
	struct kref kref;

	/* Used only by pvr_sync_update_all_timelines(). False if the timeline
	 * has been detected as racing with pvr_sync_destroy_timeline().
	 */
	bool valid;
};

/* This is the IMG extension of a sync_timeline */
struct pvr_sync_timeline_wrapper {
	/* Original timeline struct. Needs to come first. */
	struct sync_timeline obj;

	/* Pointer to extra timeline data. Separated life-cycle. */
	struct pvr_sync_timeline *timeline;
};

struct pvr_sync_timeline_kernel_pair {
	/* Binary sync point representing the android native sync in hw. */
	struct pvr_sync_native_sync_prim *fence_sync;

	/* Sync points can go away when there are deferred hardware operations
	 * still outstanding. We must not free the SERVER_SYNC_PRIMITIVE until
	 * the hardware is finished, so we add it to a defer list which is
	 * processed periodically ("defer-free").
	 *
	 * Note that the defer-free list is global, not per-timeline.
	 */
	struct list_head list;
};

struct pvr_sync_kernel_pair {
	/* Binary sync point representing the android native sync in hw. */
	struct pvr_sync_native_sync_checkpoint *fence_sync;

#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
	/* Cleanup sync structure. If the base sync prim is used for "checking"
	 * only within a GL stream, there is no way of knowing when this has
	 * happened. So use a second sync prim which just gets updated and
	 * check the update count when freeing this struct.
	 */
	struct pvr_sync_native_sync_prim *cleanup_sync;
#endif
	/* Sync points can go away when there are deferred hardware operations
	 * still outstanding. We must not free the SERVER_SYNC_PRIMITIVE until
	 * the hardware is finished, so we add it to a defer list which is
	 * processed periodically ("defer-free").
	 *
	 * Note that the defer-free list is global, not per-timeline.
	 */
	struct list_head list;
};

struct pvr_sync_data {
	/* Every sync point has a services sync object. This object is used
	 * by the hardware to enforce ordering -- it is attached as a source
	 * dependency to various commands.
	 */
	struct pvr_sync_kernel_pair *kernel;

	/* The timeline update value for this sync point. */
	u32 timeline_update_value;

	/* This refcount is incremented at create and dup time, and decremented
	 * at free time. It ensures the object doesn't start the defer-free
	 * process until it is no longer referenced.
	 */
	struct kref kref;
};

/* This is the IMG extension of a sync_pt */
struct pvr_sync_pt {
	/* Original sync_pt structure. Needs to come first. */
	struct sync_pt pt;

	/* Private shared data */
	struct pvr_sync_data *sync_data;

	/* The timeline on which this pvr_sync_pt was created */
	struct pvr_sync_timeline *timeline;
};

/* This is the IMG extension of a sync_fence */
struct pvr_sync_fence {
	/* Original sync_fence structure. Needs to come first. */
	struct sync_fence *fence;

	/* To ensure callbacks are always received for fences / sync_pts, even
	 * after the fence has been 'put' (freed), we must take a reference to
	 * the fence. We still need to 'put' the fence ourselves, but this might
	 * happen in irq context, where fput() is not allowed (in kernels <3.6).
	 * We must add the fence to a list which is processed in WQ context.
	 */
	struct list_head list;
};

/* Any sync point from a foreign (non-PVR) timeline needs to have a "shadow"
 * sync prim. This is modelled as a software operation. The foreign driver
 * completes the operation by calling a callback we registered with it.
 */
struct pvr_sync_fence_waiter {
	/* Base sync driver waiter structure */
	struct sync_fence_waiter waiter;

	/* "Shadow" sync prim backing the foreign driver's sync_pt */
	struct pvr_sync_kernel_pair *kernel;

	/* Optimizes lookup of fence for defer-put operation */
	struct pvr_sync_fence *sync_fence;
};

/* Global data for the sync driver */
static struct {
	/* Complete notify handle */
	void *command_complete_handle;

	/* Defer-free workqueue. Syncs may still be in use by the HW when freed,
	 * so we have to keep them around until the HW is done with them at
	 * some later time. This workqueue iterates over the list of free'd
	 * syncs, checks if they are in use, and frees the sync device memory
	 * when done with.
	 */
	struct workqueue_struct *defer_free_wq;
	struct work_struct defer_free_work;

	/* check_status workqueue: When a foreign point is completed, a SW
	 * operation marks the sync as completed to allow the operations to
	 * continue. This completion may require the hardware to be notified,
	 * which may be expensive/take locks, so we push that to a workqueue
	 */
	struct workqueue_struct *check_status_wq;
	struct work_struct check_status_work;

	/* Context used to create client sync prims. */
	struct SYNC_PRIM_CONTEXT *sync_prim_context;

	/* 'Global' Context used to create sync checkpoints. */
	PSYNC_CHECKPOINT_CONTEXT global_sync_checkpoint_context;

	/* Debug notify handle */
	void *debug_notify_handle;

	/* Unique id counter for the sync prims */
	atomic_t sync_id;

	/* The global event object (used to wait between checks for
	 * deferred-free sync status).
	 */
	void *event_object_handle;
} pvr_sync_data;

/* List of timelines created by this driver */
static LIST_HEAD(timeline_list);
static DEFINE_MUTEX(timeline_list_mutex);

/* Sync pool support */
static LIST_HEAD(sync_pool_free_list);
static LIST_HEAD(sync_pool_active_list);
static DEFINE_MUTEX(sync_pool_mutex);
static s32 sync_pool_size;// = 0;
static u32 sync_pool_created;// = 0;
static u32 sync_pool_reused;// = 0;

/* The "defer-free" sync_checkpoint list. Driver global. */
static LIST_HEAD(sync_checkpoint_free_list);
static DEFINE_SPINLOCK(sync_checkpoint_free_list_spinlock);

/* The "defer-free-timeline" object list. Driver global. */
static LIST_HEAD(timeline_free_list);
static DEFINE_SPINLOCK(timeline_free_list_spinlock);

/* The "defer-put" object list. Driver global. */
static LIST_HEAD(sync_fence_put_list);
static DEFINE_SPINLOCK(sync_fence_put_list_spinlock);

static void pvr_sync_update_all_timelines(void *command_complete_handle);
static void pvr_sync_free_checkpoint_list_mem(void *mem_ptr);

/* Sync prim helpers */
static inline void set_sync_prim_value(struct pvr_sync_native_sync_prim *sync,
				  u32 value)
{
	*(sync->client_sync->pui32LinAddr) = value;
}

static inline u32 get_sync_prim_value(struct pvr_sync_native_sync_prim *sync)
{
	return *(sync->client_sync->pui32LinAddr);
}

static inline void complete_sync_prim(struct pvr_sync_native_sync_prim *sync)
{
	*(sync->client_sync->pui32LinAddr) = sync->next_value;
}

static inline int is_sync_prim_met(struct pvr_sync_native_sync_prim *sync)
{
	return *(sync->client_sync->pui32LinAddr) == sync->next_value;
}

/* Checkpoint helpers */
static inline u32 get_sync_checkpoint_value(struct pvr_sync_native_sync_checkpoint *sync)
{
	PVRSRV_SYNC_CHECKPOINT_STATE checkpoint_state = PVRSRV_SYNC_CHECKPOINT_NOT_SIGNALLED;
	if (SyncCheckpointIsSignalled(sync->client_sync_checkpoint))
	{
		checkpoint_state = PVRSRV_SYNC_CHECKPOINT_SIGNALLED;
	}
	else if (SyncCheckpointIsErrored(sync->client_sync_checkpoint))
	{
		checkpoint_state = PVRSRV_SYNC_CHECKPOINT_ERRORED;
	}
	return (u32)checkpoint_state;
}

static inline char get_sync_checkpoint_char(struct pvr_sync_native_sync_checkpoint *sync)
{
	char cState = 'A';
	if (SyncCheckpointIsSignalled(sync->client_sync_checkpoint))
	{
		cState = 'S';
	}
	else if (SyncCheckpointIsErrored(sync->client_sync_checkpoint))
	{
		cState = 'E';
	}
	return cState;
}

static inline void error_sync_checkpoint(struct pvr_sync_native_sync_checkpoint *sync)
{
	SyncCheckpointError(sync->client_sync_checkpoint);
}

static inline void complete_sync_checkpoint(struct pvr_sync_native_sync_checkpoint *sync)
{
	SyncCheckpointSignal(sync->client_sync_checkpoint);
}

static inline int is_sync_checkpoint_met(struct pvr_sync_native_sync_checkpoint *sync)
{
	return (int)SyncCheckpointIsSignalled(sync->client_sync_checkpoint);
}

/* Timeline helpers */
static inline struct pvr_sync_timeline *get_timeline(struct sync_timeline *obj)
{
	return ((struct pvr_sync_timeline_wrapper *)obj)->timeline;
}

static inline struct pvr_sync_timeline *get_timeline_pt(struct sync_pt *pt)
{
	return get_timeline(sync_pt_parent(pt));
}

static inline int
pvr_sync_has_kernel_signaled(struct pvr_sync_kernel_pair *kernel)
{
	/* Idle syncs are always signaled */
	if (!kernel)
		return 1;

	return is_sync_checkpoint_met(kernel->fence_sync);
}

#ifdef DEBUG_OUTPUT

static char *debug_info_timeline(struct pvr_sync_timeline *timeline)
{
	static char info[256];

	if (timeline->kernel->fence_sync)
	{
		snprintf(info, sizeof(info),
			 "n='%s' id=%u fw=0x%x tl_curr=%u tl_next=%u",
			 timeline->obj ? timeline->obj->name : "?",
			 timeline->kernel->fence_sync->id,
			 timeline->kernel->fence_sync->vaddr,
			 get_sync_prim_value(timeline->kernel->fence_sync),
			 timeline->kernel->fence_sync->next_value);
	}
	else
	{
		snprintf(info, sizeof(info),
			 "n='%s' id=n/a fw=n/a tl_curr=n/a tl_next=n/a",
			 timeline->obj ? timeline->obj->name : "?");
	}

	return info;
}

static char *debug_info_sync_pt(struct sync_pt *pt)
{
	//struct pvr_sync_timeline *timeline = get_timeline_pt(pt);
	//struct pvr_sync_pt *pvr_pt = (struct pvr_sync_pt *)pt;
	//struct pvr_sync_kernel_pair *kernel = pvr_pt->sync_data->kernel;
	static char info[256], info1[256];

#if 1
	info[0] = '\0';
	info1[0] = '\0';
#else
	if (kernel) {
#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
		struct pvr_sync_native_sync_prim *cleanup_sync =
			kernel->cleanup_sync;

		if (cleanup_sync) {
			snprintf(info1, sizeof(info1),
				 " # cleanup: id=%u fw=0x%x curr=%u next=%u",
				 cleanup_sync->id,
				 cleanup_sync->vaddr,
				 get_sync_prim_value(cleanup_sync),
				 cleanup_sync->next_value);
		} else {
			info1[0] = 0;
		}
#endif

		if (timeline->kernel->fence_sync)
		{
			snprintf(info, sizeof(info),
				 "status=%d tl_taken=%u ref=%d # sync: id=%u fw=0x%x curr=%u next=%u%s # tl: %s",
				 pvr_sync_has_kernel_signaled(kernel),
				 pvr_pt->sync_data->timeline_update_value,
				 atomic_read(&pvr_pt->sync_data->kref.refcount),
				 kernel->fence_sync->id,
				 kernel->fence_sync->vaddr,
				 get_sync_prim_value(timeline->kernel->fence_sync),
				 kernel->fence_sync->next_value,
				 info1, debug_info_timeline(timeline));
		}
	} else {
		snprintf(info, sizeof(info),
			 "status=%d tl_taken=%u ref=%d # sync: idle # tl: %s",
			 pvr_sync_has_kernel_signaled(kernel),
			 pvr_pt->sync_data->timeline_update_value,
			 atomic_read(&pvr_pt->sync_data->kref.refcount),
			 debug_info_timeline(timeline));
	}
#endif
	return info;
}

#endif /* DEBUG_OUTPUT */

static u32 sync_pool_get_callers = 0;
static enum PVRSRV_ERROR
sync_pool_get(struct pvr_sync_native_sync_prim **_sync,
	      const char *class_name, u8 type)
{
	struct pvr_sync_native_sync_prim *sync;
	enum PVRSRV_ERROR error = PVRSRV_OK;
	u32 sync_addr;

	mutex_lock(&sync_pool_mutex);
	sync_pool_get_callers++;

	if (list_empty(&sync_pool_free_list)) {
		/* If there is nothing in the pool, create a new sync prim. */
		sync = kmalloc(sizeof(*sync),
			       GFP_KERNEL);
		if (!sync) {
			pr_err("pvr_sync2: %s: Failed to allocate sync data\n",
			       __func__);
			error = PVRSRV_ERROR_OUT_OF_MEMORY;
			goto err_unlock;
		}

		error = SyncPrimAlloc(pvr_sync_data.sync_prim_context,
				      &sync->client_sync, class_name);
		if (error != PVRSRV_OK) {
			pr_err("pvr_sync2: %s: Failed to allocate sync prim (%s)\n",
			       __func__, PVRSRVGetErrorStringKM(error));
			goto err_free;
		}

		error = SyncPrimGetFirmwareAddr(sync->client_sync, &sync_addr);
		if (error != PVRSRV_OK) {
			pr_err("pvr_sync2: %s: Failed to get FW address (%s)\n",
			       __func__, PVRSRVGetErrorStringKM(error));
			goto err_sync_prim_free;
		}
		sync->vaddr = sync_addr;

		list_add_tail(&sync->list, &sync_pool_active_list);
		++sync_pool_created;
	} else {
		sync = list_first_entry(&sync_pool_free_list,
					struct pvr_sync_native_sync_prim, list);
		list_move_tail(&sync->list, &sync_pool_active_list);
	    --sync_pool_size;
		++sync_pool_reused;
	}

	sync->id = atomic_inc_return(&pvr_sync_data.sync_id);
	sync->type = type;

	strncpy(sync->class, class_name, sizeof(sync->class));
	sync->class[sizeof(sync->class) - 1] = '\0';
	/* It's crucial to reset the sync to zero */
	set_sync_prim_value(sync, 0);
	sync->next_value = 0;

	*_sync = sync;

err_unlock:
	sync_pool_get_callers--;
	mutex_unlock(&sync_pool_mutex);
	return error;

err_sync_prim_free:
	SyncPrimFree(sync->client_sync);

err_free:
	kfree(sync);
	goto err_unlock;
}

static u32 sync_pool_put_callers = 0;

static void sync_pool_put(struct pvr_sync_native_sync_prim *sync)
{
	mutex_lock(&sync_pool_mutex);
	sync_pool_put_callers++;

	if (sync_pool_size < SYNC_MAX_POOL_SIZE) {
		/* Mark it as unused */
		set_sync_prim_value(sync, 0xffffffff);

		list_move(&sync->list, &sync_pool_free_list);
		++sync_pool_size;
	} else {
		/* Mark it as invalid */
		set_sync_prim_value(sync, 0xdeadbeef);

		list_del(&sync->list);
		SyncPrimFree(sync->client_sync);
		kfree(sync);
	}

	sync_pool_put_callers--;
	mutex_unlock(&sync_pool_mutex);
}

static void sync_pool_clear(void)
{
	struct pvr_sync_native_sync_prim *sync, *n;

	mutex_lock(&sync_pool_mutex);

	list_for_each_entry_safe(sync, n, &sync_pool_free_list, list) {
		/* Mark it as invalid */
		set_sync_prim_value(sync, 0xdeadbeef);

		list_del(&sync->list);
		SyncPrimFree(sync->client_sync);
		kfree(sync);
		--sync_pool_size;
	}

	mutex_unlock(&sync_pool_mutex);
}

static void pvr_sync_debug_request(void *hDebugRequestHandle,
								   u32 ui32VerbLevel,
								   DUMPDEBUG_PRINTF_FUNC *pfnDumpDebugPrintf,
								   void *pvDumpDebugFile)
{
	/* TODO: */
#if 0 /* Comment-out entire function */
	struct pvr_sync_native_sync_checkpoint *sync;

	static const char *const type_names[] = {
		"Timeline", "Fence", "Cleanup",
		"Foreign Fence", "Foreign Cleanup"
	};

	if (ui32VerbLevel == DEBUG_REQUEST_VERBOSITY_MEDIUM) {
		mutex_lock(&sync_pool_mutex);

		PVR_DUMPDEBUG_LOG(pfnDumpDebugPrintf, pvDumpDebugFile,
				  "Dumping all pending android native syncs (Pool usage: %d%% - %d %d)",
				  sync_pool_reused ?
				  (10000 /
				   ((sync_pool_created + sync_pool_reused) *
				    100 / sync_pool_reused)) : 0,
				  sync_pool_created, sync_pool_reused);

		list_for_each_entry(sync, &sync_pool_active_list, list) {
			if (is_sync_checkpoint_met(sync))
				continue;

			BUG_ON(sync->type >= ARRAY_SIZE(type_names));

			if (sync->type == 2 || sync->type == 4)
			{
			PVR_DUMPDEBUG_LOG(pfnDumpDebugPrintf, pvDumpDebugFile,
					  "\t~ID = %d, FWAddr = 0x%08x: Current = %s, %s (%s)",
					  sync->id, sync->vaddr,
					  SyncCheckpointIsSignalled(sync->client_sync_checkpoint) ? "PVRSRV_SYNC_CHECKPOINT_SIGNALLED" : "PVRSRV_SYNC_CHECKPOINT_NOT_SIGNALLED",
					  sync->class,
					  type_names[sync->type]);
			}
			else
			{
#if !defined(PVRSRV_USE_SYNC_CHECKPOINTS)
				PVR_DUMPDEBUG_LOG(pfnDumpDebugPrintf, pvDumpDebugFile,
						  "\tID = %d, FWAddr = 0x%08x: Current = 0x%08x, Next = 0x%08x, %s (%s)",
						  sync->id, sync->vaddr,
						  get_sync_prim_value(sync),
						  sync->next_value,
#else
				PVR_DUMPDEBUG_LOG(pfnDumpDebugPrintf, pvDumpDebugFile,
						  "\tID = %d, FWAddr = 0x%08x: Current = %s, %s (%s)",
						  sync->id, sync->vaddr,
						  SyncCheckpointIsSignalled(sync->client_sync_checkpoint) ? "PVRSRV_SYNC_CHECKPOINT_SIGNALLED" : "PVRSRV_SYNC_CHECKPOINT_NOT_SIGNALLED",
#endif
						  sync->class,
						  type_names[sync->type]);
			}
		}
#if 0
		PVR_DUMPDEBUG_LOG(pfnDumpDebugPrintf,
				  "Dumping all unused syncs");
		list_for_each_entry(sync, &sync_pool_free_list, list) {
			BUG_ON(sync->type >= ARRAY_SIZE(type_names));

			PVR_DUMPDEBUG_LOG(pfnDumpDebugPrintf,
					  "\tID = %d, FWAddr = 0x%08x: Current = 0x%08x, Next = 0x%08x, %s (%s)",
					  sync->id, sync->vaddr,
					  get_sync_value(sync),
					  sync->next_value,
					  sync->class,
					  type_names[sync->type]);
		}
#endif
		mutex_unlock(&sync_pool_mutex);
	}
#endif /* Comment-out entire function */
}

static struct sync_pt *pvr_sync_dup(struct sync_pt *sync_pt)
{
	struct pvr_sync_pt *pvr_pt_a = (struct pvr_sync_pt *)sync_pt;
	struct pvr_sync_pt *pvr_pt_b = NULL;

	DPF("%s: # %s", __func__, debug_info_sync_pt(sync_pt));

	pvr_pt_b = (struct pvr_sync_pt *)
		sync_pt_create(sync_pt_parent(sync_pt),
			       sizeof(*pvr_pt_b));
	if (!pvr_pt_b) {
		pr_err("pvr_sync2: %s: Failed to dup sync pt\n", __func__);
		goto err_out;
	}

	kref_get(&pvr_pt_a->sync_data->kref);

	pvr_pt_b->sync_data = pvr_pt_a->sync_data;

err_out:
	return (struct sync_pt *)pvr_pt_b;
}

static int pvr_sync_has_signaled(struct sync_pt *sync_pt)
{
	struct pvr_sync_pt *pvr_pt = (struct pvr_sync_pt *)sync_pt;

	DPF("%s: # %s", __func__, debug_info_sync_pt(sync_pt));

	return pvr_sync_has_kernel_signaled(pvr_pt->sync_data->kernel);
}

static int pvr_sync_compare(struct sync_pt *a, struct sync_pt *b)
{
	u32 a1 = ((struct pvr_sync_pt *)a)->sync_data->timeline_update_value;
	u32 b1 = ((struct pvr_sync_pt *)b)->sync_data->timeline_update_value;

	DPF("%s: a # %s", __func__, debug_info_sync_pt(a));
	DPF("%s: b # %s", __func__, debug_info_sync_pt(b));

	if (a1 == b1)
		return 0;

	/* Take integer wrapping into account */
	return ((s32)a1 - (s32)b1) < 0 ? -1 : 1;
}

static void wait_for_sync_prim(struct pvr_sync_native_sync_prim *sync)
{
#ifndef NO_HARDWARE
	void *event_object = NULL;
	enum PVRSRV_ERROR error = PVRSRV_OK;

	while (sync && !is_sync_prim_met(sync)) {
		/* This debug will indicate if pvr_sync is stuck waiting for a sync prim */
		pr_err("pvr_sync2: %s: waiting for sync prim<%p> %s (%d != %d)\n",
			__func__, (void*)sync->client_sync, sync->class,
			 *(sync->client_sync->pui32LinAddr), sync->next_value);
		if (!event_object) {
			error = OSEventObjectOpen(
				pvr_sync_data.event_object_handle,
				&event_object);
			if (error != PVRSRV_OK) {
				pr_err("pvr_sync2: %s: Error opening event object (%s)\n",
					__func__,
					PVRSRVGetErrorStringKM(error));
				break;
			}
		}
		error = OSEventObjectWait(event_object);
		if (error != PVRSRV_OK && error != PVRSRV_ERROR_TIMEOUT) {
			pr_err("pvr_sync2: %s: Error waiting on event object (%s)\n",
				__func__,
				PVRSRVGetErrorStringKM(error));
		}
	}

	if (event_object)
		OSEventObjectClose(event_object);
#endif /* NO_HARDWARE */
}

static void pvr_sync_defer_free_checkpoints(struct pvr_sync_kernel_pair *kernel)
{
	unsigned long flags;

	spin_lock_irqsave(&sync_checkpoint_free_list_spinlock, flags);
	list_add_tail(&kernel->list, &sync_checkpoint_free_list);
	spin_unlock_irqrestore(&sync_checkpoint_free_list_spinlock, flags);

	queue_work(pvr_sync_data.defer_free_wq, &pvr_sync_data.defer_free_work);
}

static void pvr_sync_timeline_defer_free(struct pvr_sync_timeline_kernel_pair *kernel)
{
	unsigned long flags;

	spin_lock_irqsave(&timeline_free_list_spinlock, flags);
	list_add_tail(&kernel->list, &timeline_free_list);
	spin_unlock_irqrestore(&timeline_free_list_spinlock, flags);

	queue_work(pvr_sync_data.defer_free_wq, &pvr_sync_data.defer_free_work);
}

/* This function assumes the timeline_list_mutex is held while it runs */

static void pvr_sync_destroy_timeline_locked(struct kref *kref)
{
	struct pvr_sync_timeline *timeline = (struct pvr_sync_timeline *)
		container_of(kref, struct pvr_sync_timeline, kref);

	pvr_sync_timeline_defer_free(timeline->kernel);
	list_del(&timeline->list);
	kfree(timeline);
}

static void pvr_sync_destroy_timeline(struct kref *kref)
{
	mutex_lock(&timeline_list_mutex);
	pvr_sync_destroy_timeline_locked(kref);
	mutex_unlock(&timeline_list_mutex);
}

static void pvr_sync_release_timeline(struct sync_timeline *obj)
{
	struct pvr_sync_timeline *timeline = get_timeline(obj);

	/* If pvr_sync_open failed after calling sync_timeline_create, this
	 * can be called with a timeline that has not got a timeline sync
	 * or been added to our timeline list. Use a NULL timeline to
	 * detect and handle this condition
	 */
	if (!timeline)
		return;

	DPF("%s: # %s", __func__, debug_info_timeline(timeline));

	if (timeline->kernel->fence_sync)
		wait_for_sync_prim(timeline->kernel->fence_sync);

	/* Whether or not we're the last reference, obj is going away
	 * after this function returns, so remove our back reference
	 * to it.
	 */
	timeline->obj = NULL;

	/* This might be the last reference to the timeline object.
	 * If so, we'll go ahead and delete it now.
	 */
	kref_put(&timeline->kref, pvr_sync_destroy_timeline);
}

/* The print_obj() and print_pt() functions have been removed, so we're forced
 * to use the timeline_value_str() and pt_value_str() functions. These are
 * worse because we're limited to 64 characters, and the strings for sync
 * pts have to be formatted like:
 *
 *   pt active: pt_info / tl_info
 *
 * For us, the tl_info is complicated and doesn't need to be repeated over
 * and over. So try to detect the way sync_print_pt() calls the two value_str
 * functions and change what pvr_sync_timeline_value_str() returns dynamically.
 */
static struct sync_timeline *last_pt_timeline;

static void pvr_sync_timeline_value_str(struct sync_timeline *sync_timeline,
					char *str, int size)
{
	struct pvr_sync_timeline *timeline = get_timeline(sync_timeline);

	if (timeline->kernel->fence_sync) {
		if (sync_timeline != last_pt_timeline) {
			snprintf(str, size, "%u 0x%x %u/%u",
				 timeline->kernel->fence_sync->id,
				 timeline->kernel->fence_sync->vaddr,
				 get_sync_prim_value(timeline->kernel->fence_sync),
				 timeline->kernel->fence_sync->next_value);
		} else {
			snprintf(str, size, "%u",
				 get_sync_prim_value(timeline->kernel->fence_sync));
		}
	} else {
		snprintf(str, size, "n/a");
	}
}

static void pvr_sync_pt_value_str(struct sync_pt *sync_pt, char *str, int size)
{
	struct pvr_sync_pt *pvr_pt = (struct pvr_sync_pt *)sync_pt;
	struct pvr_sync_kernel_pair *kernel;

	if (!pvr_pt->sync_data)
		return;

	kernel = pvr_pt->sync_data->kernel;

	/* Messages must be at most 64 bytes (including the null terminator):
	 *
	 * 123456789012345678901234567890123456789012345678901234567890123
	 *
	 * ID     FW ADDR    C/N # REF TAKEN
	 * 123456 0xdeadbeef 0/1 # r=2 123456
	 *
	 * ID     FW ADDR    C/N # ID     FW ADDR    C/N # REF TAKEN
	 * 123456 0xdeadbeef 0/1 # 123456 0xdeadbeef 0/1 # r=2 123456
	 */
	if (kernel && kernel->fence_sync) {
#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
		if (!kernel->cleanup_sync) {
#endif
			snprintf(str, size,
				 "%u 0x%x %c e=%d r=%d %u",
				 kernel->fence_sync->id,
				 kernel->fence_sync->vaddr,
				 get_sync_checkpoint_char(kernel->fence_sync),
				 SyncCheckpointGetEnqueuedCount(kernel->fence_sync->client_sync_checkpoint),
				 atomic_read(&pvr_pt->sync_data->kref.refcount),
				 pvr_pt->sync_data->timeline_update_value);
#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
		} else {
			snprintf(str, size,
				 "%u 0x%x %c e=%d # %u 0x%x %u/%u # r=%d %u",
				 kernel->fence_sync->id,
				 kernel->fence_sync->vaddr,
				 get_sync_checkpoint_char(kernel->fence_sync),
				 SyncCheckpointGetEnqueuedCount(kernel->fence_sync->client_sync_checkpoint),
				 kernel->cleanup_sync->id,
				 kernel->cleanup_sync->vaddr,
				 get_sync_prim_value(kernel->cleanup_sync),
				 kernel->cleanup_sync->next_value,
				 atomic_read(&pvr_pt->sync_data->kref.refcount),
				 pvr_pt->sync_data->timeline_update_value);
		}
#endif
	} else {
		snprintf(str, size, "idle # r=%d %u",
			 atomic_read(&pvr_pt->sync_data->kref.refcount),
			 pvr_pt->sync_data->timeline_update_value);
	}

	last_pt_timeline = sync_pt_parent(sync_pt);
}

/* pvr_sync_create_sync_data() should be called with the bridge lock held */
static struct pvr_sync_data *
pvr_sync_create_sync_data(struct sync_timeline *obj, const s32 timeline_fd, PSYNC_CHECKPOINT_CONTEXT psSyncCheckpointContext)
{
	struct pvr_sync_data *sync_data = NULL;
	enum PVRSRV_ERROR error;

	sync_data = kzalloc(sizeof(*sync_data), GFP_KERNEL);
	if (!sync_data)
		goto err_out;

	kref_init(&sync_data->kref);

	sync_data->kernel =
		kzalloc(sizeof(*sync_data->kernel),
		GFP_KERNEL);

	if (!sync_data->kernel)
		goto err_free_data;

	sync_data->kernel->fence_sync =
		kzalloc(sizeof(struct pvr_sync_native_sync_checkpoint), GFP_KERNEL);
	if (!sync_data->kernel->fence_sync)
		goto err_free_kernel;

	error = SyncCheckpointAlloc(psSyncCheckpointContext,
								(PVRSRV_TIMELINE)timeline_fd,
								obj->name,
								&sync_data->kernel->fence_sync->client_sync_checkpoint);
	if (error != PVRSRV_OK)
	{
		pr_err("pvr_sync2: %s: Failed to allocate sync checkpoint (%s)\n",
		       __func__, PVRSRVGetErrorStringKM(error));
		goto err_free_fence;
	}

	sync_data->kernel->fence_sync->vaddr =
		SyncCheckpointGetFirmwareAddr(sync_data->kernel->fence_sync->client_sync_checkpoint);
	sync_data->kernel->fence_sync->id =
		SyncCheckpointGetId(sync_data->kernel->fence_sync->client_sync_checkpoint);
	sync_data->kernel->fence_sync->type = SYNC_PT_FENCE_TYPE;
	strncpy(sync_data->kernel->fence_sync->class, obj->name,
			sizeof(sync_data->kernel->fence_sync->class));

err_out:
	return sync_data;

err_free_fence:
	kfree(sync_data->kernel->fence_sync);
err_free_kernel:
	kfree(sync_data->kernel);
err_free_data:
	kfree(sync_data);
	sync_data = NULL;
	goto err_out;
}

static void pvr_sync_free_sync_data(struct kref *kref)
{
	struct pvr_sync_data *sync_data = (struct pvr_sync_data *)
		container_of(kref, struct pvr_sync_data, kref);

	if (sync_data->kernel)
		pvr_sync_defer_free_checkpoints(sync_data->kernel);
	kfree(sync_data);
}

static void pvr_sync_free_sync(struct sync_pt *sync_pt)
{
	struct pvr_sync_pt *pvr_pt = (struct pvr_sync_pt *)sync_pt;

	DPF("%s: # %s", __func__, debug_info_sync_pt(sync_pt));

	kref_put(&pvr_pt->sync_data->kref, pvr_sync_free_sync_data);
}

/* this function uses pvr_sync_timeline_ops defined below */
static int pvr_sync_fill_driver_data(struct sync_pt *, void *, int);

static struct sync_timeline_ops pvr_sync_timeline_ops = {
	.driver_name        = PVRSYNC_MODNAME,
	.dup                = pvr_sync_dup,
	.has_signaled       = pvr_sync_has_signaled,
	.compare            = pvr_sync_compare,
	.free_pt            = pvr_sync_free_sync,
	.release_obj        = pvr_sync_release_timeline,
	.timeline_value_str = pvr_sync_timeline_value_str,
	.pt_value_str       = pvr_sync_pt_value_str,
	.fill_driver_data   = pvr_sync_fill_driver_data,
};

static inline bool is_pvr_timeline(struct sync_timeline *obj)
{
	//pr_err("pvr_sync2: %s:   obj=<%p> , obj->ops=<%p>, &pvr_sync_timeline_ops=<%p>\n",__func__, (void*)obj, (void*)obj->ops, (void*)&pvr_sync_timeline_ops);
	return obj->ops == &pvr_sync_timeline_ops;
}

static inline bool is_pvr_timeline_pt(struct sync_pt *pt)
{
	return is_pvr_timeline(sync_pt_parent(pt));
}

static int
pvr_sync_fill_driver_data(struct sync_pt *sync_pt, void *data, int size)
{
	struct pvr_sync_pt_info *info = (struct pvr_sync_pt_info *)data;
	struct pvr_sync_pt *pvr_pt = (struct pvr_sync_pt *)sync_pt;
	struct pvr_sync_data *sync_data = pvr_pt->sync_data;
	struct pvr_sync_kernel_pair *kernel = sync_data->kernel;

	if (size < sizeof(*info))
		return -ENOMEM;

	info->ui32TlTaken = sync_data->timeline_update_value;

	if (kernel && kernel->fence_sync) {
		info->id         = kernel->fence_sync->id;
		info->ui32FWAddr = kernel->fence_sync->vaddr;
		info->ui32CurrOp = get_sync_checkpoint_value(kernel->fence_sync);
		info->ui32NextOp = PVRSRV_SYNC_CHECKPOINT_SIGNALLED;
	} else {
		info->id         = 0;
		info->ui32FWAddr = 0;
		info->ui32CurrOp = 0;
		info->ui32NextOp = 0;
	}

	return sizeof(*info);
}

/* foreign sync handling */

static void pvr_sync_foreign_sync_pt_signaled(struct sync_fence *fence,
					      struct sync_fence_waiter *_waiter)
{
	struct pvr_sync_fence_waiter *waiter =
		(struct pvr_sync_fence_waiter *)_waiter;
	unsigned long flags;

	//pr_err("pvr_sync2: %s:   signalling sync checkpoint <%p> \n",__func__, (void*)waiter->kernel->fence_sync->client_sync_checkpoint);

	/* Complete the SW operation and free the sync if we can. If we can't,
	 * it will be checked by a later workqueue kick.
	 */
	if (!is_sync_checkpoint_met(waiter->kernel->fence_sync)) {
		complete_sync_checkpoint(waiter->kernel->fence_sync);

		/* We can 'put' the fence now, but this function might be called in
		 * irq context so we must defer to WQ.
		 * This WQ is triggered in pvr_sync_defer_free, so adding it to the
		 * put list before that should guarantee it's cleaned up on the next
		 * wq run.
		 */
		spin_lock_irqsave(&sync_fence_put_list_spinlock, flags);
		list_add_tail(&waiter->sync_fence->list, &sync_fence_put_list);
		spin_unlock_irqrestore(&sync_fence_put_list_spinlock, flags);

		pvr_sync_defer_free_checkpoints(waiter->kernel);

		/* The completed sw-sync may allow other tasks to complete,
		 * so we need to allow them to progress.
		 */
		queue_work(pvr_sync_data.check_status_wq,
			&pvr_sync_data.check_status_work);

		kfree(waiter);
	}
	else {
		pr_err("pvr_sync2: %s:   this sync checkpoint has already been signalled - why are we asked to do this more than once?! \n",__func__);
	}
}

static PSYNC_CHECKPOINT
pvr_sync_create_waiter_for_foreign_sync(int fd, PSYNC_CHECKPOINT_CONTEXT psSyncCheckpointContext)
{
	struct pvr_sync_kernel_pair *kernel = NULL;
	struct pvr_sync_fence_waiter *waiter;
	struct pvr_sync_fence *sync_fence;
	PSYNC_CHECKPOINT checkpoint;
	struct sync_fence *fence;
	enum PVRSRV_ERROR error;
	int err;

	fence = sync_fence_fdget(fd);
	if (!fence) {
		pr_err("pvr_sync2: %s: Failed to take reference on fence\n",
		       __func__);
		goto err_out;
	}

	kernel = kmalloc(sizeof(*kernel), GFP_KERNEL);
	if (!kernel) {
		pr_err("pvr_sync2: %s: Failed to allocate sync kernel\n",
		       __func__);
		goto err_put_fence;
	}

	sync_fence = kmalloc(sizeof(*sync_fence), GFP_KERNEL);
	if (!sync_fence) {
		pr_err("pvr_sync2: %s: Failed to allocate pvr sync fence\n",
		       __func__);
		goto err_free_kernel;
	}

	sync_fence->fence = fence;

	kernel->fence_sync = kzalloc(sizeof(struct pvr_sync_native_sync_checkpoint), GFP_KERNEL);
	if (!kernel->fence_sync)
		goto err_free_fence;

	/* Create sync checkpoint for the foreign sync, with an invalid timeline (as we do not know it) */
	//pr_err("pvr_sync2: %s:   Allocating-sync checkpoint for foreign sync (fence->name = %s)...\n",__func__, fence->name);
	//pr_err("pvr_sync2: %s:              kernel=<%p>\n",__func__, (void*)kernel);
	//pr_err("pvr_sync2: %s:              kernel->fence_sync=<%p>\n",__func__, (void*)kernel->fence_sync);
	//pr_err("pvr_sync2: %s:              pvr_sync_data.global_sync_checkpoint_context=<%p>\n",__func__, (void*)pvr_sync_data.global_sync_checkpoint_context);
	error = SyncCheckpointAlloc(pvr_sync_data.global_sync_checkpoint_context, (PVRSRV_TIMELINE)-1,
								fence->name,
								&checkpoint);
	if (error != PVRSRV_OK) {
		pr_err("pvr_sync2: %s: Failed to allocate sync checkpoint (%s)\n",
		       __func__, PVRSRVGetErrorStringKM(error));
		goto err_free_fence_sync;
	}
	kernel->fence_sync->client_sync_checkpoint = checkpoint;
	//pr_err("pvr_sync2: %s:   ...done, kernel->fence_sync->client_sync_checkpoint=<%p>\n",__func__, (void*)kernel->fence_sync->client_sync_checkpoint);

	//pr_err("pvr_sync2: %s:   filling-in fence_sync vAddr(0x%x)\n",__func__, SyncCheckpointGetFirmwareAddr(kernel->fence_sync->client_sync_checkpoint));
	kernel->fence_sync->vaddr =
		SyncCheckpointGetFirmwareAddr(kernel->fence_sync->client_sync_checkpoint);
	//pr_err("pvr_sync2: %s:   filling-in fence_sync ID(%d)\n",__func__, SyncCheckpointGetId(kernel->fence_sync->client_sync_checkpoint));
	kernel->fence_sync->id =
		SyncCheckpointGetId(kernel->fence_sync->client_sync_checkpoint);
	kernel->fence_sync->type = SYNC_PT_FOREIGN_FENCE_TYPE;
	//pr_err("pvr_sync2: %s:   copying fence name(%s)\n",__func__, fence->name);
	strncpy(kernel->fence_sync->class, fence->name, sizeof(kernel->fence_sync->class));

#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
	error = sync_pool_get(&kernel->cleanup_sync,
			      fence->name, SYNC_PT_FOREIGN_CLEANUP_TYPE);
	if (error != PVRSRV_OK) {
		//pr_err("pvr_sync2: %s: Failed to allocate cleanup sync prim (%s)\n",
		//       __func__, PVRSRVGetErrorStringKM(error));
		goto err_free_checkpoint;
	}

	kernel->cleanup_sync->next_value++;
#endif

	/* The custom waiter structure is freed in the waiter callback */
	waiter = kmalloc(sizeof(*waiter), GFP_KERNEL);
	if (!waiter) {
		pr_err("pvr_sync2: %s: Failed to allocate waiter\n", __func__);
		goto err_free_cleanup_sync;
	}

	waiter->kernel = kernel;
	waiter->sync_fence = sync_fence;

	/* Take an extra ref on the checkpoint for the reference handed over to
	 * the firmware.
	 * This must be done before the waiter_init, as the waiter can be called
	 * and it's reference dropped at _any time_
	 */
	SyncCheckpointTakeRef(checkpoint);

	//pr_err("pvr_sync2: %s:   initialising-fence waiter\n",__func__);
	sync_fence_waiter_init(&waiter->waiter,
			       pvr_sync_foreign_sync_pt_signaled);

	//pr_err("pvr_sync2: %s:   calling-sync_fence_wait_async()\n",__func__);
	err = sync_fence_wait_async(fence, &waiter->waiter);
	if (err) {
		if (err < 0) {
			//pr_err("pvr_sync2: %s: Fence was in error state (%d)\n",
			//       __func__, err);
			/* Fall-thru */
		}

		/* -1 means the fence was broken, 1 means the fence already
		 * signalled. In either case, roll back what we've done and
		 * skip using this sync_pt for synchronization.
		 */
		goto err_put_checkpoint_ref;
	}

	//pr_err("pvr_sync2: %s: ...done (ok)\n",__func__);
err_out:
	return checkpoint;
err_put_checkpoint_ref:
	SyncCheckpointDropRef(checkpoint);
	kfree(waiter);
err_free_cleanup_sync:
#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
	sync_pool_put(kernel->cleanup_sync);
err_free_checkpoint:
#endif
	SyncCheckpointFree(checkpoint);
	checkpoint = NULL;
err_free_fence_sync:
	kfree(kernel->fence_sync);
	kernel->fence_sync = NULL;
err_free_fence:
	kfree(sync_fence);
	sync_fence = NULL;
err_free_kernel:
	kfree(kernel);
	kernel = NULL;
err_put_fence:
	sync_fence_put(fence);
	//pr_err("pvr_sync2: %s: ...done (error)\n",__func__);
	goto err_out;
}

static
struct pvr_sync_pt *pvr_sync_create_pt(struct pvr_sync_timeline *timeline, const s32 timeline_fd, PSYNC_CHECKPOINT_CONTEXT psSyncCheckpointContext)
{
	struct pvr_sync_data *sync_data;
	struct pvr_sync_pt *pvr_pt = NULL;

	sync_data = pvr_sync_create_sync_data(timeline->obj, timeline_fd, psSyncCheckpointContext);
	if (!sync_data) {
		pr_err("pvr_sync2: %s: Failed to create sync data\n", __func__);
		goto err_out;
	}

	pvr_pt = (struct pvr_sync_pt *)
		sync_pt_create(timeline->obj, sizeof(struct pvr_sync_pt));
//	pr_err("pvr_sync2: %s: sizeof(struct pvr_sync_pt)=%lu, sizeof(*pvr_pt)=%lu\n", __func__, sizeof(struct pvr_sync_pt), sizeof(*pvr_pt));
//	pvr_pt = (struct pvr_sync_pt *)sync_pt_create(timeline->obj, sizeof(*pvr_pt));

	if (!pvr_pt) {
		pr_err("pvr_sync2: %s: Failed to create sync pt\n", __func__);
		goto err_rollback_fence;
	}

	//pr_err("pvr_sync2: %s:   pvr_pt=<%p>\n",__func__, (void*)pvr_pt);
	pvr_pt->sync_data = sync_data;

	pvr_pt->timeline = timeline;

	/* Increment the timeline next value */
	pvr_pt->sync_data->timeline_update_value =
		timeline->kernel->fence_sync->next_value++;

	return pvr_pt;

err_rollback_fence:
	/* Error the sync checkpoint (so the deferred free considers it 'met') */
	error_sync_checkpoint(sync_data->kernel->fence_sync);
	kref_put(&sync_data->kref, pvr_sync_free_sync_data);
err_out:
	return NULL;
}

/* Predeclare the pvr_sync_fops as it's used for comparison to ensure the
 * update_timeline_fd passed in to pvr_sync_append_fences() is a pvr_sync
 * timeline.
 */
static const struct file_operations pvr_sync_fops;


void pvr_sync_get_updates(const struct pvr_sync_append_data *sync_data,
	u32 *nr_fences, struct _RGXFWIF_DEV_VIRTADDR_ **ufo_addrs, u32 **values)
{
	pr_err("pvr_sync2: %s: SHOULD NOT HAVE BEEN CALLED!!!\n", __func__);
	*nr_fences = sync_data->nr_updates;
	*ufo_addrs = sync_data->update_ufo_addresses;
	*values = sync_data->update_values;
}

void pvr_sync_get_checks(const struct pvr_sync_append_data *sync_data,
	u32 *nr_fences, struct _RGXFWIF_DEV_VIRTADDR_ **ufo_addrs, u32 **values)
{
	pr_err("pvr_sync2: %s: SHOULD NOT HAVE BEEN CALLED!!!\n", __func__);
	*nr_fences = sync_data->nr_checks;
	*ufo_addrs = sync_data->check_ufo_addresses;
	*values = sync_data->check_values;
}

void pvr_sync_rollback_append_fences(struct pvr_sync_append_data *sync_data)
{
#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
	u32 i;
#endif

	pr_err("pvr_sync2: %s: SHOULD NOT HAVE BEEN CALLED!!!\n", __func__);
	if (!sync_data)
		return;

#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
	for (i = 0; i < sync_data->nr_cleanup_syncs; i++) {
		struct pvr_sync_native_sync_prim *cleanup_sync =
			sync_data->cleanup_syncs[i];

		/* If this cleanup was called on a partially-created data set
		 * it's possible to have NULL cleanup sync pointers.
		 */
		if (!cleanup_sync)
			continue;
		cleanup_sync->next_value--;
	}
#endif
	/* If there was an update, rollback the next values taken on the
	 * fence and timeline. This must be done before the sync_fence_put()
	 * as that may free the corresponding fence.
	 */

	if (sync_data->update_sync) {
		sync_data->update_sync = NULL;
	}

	if (sync_data->update_timeline_sync) {
		BUG_ON(sync_data->update_timeline_sync->next_value == 0);
		sync_data->update_timeline_sync->next_value--;
		sync_data->update_timeline_sync = NULL;
	}
}

int pvr_sync_get_update_fd(struct pvr_sync_append_data *sync_data)
{
	int fd = -EINVAL;

	pr_err("pvr_sync2: %s: SHOULD NOT HAVE BEEN CALLED!!!\n", __func__);
	if (!sync_data || !sync_data->update_fence ||
		sync_data->update_fence_fd < 0)
		goto err_out;

	fd = sync_data->update_fence_fd;
	sync_data->update_fence_fd = -1;

	sync_fence_install(sync_data->update_fence, fd);

	/* Note: It is invalid for an FD to have been installed on the update
	 * fence then fput called - as this would leave a dangling reference
	 * in the FD table. Set it to NULL so the free_append_fences_data()
	 * call doesn't fput it.
	 */
	sync_data->update_fence = NULL;

err_out:
	return fd;
}

void pvr_sync_free_append_fences_data(struct pvr_sync_append_data *sync_data)
{
	pr_err("pvr_sync2: %s: SHOULD NOT HAVE BEEN CALLED!!!\n", __func__);
	if (!sync_data)
		return;

	if (sync_data->check_fence)
		sync_fence_put(sync_data->check_fence);

	if (sync_data->update_fence)
		sync_fence_put(sync_data->update_fence);

	if (sync_data->update_fence_fd >= 0)
	{
		pr_err("pvr_sync2: %s: putting fd %d back to unused\n",__func__, sync_data->update_fence_fd);
		put_unused_fd(sync_data->update_fence_fd);
	}

	kfree(sync_data->update_ufo_addresses);
	kfree(sync_data->update_values);
	kfree(sync_data->check_ufo_addresses);
	kfree(sync_data->check_values);
#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
	kfree(sync_data->cleanup_syncs);
#endif
	kfree(sync_data);
}

void pvr_sync_nohw_complete_fences(struct pvr_sync_append_data *sync_data)
{
#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
	u32 i;
#endif

	if (!sync_data)
		return;

#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
	for (i = 0; i < sync_data->nr_cleanup_syncs; i++) {
		struct pvr_sync_native_sync_prim *cleanup_sync =
			sync_data->cleanup_syncs[i];

		if (!cleanup_sync)
			continue;

		complete_sync_prim(cleanup_sync);
	}
#endif

	if (sync_data->update_sync)
		complete_sync_checkpoint(sync_data->update_sync);
	if (sync_data->update_timeline_sync)
		complete_sync_prim(sync_data->update_timeline_sync);

	pvr_sync_update_all_timelines(NULL);
}

/* ioctl and fops handling */

static int pvr_sync_open(struct inode *inode, struct file *file)
{
	struct pvr_sync_timeline_wrapper *timeline_wrapper;
	struct pvr_sync_timeline *timeline;
	char task_comm[TASK_COMM_LEN];
	int err = -ENOMEM;

	get_task_comm(task_comm, current);

	timeline_wrapper = (struct pvr_sync_timeline_wrapper *)
		sync_timeline_create(&pvr_sync_timeline_ops,
			sizeof(*timeline_wrapper), task_comm);
	if (!timeline_wrapper) {
		pr_err("pvr_sync2: %s: sync_timeline_create failed\n", __func__);
		goto err_out;
	}

	timeline = kmalloc(sizeof(*timeline), GFP_KERNEL);
	if (!timeline) {
		pr_err("pvr_sync2: %s: Out of memory\n", __func__);
		goto err_free_timeline_wrapper;
	}

	timeline->kernel = kzalloc(sizeof(*timeline->kernel),
				   GFP_KERNEL);
	if (!timeline->kernel) {
		pr_err("pvr_sync2: %s: Out of memory\n", __func__);
		goto err_free_timeline;
	}

	timeline_wrapper->timeline = timeline;

	timeline->obj = &timeline_wrapper->obj;
	kref_init(&timeline->kref);

	mutex_lock(&timeline_list_mutex);
	list_add_tail(&timeline->list, &timeline_list);
	mutex_unlock(&timeline_list_mutex);

	DPF("%s: # %s", __func__, debug_info_timeline(timeline));

	file->private_data = timeline_wrapper;
	err = 0;
err_out:
	return err;

err_free_timeline:
	kfree(timeline);

	/* Use a NULL timeline to detect this partially-setup timeline in the
	 * timeline release function (called by sync_timeline_destroy) and
	 * handle it appropriately.
	 */
	timeline_wrapper->timeline = NULL;
err_free_timeline_wrapper:
	sync_timeline_destroy(&timeline_wrapper->obj);
	goto err_out;
}

static int pvr_sync_close(struct inode *inode, struct file *file)
{
	struct sync_timeline *obj = file->private_data;

	if (is_pvr_timeline(obj)) {
		DPF("%s: # %s", __func__,
		    debug_info_timeline(get_timeline(obj)));
	}

	sync_timeline_destroy(obj);
	return 0;
}

enum PVRSRV_ERROR pvr_sync_finalise_fence (PVRSRV_FENCE fence_fd, void *finalise_data)
{
	struct sync_fence *native_fence = (struct sync_fence *)finalise_data;

	if (!native_fence || (fence_fd < 0))
	{
		return PVRSRV_ERROR_INVALID_PARAMS;
	}
	sync_fence_install(native_fence, fence_fd);
	return PVRSRV_OK;
}

enum PVRSRV_ERROR pvr_sync_create_fence (const char *fence_name,
		PVRSRV_TIMELINE new_fence_timeline,
		PSYNC_CHECKPOINT_CONTEXT psSyncCheckpointContext,
		PVRSRV_FENCE *new_fence,
		u32 *fence_uid,
		void **fence_finalise_data,
		PSYNC_CHECKPOINT *new_checkpoint_handle,
		void **timeline_update_sync,
		__u32 *timeline_update_value)
{
	PVRSRV_ERROR err = PVRSRV_OK;
	PVRSRV_FENCE new_fence_fd = -1;
	struct file *timeline_file;
	struct pvr_sync_timeline *timeline;
	struct pvr_sync_pt *native_sync_point = NULL;
	struct sync_fence *native_fence = NULL;
	struct pvr_sync_kernel_pair *sync_kernel;

	//pr_err("pvr_sync2: %s: Entry, fence_name=%s, new_fence_timeline=%d, new_fence=<%p>, fence_finalise_data=<%p>, new_checkpoint_handle=<%p>\n",
	//	__func__, fence_name, new_fence_timeline, (void*)new_fence, (void*)fence_finalise_data, (void*)new_checkpoint_handle);
	if (new_fence_timeline < 0 || !new_fence || !new_checkpoint_handle || !fence_finalise_data) {
		err =  PVRSRV_ERROR_INVALID_PARAMS;
		goto err_out;
	}

	/* We reserve the new fence FD before taking any operations
	 * as we do not want to fail (e.g. run out of FDs)
	 */
	new_fence_fd = get_unused_fd();
	if (new_fence_fd < 0) {
		//pr_err("pvr_sync2: %s: unable to obtain an fd for new_fence\n",__func__);
		err = PVRSRV_ERROR_OUT_OF_MEMORY;
		goto err_out;
	}
	//pr_err("pvr_sync2: %s: obtained fd for new_fence = %d\n",__func__, new_fence_fd);

	//pr_err("pvr_sync2: %s: accessing timeline (%d) for new_fence\n",__func__, new_fence_timeline);

	timeline_file = fget(new_fence_timeline);
	if (!timeline_file) {
		pr_err("pvr_sync2: %s: Failed to open supplied timeline fd (%d)\n",
			__func__, new_fence_timeline);
		err = PVRSRV_ERROR_HANDLE_NOT_FOUND;
		goto err_put_fd;
	}

	//pr_err("pvr_sync2: %s: validating timeline \n",__func__);
	if (timeline_file->f_op != &pvr_sync_fops) {
		pr_err("pvr_sync2: %s: Supplied timeline not pvr_sync timeline\n",
			__func__);
		err = PVRSRV_ERROR_INVALID_PARAMS;
		goto err_put_timeline;
	}

	//pr_err("pvr_sync2: %s: getting timeline private data\n",__func__);
	timeline = get_timeline(timeline_file->private_data);

	/* We know this will not free the timeline as the user still
	 * has the fd referencing it.
	 */
	fput(timeline_file);

	if (!timeline) {
		pr_err("pvr_sync2: %s: Supplied timeline has no private data\n",
			__func__);
		err = PVRSRV_ERROR_HANDLE_NOT_FOUND;
		goto err_put_fd;
	}

	/* Check if this timeline already has a sync prim, if not create it now */
	if (!timeline->kernel->fence_sync) {
		err = sync_pool_get(&timeline->kernel->fence_sync,
							timeline->obj->name,
							SYNC_TL_TYPE);

		if (err != PVRSRV_OK) {
			pr_err("pvr_sync2: %s: Failed to allocate timeline sync prim (%s)\n",
							__func__, PVRSRVGetErrorStringKM(err));
			err = PVRSRV_ERROR_OUT_OF_MEMORY;
			goto err_put_fd;
		}
	}

	//pr_err("pvr_sync2: %s: creating native_sync_point on timeline %d <%p>, using sync checkpoint context <%p>\n",__func__, new_fence_timeline, (void*)timeline, (void*)psSyncCheckpointContext);
	native_sync_point = pvr_sync_create_pt(timeline, new_fence_timeline, psSyncCheckpointContext);
	if (!native_sync_point) {
		pr_err("pvr_sync2: %s: Failed to create sync point\n",
			__func__);
		err = PVRSRV_ERROR_OUT_OF_MEMORY;
		goto err_put_fd;
	}

	//pr_err("pvr_sync2: %s: creating native_fence containing the new native_sync_point\n",__func__);
#if defined(CHROMIUMOS_KERNEL) && (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
	native_fence = sync_fence_create(fence_name, &native_sync_point->pt.base);
#else
	native_fence = sync_fence_create(fence_name, &native_sync_point->pt);
#endif
	if (!native_fence) {
		struct pvr_sync_native_sync_prim *timeline_prim =
			timeline->kernel->fence_sync;

		pr_err("pvr_sync2: %s: Failed to create sync fence\n",
			__func__);
		err = PVRSRV_ERROR_OUT_OF_MEMORY;

		/* If the point was created but the fence failed to be
		 * created, the point must be manually freed as a
		 * fence has not yet taken ownership.
		 */
		timeline_prim->next_value--;
		/* Error the new fence's sync checkpoint (so the deferred free considers it 'met') */
		error_sync_checkpoint(native_sync_point->sync_data->kernel->fence_sync);
		pvr_sync_free_sync(&native_sync_point->pt);
		goto err_put_fd;
	}

	//pr_err("pvr_sync2: %s: native_fence=<%p>\n",__func__, (void*)native_fence);
	//pr_err("pvr_sync2: %s: native_sync_point=<%p>\n",__func__, (void*)native_sync_point);
	//pr_err("pvr_sync2: %s: native_sync_point->sync_data=<%p>\n",__func__, (void*)native_sync_point->sync_data);
	//pr_err("pvr_sync2: %s: native_sync_point->sync_data->kernel=<%p>\n",__func__, (void*)native_sync_point->sync_data->kernel);
	sync_kernel = native_sync_point->sync_data->kernel;

	//pr_err("pvr_sync2: %s: installing native_fence<%p> to new_fence_fd (%d)\n",__func__, (void*)native_fence, new_fence_fd);
	/* For Linux, we do not return the fence fd here, but via
	 * pvr_sync_finalise_fence() - this is because once we
	 * associate the fd with the fence, it can only be closed
	 * from client code so it should only be done once we
	 * know we will definitely require it.
	 */
	*new_fence = new_fence_fd;
	*fence_finalise_data = (void*)native_fence;
	//pr_err("pvr_sync2: %s: sync_kernel->fence_sync=<%p>\n",__func__, (void*)sync_kernel->fence_sync);
	//pr_err("pvr_sync2: %s: returning sync_kernel->fence_sync->client_sync_checkpoint=<%p>\n",__func__, (void*)sync_kernel->fence_sync->client_sync_checkpoint);
	//pr_err("pvr_sync2: %s: returning sync_kernel->fence_sync->client_sync_checkpoint in new_checkpoint_handle parameter\n",__func__);
	*new_checkpoint_handle = sync_kernel->fence_sync->client_sync_checkpoint;

	//pr_err("pvr_sync2: %s: timeline_update_sync=<%p>, timeline_update_value=<%p>\n",__func__, (void*)timeline_update_sync, (void*)timeline_update_value);
	if(timeline_update_sync && timeline_update_value)
	{
		*timeline_update_sync = (void*)timeline->kernel->fence_sync->client_sync;
		//pr_err("pvr_sync2: %s: *timeline_update_sync=<%p>\n",__func__, (void*)*timeline_update_sync);
		*timeline_update_value = timeline->kernel->fence_sync->next_value;
		//pr_err("pvr_sync2: %s: *timeline_update_value=0x%x\n",__func__, *timeline_update_value);
	}

	*fence_uid = new_fence_fd; /* TODO FDs are not unique! */

	goto err_out;

err_put_timeline:
	fput(timeline_file);
err_put_fd:
	pr_err("pvr_sync2: %s: putting fd %d back to unused\n",__func__, new_fence_fd);
	put_unused_fd(new_fence_fd);
	*fence_uid = PVRSRV_FENCE_INVALID;
err_out:
	return err;
}

enum PVRSRV_ERROR pvr_sync_rollback_fence_data(PVRSRV_FENCE fence_to_rollback, void *fence_data_to_rollback)
{
	PVRSRV_ERROR err = PVRSRV_OK;
	struct sync_fence *sync_fence = (struct sync_fence *)fence_data_to_rollback;
	struct sync_pt *sync_pt;
	struct pvr_sync_pt *pvr_pt = NULL;
	int j;

	if (!sync_fence) {
		pr_err("pvr_sync2: %s: Failed to recognise fence_to_rollback(%d)\n", __func__, fence_to_rollback);
		err = PVRSRV_ERROR_INVALID_PARAMS;
		goto err_out;
	}

	(void)j;
	for_each_sync_pt(sync_pt, sync_fence, j) {
		if (!is_pvr_timeline_pt(sync_pt)) {
			pr_err("pvr_sync2: %s: Fence(%d) contains non-pvr timeline sync_pt\n", __func__, fence_to_rollback);
			err = PVRSRV_ERROR_INVALID_PARAMS;
			goto err_out2;
		}

		pvr_pt = (struct pvr_sync_pt *)sync_pt;

		//pr_err("pvr_sync2: %s marking sync checkpoint<%p> as errored, before we destroy the fence\n", __func__, (void*)pvr_pt->sync_data->kernel->fence_sync->client_sync_checkpoint);
		SyncCheckpointError(pvr_pt->sync_data->kernel->fence_sync->client_sync_checkpoint);

		/* rollback timeline next_value */
		//pr_err("pvr_sync2: %s called for fence %d. Rolling back timeline<%p> (%d->%d)\n", __func__, fence_to_rollback, (void*)pvr_pt->timeline, pvr_pt->timeline->kernel->fence_sync->next_value, pvr_pt->timeline->kernel->fence_sync->next_value-1);
		pvr_pt->timeline->kernel->fence_sync->next_value--;
	}

	/* close the fence */
	sync_fence_put(sync_fence);

err_out2:
	put_unused_fd(fence_to_rollback);

err_out:
	return err;
}

enum PVRSRV_ERROR pvr_sync_resolve_fence(PSYNC_CHECKPOINT_CONTEXT psSyncCheckpointContext, PVRSRV_FENCE fence_to_resolve, u32 *nr_checkpoints, PSYNC_CHECKPOINT **checkpoint_handles, u32 *fence_uid)
{
	PVRSRV_ERROR err = PVRSRV_OK;

	//pr_err("pvr_sync2: %s: called, fence_to_resolve=%d, return param ptrs: nr_checkpoints<%p>, checkpoint_handles<%p>\n",__func__, fence_to_resolve, (void*)nr_checkpoints, (void*)checkpoint_handles);
	if (!nr_checkpoints || !checkpoint_handles) {
		err =  PVRSRV_ERROR_INVALID_PARAMS;
		goto err_out;
	}

	if (fence_to_resolve < 0) {
		//pr_err("pvr_sync2: %s: null fence passed(%d), returning 0 checkpoints\n",__func__, fence_to_resolve);
		/* Null fence passed, so return 0 checkpoints */
		*nr_checkpoints = 0;
		*checkpoint_handles = NULL;
		*fence_uid = 0;
	}
	else
	{
		struct sync_fence *sync_fence = sync_fence_fdget(fence_to_resolve);
		struct sync_pt *sync_pt;
		struct pvr_sync_kernel_pair *sync_kernel;
		u32 points_on_fence = 0;
		PSYNC_CHECKPOINT foreign_checkpoint = NULL;
		PSYNC_CHECKPOINT *next_checkpoint;
		int j;

		//pr_err("pvr_sync: %s: resolving fence (sync_fence=<%p>)...\n",__func__, (void*)sync_fence);
		if (!sync_fence) {
			pr_err("pvr_sync2: %s: Failed to read sync private data for fd %d\n",
				__func__, fence_to_resolve);
			err = PVRSRV_ERROR_HANDLE_NOT_FOUND;
			goto err_out;
		}

		/* Alloc memory to hold list of PSYNC_CHECKPOINTs */
		/* (Alloc memory for 32 sync checkpoint handles) */
		//pr_err("pvr_sync2: %s: allocating memory for 32 PSYNC_CHECKPOINTs...\n",__func__);
		*checkpoint_handles = (PSYNC_CHECKPOINT*)kmalloc((sizeof(PSYNC_CHECKPOINT) * 32), GFP_KERNEL);
		if (!(*checkpoint_handles)) {
			pr_err("pvr_sync2: %s: Failed to alloc memory for returned list of sync checkpoints\n",
				__func__);
			err = PVRSRV_ERROR_OUT_OF_MEMORY;
			goto err_out2;
		}
		//pr_err("pvr_sync2: %s: ...done <%p>\n",__func__, *checkpoint_handles);

		next_checkpoint = (PSYNC_CHECKPOINT*)*checkpoint_handles;

		(void)j;
		for_each_sync_pt(sync_pt, sync_fence, j) {
			struct pvr_sync_pt *pvr_pt = NULL;
			bool is_foreign_sync_pt = false;
			bool add_foreign_sync = false;

			//pr_err("pvr_sync2: %s:  parsing sync_pt<%p>\n",__func__, (void*)sync_pt);
			if (!is_pvr_timeline_pt(sync_pt)) {
				//pr_err("pvr_sync2: %s:   sync_pt=<%p> is not from a pvr timeline\n",__func__, (void*)sync_pt);
				is_foreign_sync_pt = true;
				//pr_err("pvr_sync2: %s:   sync_pt=<%p> is foreign - creating waiter...\n",__func__, (void*)sync_pt);
				foreign_checkpoint = pvr_sync_create_waiter_for_foreign_sync(fence_to_resolve, psSyncCheckpointContext);
				add_foreign_sync = true;
				//pr_err("pvr_sync2: %s:   ...done, foreign_sync_kernel=<%p>\n",__func__, (void*)foreign_sync_kernel);
			}

			//pr_err("pvr_sync2: %s: @ Line %d\n",__func__, __LINE__);
			if (!is_foreign_sync_pt) {
				pvr_pt = (struct pvr_sync_pt *)sync_pt;
				//pr_err("pvr_sync2: %s:   pvr_pt=<%p>\n",__func__, (void*)pvr_pt);
				//pr_err("pvr_sync2: %s:   pvr_pt->sync_data=<%p>\n",__func__, (void*)pvr_pt->sync_data);
				//pr_err("pvr_sync2: %s:   pvr_pt->sync_data->kernel=<%p>\n",__func__, (void*)pvr_pt->sync_data->kernel);
				sync_kernel = pvr_pt->sync_data->kernel;

				//pr_err("pvr_sync2: %s: calling is_sync_checkpoint_met\n",__func__);
				if (!sync_kernel ||
					is_sync_checkpoint_met(sync_kernel->fence_sync)) {
					//pr_err("pvr_sync2: %s: sync_pt (skipped as no checkpoint or checkpoint is already met)...\n",__func__);
					continue;
				}

				//pr_err("pvr_sync2: %s: @ Line %d\n",__func__, __LINE__);

				//pr_err("pvr_sync2: %s: ...next_checkpoint = <%p>\n",__func__, (void*)next_checkpoint);

				/* Take ref on sync_checkpoint - this will be dropped by the caller
				 * (Kick code) once it has incremented the checkpoint's CCB enqueued count.
				 * We only really need to do this for foreign sync checkpoints, to prevent
				 * the sync_checkpoint from being destroyed if it gets signalled while being
				 * processed by the Kick code, but the Kick code has no knowledge of whether a
				 * sync_checkpoint is foreign, so we take a ref on all checkpoints.
				 */
				SyncCheckpointTakeRef(sync_kernel->fence_sync->client_sync_checkpoint);

				*next_checkpoint = sync_kernel->fence_sync->client_sync_checkpoint;
				next_checkpoint++;
				points_on_fence++;
				//pr_err("pvr_sync2: %s: fence contains sync checkpoint<%p>\n",__func__, (void*)sync_kernel->fence_sync->client_sync_checkpoint);
				//pr_err("pvr_sync2: %s: increment points_on_fence (now %d)\n",__func__, points_on_fence);
			}
			else {
				//pr_err("pvr_sync2: %s: skipping rest of loop as a foreign sync pt\n",__func__);
				if (foreign_checkpoint && add_foreign_sync) {
					//pr_err("pvr_sync2: %s: ...next_checkpoint (fs) = <%p>\n",__func__, (void*)foreign_sync_kernel->fence_sync->client_sync_checkpoint);//next_checkpoint);
					/* Take ref on sync_checkpoint - this will be dropped by the caller
					 * (see comment for the other call to SyncCheckpointTakeRef, above).
					 */
					/* For foreign points, an extra
					 * checkpoint reference was taken at
					 * creation time to ensure it wasn't
					 * completed and free'd before we got
					 * here, so ownership of that reference
					 * is effectively passed to the firmware
					 */
					*next_checkpoint = foreign_checkpoint;
					next_checkpoint++;
					points_on_fence++;
				}
			}
		}

		if (0)
		{
			int ii;

			pr_err("pvr_sync2: %s: returning nr_checkpoints=%d\n",__func__, points_on_fence);
			for (ii=0; ii<points_on_fence; ii++)
			{
				PSYNC_CHECKPOINT *psTmp = *(checkpoint_handles + ii);
				pr_err("pvr_sync2: %s:   pt %d: sync checkpoint <%p>,\n",__func__, ii, (void*)psTmp);
				pr_err("pvr_sync2: %s:          ID=%d\n",__func__, SyncCheckpointGetId(*psTmp));
			}
		}
		*nr_checkpoints = points_on_fence;
		*fence_uid = fence_to_resolve; /* TODO FDs are not really unique! */

err_out2:
		sync_fence_put(sync_fence);
	}

err_out:
	return err;
}

static long pvr_sync_ioctl_rename(struct pvr_sync_timeline *timeline,
	void __user *user_data)
{
	int err = 0;
	struct pvr_sync_rename_ioctl_data data;

	if (!access_ok(user_data, sizeof(data))) {
		err = -EFAULT;
		goto err;
	}

	if (copy_from_user(&data, user_data, sizeof(data))) {
		err = -EFAULT;
		goto err;
	}

	data.szName[sizeof(data.szName) - 1] = '\0';
	strlcpy(timeline->obj->name, data.szName, sizeof(timeline->obj->name));
err:
	return err;
}

#ifndef CONFIG_SW_SYNC_USER

static long pvr_sync_ioctl_force_sw_only(struct pvr_sync_timeline *timeline,
	void **private_data)
{
	struct sw_sync_timeline *sw_sync_timeline;

	/* We can only convert an empty GPU timeline */
	if (timeline->kernel->fence_sync &&
			timeline->kernel->fence_sync->next_value)
		return -EFAULT;

	/* Create a sw_sync timeline with the old GPU timeline's name */
	sw_sync_timeline = sw_sync_timeline_create(timeline->obj->name);
	if (!sw_sync_timeline)
		return -ENOMEM;

	/* Destroy the old GPU timeline and update the struct file */
	DPF("%s: # %s", __func__, debug_info_timeline(timeline));

	sync_timeline_destroy(timeline->obj);
	*private_data = sw_sync_timeline;
	return 0;
}

static long pvr_sync_ioctl_sw_create_fence(struct sw_sync_timeline *timeline,
	void __user *user_data)
{
	struct sw_sync_create_fence_data data;
	struct sync_fence *fence;
	int fd = get_unused_fd();
	struct sync_pt *sync_pt;
	int err = -EFAULT;

	if (fd < 0) {
		pr_err("pvr_sync2: %s: Failed to find unused fd (%d)\n",
		       __func__, fd);
		goto err_out;
	}

	if (copy_from_user(&data, user_data, sizeof(data)))
		goto err_put_fd;

	sync_pt = sw_sync_pt_create(timeline, data.value);
	if (!sync_pt) {
		pr_err("pvr_sync2: %s: Failed to create a sync point (%d)\n",
		       __func__, fd);
		err = -ENOMEM;
		goto err_put_fd;
	}

	data.name[sizeof(data.name) - 1] = '\0';
#if defined(CHROMIUMOS_KERNEL) && (LINUX_VERSION_CODE < KERNEL_VERSION(4, 4, 0))
	fence = sync_fence_create(data.name, &sync_pt->base);
#else
	fence = sync_fence_create(data.name, sync_pt);
#endif
	if (!fence) {
		pr_err("pvr_sync2: %s: Failed to create a fence (%d)\n",
		       __func__, fd);
		sync_pt_free(sync_pt);
		err = -ENOMEM;
		goto err_put_fd;
	}

	data.fence = fd;

	if (copy_to_user(user_data, &data, sizeof(data)))
		goto err_put_fence;

	sync_fence_install(fence, fd);
	err = 0;
err_out:
	return err;
err_put_fence:
	sync_fence_put(fence);
err_put_fd:
	pr_err("pvr_sync2: %s: putting fd %d back to unused\n",__func__, fd);
	put_unused_fd(fd);
	goto err_out;
}

static long pvr_sync_ioctl_sw_inc(struct sw_sync_timeline *timeline,
	void __user *user_data)
{
	u32 value;

	if (copy_from_user(&value, user_data, sizeof(value)))
		return -EFAULT;

	sw_sync_timeline_inc(timeline, value);
	return 0;
}

#endif /* !CONFIG_SW_SYNC_USER */

static long
pvr_sync_ioctl(struct file *file, unsigned int cmd, unsigned long __user arg)
{
	struct sync_timeline *obj = file->private_data;
	void __user *user_data = (void __user *)arg;
	long err = -ENOTTY;

	if (is_pvr_timeline(obj)) {
		struct pvr_sync_timeline *pvr = get_timeline(obj);

		switch (cmd) {
		case PVR_SYNC_IOC_RENAME:
			err = pvr_sync_ioctl_rename(pvr, user_data);
			break;
#ifndef CONFIG_SW_SYNC_USER
		case PVR_SYNC_IOC_FORCE_SW_ONLY:
			err = pvr_sync_ioctl_force_sw_only(pvr,
				&file->private_data);
			break;
#endif /* !CONFIG_SW_SYNC_USER */
		default:
			break;
		}
	} else {
#ifndef CONFIG_SW_SYNC_USER
		struct sw_sync_timeline *sw = file->private_data;

		switch (cmd) {
		case SW_SYNC_IOC_CREATE_FENCE:
			err = pvr_sync_ioctl_sw_create_fence(sw, user_data);
			break;
		case SW_SYNC_IOC_INC:
			err = pvr_sync_ioctl_sw_inc(sw, user_data);
			break;
		default:
			break;
		}
#endif /* !CONFIG_SW_SYNC_USER */
	}

	return err;
}

static void
pvr_sync_check_status_work_queue_function(struct work_struct *data)
{
	/* A completed SW operation may un-block the GPU */
	PVRSRVCheckStatus(NULL);
}

/* Returns true if the freelist still has entries, else false if empty */
static bool
pvr_sync_clean_freelist(void)
{
	struct pvr_sync_kernel_pair *kernel, *k;
	struct pvr_sync_timeline_kernel_pair *tl_kernel, *tl_k;
	struct pvr_sync_fence *sync_fence, *f;
	LIST_HEAD(unlocked_free_checkpoint_list);
	LIST_HEAD(unlocked_free_timeline_list);
	LIST_HEAD(unlocked_free_list);
	unsigned long flags;
	bool freelist_empty;

	/* We can't call PVRSRVServerSyncFreeKM directly in this loop because
	 * that will take the mmap mutex. We can't take mutexes while we have
	 * this list locked with a spinlock. So move all the items we want to
	 * free to another, local list (no locking required) and process it
	 * in a second loop.
	 */

	spin_lock_irqsave(&sync_checkpoint_free_list_spinlock, flags);
	list_for_each_entry_safe(kernel, k, &sync_checkpoint_free_list, list) {
		/* Check if this sync is not used anymore. */
#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
		if (kernel->fence_sync && !is_sync_checkpoint_met(kernel->fence_sync) ||
		    (kernel->cleanup_sync &&
		     !is_sync_prim_met(kernel->cleanup_sync))) {
#else
		if ((kernel->fence_sync) && !is_sync_checkpoint_met(kernel->fence_sync)) {
#endif
			continue;
		}

		/* Remove the entry from the free list. */
		list_move_tail(&kernel->list, &unlocked_free_checkpoint_list);
	}

	/* Wait and loop if there are still syncs on the free list (IE
	 * are still in use by the HW).
	 */
	freelist_empty = list_empty(&sync_checkpoint_free_list);

	spin_unlock_irqrestore(&sync_checkpoint_free_list_spinlock, flags);

	spin_lock_irqsave(&timeline_free_list_spinlock, flags);
	list_for_each_entry_safe(tl_kernel, tl_k, &timeline_free_list, list) {
		/* Check if this sync is not used anymore. */
		if (tl_kernel->fence_sync && !is_sync_prim_met(tl_kernel->fence_sync))
			continue;

		/* Remove the entry from the free list. */
		list_move_tail(&tl_kernel->list, &unlocked_free_timeline_list);
	}

	/* Wait and loop if there are still syncs on the free list (IE
	 * are still in use by the HW).
	 */
	freelist_empty &= list_empty(&timeline_free_list);

	spin_unlock_irqrestore(&timeline_free_list_spinlock, flags);

#if defined(PVRSRV_USE_BRIDGE_LOCK)
	OSAcquireBridgeLock();
#endif

	list_for_each_entry_safe(kernel, k, &unlocked_free_checkpoint_list, list) {
		list_del(&kernel->list);

		if (kernel->fence_sync && kernel->fence_sync->client_sync_checkpoint)
		{
			//pr_err("pvr_sync2: %s:   Freeing sync checkpoint <%p>\n", __func__, (void*)kernel->fence_sync->client_sync_checkpoint);
			SyncCheckpointFree(kernel->fence_sync->client_sync_checkpoint);
			kernel->fence_sync->client_sync_checkpoint = NULL;
		}
		kfree(kernel->fence_sync);
#if defined(PVR_SYNC_CHECKPOINTS_NEED_CLEANUP_SYNC)
		if (kernel->cleanup_sync)
			sync_pool_put(kernel->cleanup_sync);
#endif
		kfree(kernel);
	}

	list_for_each_entry_safe(tl_kernel, tl_k, &unlocked_free_timeline_list, list) {
		list_del(&tl_kernel->list);

		if(tl_kernel->fence_sync)
			sync_pool_put(tl_kernel->fence_sync);
		kfree(tl_kernel);
	}

#if defined(PVRSRV_USE_BRIDGE_LOCK)
	OSReleaseBridgeLock();
#endif
	/* sync_fence_put() must be called from process/WQ context
	 * because it uses fput(), which is not allowed to be called
	 * from interrupt context in kernels <3.6.
	 */
	INIT_LIST_HEAD(&unlocked_free_list);

	spin_lock_irqsave(&sync_fence_put_list_spinlock, flags);
	list_for_each_entry_safe(sync_fence, f, &sync_fence_put_list, list) {
	    list_move_tail(&sync_fence->list, &unlocked_free_list);
	}    
	spin_unlock_irqrestore(&sync_fence_put_list_spinlock, flags);

	list_for_each_entry_safe(sync_fence, f, &unlocked_free_list, list) {
	    list_del(&sync_fence->list);
	    sync_fence_put(sync_fence->fence);
	    kfree(sync_fence);
	}

	return !freelist_empty;
}

static void
pvr_sync_defer_free_work_queue_function(struct work_struct *data)
{
	enum PVRSRV_ERROR error = PVRSRV_OK;
	void *event_object;

	error = OSEventObjectOpen(pvr_sync_data.event_object_handle,
		&event_object);
	if (error != PVRSRV_OK) {
		pr_err("pvr_sync2: %s: Error opening event object (%s)\n",
			__func__, PVRSRVGetErrorStringKM(error));
		return;

	}

	while (pvr_sync_clean_freelist()) {

		//pr_err("pvr_sync2: %s: pvr_sync_clean_freelist still has entries, waiting for event_object <%p>\n",
		//	__func__, (void*)event_object);
		error = OSEventObjectWait(event_object);

		switch (error) {

		case PVRSRV_OK:
		case PVRSRV_ERROR_TIMEOUT:
			/* Timeout is normal behaviour */
			continue;
		default:
			pr_err("pvr_sync2: %s: Error waiting for event object (%s)\n",
				__func__, PVRSRVGetErrorStringKM(error));
			break;
		}
	}
	//pr_err("pvr_sync2: %s: closing event_object <%p>\n",__func__,(void*)event_object);
	error = OSEventObjectClose(event_object);
	if (error != PVRSRV_OK) {
		pr_err("pvr_sync2: %s: Error closing event object (%s)\n",
			__func__, PVRSRVGetErrorStringKM(error));
	}
}

static const struct file_operations pvr_sync_fops = {
	.owner          = THIS_MODULE,
	.open           = pvr_sync_open,
	.release        = pvr_sync_close,
	.unlocked_ioctl = pvr_sync_ioctl,
	.compat_ioctl   = pvr_sync_ioctl,
};

static struct miscdevice pvr_sync_device = {
	.minor          = MISC_DYNAMIC_MINOR,
	.name           = PVRSYNC_MODNAME,
	.fops           = &pvr_sync_fops,
};

static
void pvr_sync_free_checkpoint_list_mem(void *mem_ptr)
{
	kfree(mem_ptr);
}

static
void pvr_sync_update_all_timelines(void *command_complete_handle)
{
	struct pvr_sync_timeline *timeline, *n;

	mutex_lock(&timeline_list_mutex);

	list_for_each_entry(timeline, &timeline_list, list) {
		/* If a timeline is destroyed via pvr_sync_release_timeline()
		 * in parallel with a call to pvr_sync_update_all_timelines(),
		 * the timeline_list_mutex will block destruction of the
		 * 'timeline' pointer. Use kref_get_unless_zero() to detect
		 * and handle this race. Skip the timeline if it's being
		 * destroyed, blocked only on the timeline_list_mutex.
		 */
		timeline->valid =
			kref_get_unless_zero(&timeline->kref) ? true : false;
	}

	list_for_each_entry_safe(timeline, n, &timeline_list, list) {
		/* We know timeline is valid at this point because we're
		 * holding the list lock (so pvr_sync_destroy_timeline() has
		 * to wait).
		 */
		void *obj = timeline->obj;

		/* If we're racing with pvr_sync_release_timeline(), ignore */
		if (!timeline->valid)
			continue;

		/* If syncs have signaled on the GPU, echo this in pvr_sync.
		 *
		 * At this point we know the timeline is valid, but obj might
		 * have raced and been set to NULL. It's only important that
		 * we use NULL / non-NULL consistently with the if() and call
		 * to sync_timeline_signal() -- the timeline->obj can't be
		 * freed (pvr_sync_release_timeline() will be stuck waiting
		 * for the timeline_list_mutex) but it might have been made
		 * invalid by the base sync driver, in which case this call
		 * will bounce harmlessly.
		 */
		if (obj)
			sync_timeline_signal(obj);

		/* We're already holding the timeline_list_mutex */
		kref_put(&timeline->kref, pvr_sync_destroy_timeline_locked);
	}

	mutex_unlock(&timeline_list_mutex);
}

enum PVRSRV_ERROR pvr_sync_init(void *device_cookie)
{
	enum PVRSRV_ERROR error;
	int err;

	DPF("%s", __func__);

	atomic_set(&pvr_sync_data.sync_id, 0);

	error = PVRSRVAcquireGlobalEventObjectKM(
		&pvr_sync_data.event_object_handle);
	if (error != PVRSRV_OK) {
		pr_err("pvr_sync2: %s: Failed to acquire global event object (%s)\n",
			__func__, PVRSRVGetErrorStringKM(error));
		goto err_out;
	}

#if defined(PVRSRV_USE_BRIDGE_LOCK)
	OSAcquireBridgeLock();
#endif

	error = SyncPrimContextCreate(device_cookie,
				      &pvr_sync_data.sync_prim_context);
	if (error != PVRSRV_OK) {
		pr_err("pvr_sync2: %s: Failed to create sync prim context (%s)\n",
		       __func__, PVRSRVGetErrorStringKM(error));
#if defined(PVRSRV_USE_BRIDGE_LOCK)
		OSReleaseBridgeLock();
#endif
		goto err_release_event_object;
	}

#if defined(PVRSRV_USE_BRIDGE_LOCK)
	OSReleaseBridgeLock();
#endif

	/* Create the 'global' sync checkpoint context */
	error = SyncCheckpointContextCreate(device_cookie,
	                                    &pvr_sync_data.global_sync_checkpoint_context);
	if (error != PVRSRV_OK) {
		pr_err("pvr_sync2: %s: Failed to create global sync checkpoint context (%s)\n",
			   __func__, PVRSRVGetErrorStringKM(error));
		goto err_release_event_object;
	}

	/* Register the resolve fence and create fence functions with sync_checkpoint.c */
	SyncCheckpointRegisterFunctions(pvr_sync_resolve_fence,
	                                pvr_sync_create_fence,
	                                pvr_sync_rollback_fence_data,
	                                pvr_sync_finalise_fence,
	                                pvr_sync_update_all_timelines,
	                                pvr_sync_free_checkpoint_list_mem);

	pvr_sync_data.defer_free_wq =
		create_freezable_workqueue("pvr_sync_defer_free_workqueue");
	if (!pvr_sync_data.defer_free_wq) {
		pr_err("pvr_sync2: %s: Failed to create pvr_sync defer_free workqueue\n",
		       __func__);
		goto err_free_sync_context;
	}

	INIT_WORK(&pvr_sync_data.defer_free_work,
		pvr_sync_defer_free_work_queue_function);

	pvr_sync_data.check_status_wq =
		create_freezable_workqueue("pvr_sync_check_status_workqueue");
	if (!pvr_sync_data.check_status_wq) {
		pr_err("pvr_sync2: %s: Failed to create pvr_sync check_status workqueue\n",
		       __func__);
		goto err_destroy_defer_free_wq;
	}

	INIT_WORK(&pvr_sync_data.check_status_work,
		pvr_sync_check_status_work_queue_function);
	error = PVRSRVRegisterCmdCompleteNotify(
			&pvr_sync_data.command_complete_handle,
			&pvr_sync_update_all_timelines,
			&device_cookie);
	if (error != PVRSRV_OK) {
		pr_err("pvr_sync2: %s: Failed to register MISR notification (%s)\n",
		       __func__, PVRSRVGetErrorStringKM(error));
		goto err_destroy_status_wq;
	}

	error = PVRSRVRegisterDbgRequestNotify(
			&pvr_sync_data.debug_notify_handle,
			device_cookie,
			pvr_sync_debug_request,
			DEBUG_REQUEST_ANDROIDSYNC,
			NULL);
	if (error != PVRSRV_OK) {
		pr_err("pvr_sync2: %s: Failed to register debug notifier (%s)\n",
			__func__, PVRSRVGetErrorStringKM(error));
		goto err_unregister_cmd_complete;
	}

	err = misc_register(&pvr_sync_device);
	if (err) {
		pr_err("pvr_sync2: %s: Failed to register pvr_sync device (%d)\n",
		       __func__, err);
		error = PVRSRV_ERROR_RESOURCE_UNAVAILABLE;
		goto err_unregister_dbg;
	}

	error = PVRSRV_OK;
	return error;

err_unregister_dbg:
	PVRSRVUnregisterDbgRequestNotify(pvr_sync_data.debug_notify_handle);
err_unregister_cmd_complete:
	PVRSRVUnregisterCmdCompleteNotify(
		pvr_sync_data.command_complete_handle);
err_destroy_status_wq:
	destroy_workqueue(pvr_sync_data.check_status_wq);
err_destroy_defer_free_wq:
	destroy_workqueue(pvr_sync_data.defer_free_wq);
err_free_sync_context:
#if defined(PVRSRV_USE_BRIDGE_LOCK)
	OSAcquireBridgeLock();
#endif
	SyncPrimContextDestroy(pvr_sync_data.sync_prim_context);
	SyncCheckpointContextDestroy(pvr_sync_data.global_sync_checkpoint_context);
#if defined(PVRSRV_USE_BRIDGE_LOCK)
	OSReleaseBridgeLock();
#endif
err_release_event_object:
	PVRSRVReleaseGlobalEventObjectKM(pvr_sync_data.event_object_handle);
err_out:

	return error;
}

void pvr_sync_deinit(void)
{
	DPF("%s", __func__);

	misc_deregister(&pvr_sync_device);

	PVRSRVUnregisterDbgRequestNotify(pvr_sync_data.debug_notify_handle);

	PVRSRVUnregisterCmdCompleteNotify(
		pvr_sync_data.command_complete_handle);

	/* This will drain the workqueue, so we guarantee that all deferred
	 * syncs are free'd before returning.
	 */
	destroy_workqueue(pvr_sync_data.defer_free_wq);
	destroy_workqueue(pvr_sync_data.check_status_wq);

#if defined(PVRSRV_USE_BRIDGE_LOCK)
	OSAcquireBridgeLock();
#endif
	sync_pool_clear();

	SyncPrimContextDestroy(pvr_sync_data.sync_prim_context);

	SyncCheckpointContextDestroy(pvr_sync_data.global_sync_checkpoint_context);

#if defined(PVRSRV_USE_BRIDGE_LOCK)
	OSReleaseBridgeLock();
#endif

	PVRSRVReleaseGlobalEventObjectKM(pvr_sync_data.event_object_handle);
}
