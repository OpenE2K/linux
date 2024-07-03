/*
 * SPDX-License-Identifier: GPL-2.0 WITH Linux-syscall-note
 * Copyright (c) 2023 MCST
 */

#ifndef __MGA2_DRM_H__
#define __MGA2_DRM_H__

#include "drm.h"


#define DRM_MGA2_BCTRL			0x00	/* Add decriptor to BCTRL list */
#define DRM_MGA2_GEM_CREATE		0x01
#define DRM_MGA2_GEM_MMAP		0x02
#define DRM_MGA2_SYNC			0x03
#define DRM_MGA2_INFO			0x04
#define DRM_MGA2_AUC2			0x05	/* Add decriptor to AUC2 ring */
#define DRM_MGA2_GEM_CPU_PREP		0x06
#define DRM_MGA2_GEM_CPU_FINI		0x07
#define DRM_MGA2_VIRT_TO_HNDL		0x08

#define DRM_IOCTL_MGA2_BCTRL		DRM_IOW(DRM_COMMAND_BASE + DRM_MGA2_BCTRL, struct drm_mga2_bctrl)
#define DRM_IOCTL_MGA2_GEM_CREATE	DRM_IOWR(DRM_COMMAND_BASE + DRM_MGA2_GEM_CREATE, struct drm_mga2_gem_create)
#define DRM_IOCTL_MGA2_GEM_MMAP		DRM_IOWR(DRM_COMMAND_BASE + DRM_MGA2_GEM_MMAP, struct drm_mga2_gem_mmap)
#define DRM_IOCTL_MGA2_SYNC		DRM_IO(DRM_COMMAND_BASE + DRM_MGA2_SYNC)
#define DRM_IOCTL_MGA2_INFO		DRM_IOWR(DRM_COMMAND_BASE + DRM_MGA2_INFO, struct drm_mga2_info)
#define DRM_IOCTL_MGA2_AUC2		DRM_IOW(DRM_COMMAND_BASE + DRM_MGA2_AUC2, struct drm_mga2_bctrl)
#define DRM_IOCTL_MGA2_GEM_CPU_PREP	DRM_IOW(DRM_COMMAND_BASE + DRM_MGA2_GEM_CPU_PREP, struct drm_mga2_gem_cpu_prep)
#define DRM_IOCTL_MGA2_GEM_CPU_FINI	DRM_IOW(DRM_COMMAND_BASE + DRM_MGA2_GEM_CPU_FINI, struct drm_mga2_gem_cpu_fini)
#define DRM_IOCTL_MGA2_VIRT_TO_HNDL	DRM_IOW(DRM_COMMAND_BASE + DRM_MGA2_VIRT_TO_HNDL, struct drm_mga2_virt_to_hndl)

#define DRM_BCTRL_PAGES_NR	1

struct drm_mga2_bctrl {
	/* Ins */
	uint32_t	desc_handle;
	uint32_t	pad;
	uint64_t	buffers_ptr;
};

struct drm_mga2_buffers {
	uint16_t        nr;
	uint16_t        reltype; /* 0 - low half of addresss, 1 - high*/
	uint32_t	handle;
	uint32_t	offset[0];
};

#define MGA2_GEM_DOMAIN_CPU		0x1
#define MGA2_GEM_DOMAIN_VRAM		0x2

struct drm_mga2_gem_create {
	/* Ins */
	uint64_t	size;
	uint32_t	domain;
	/* Outs */
	uint32_t	handle;
};

struct drm_mga2_gem_mmap {
	/* Ins */
	/* Handle for the object being mapped. */
	uint32_t	handle;
	uint32_t	pad;
	/* Outs */
	/*
	 * Fake offset to use for subsequent mmap call
	 *
	 * This is a fixed-size type for 32/64 compatibility.
	 */
	uint64_t offset;
};

/* Input structure for the INFO ioctl */
struct drm_mga2_info {
	/* Where the return value will be stored */
	__u64 return_pointer;
	/* The size of the return value. Just like "size" in "snprintf",
	 * it limits how many bytes the kernel can write. */
	__u32 return_size;
	/* The query request id. */
	__u32 query;

	union {
		struct {
			__u32 _reserved[4];
		} _reserved;
	};
};

/* Query memory about VRAM and GTT domains */
#define MGA2_INFO_MEMORY			0x1

struct drm_mga2_heap_info {
	/** max. physical memory */
	__u64 total_heap_size;

	/** Theoretical max. available memory in the given heap */
	__u64 usable_heap_size;

	/**
	 * Number of bytes allocated in the heap. This includes all processes
	 * and private allocations in the kernel. It changes when new buffers
	 * are allocated, freed, and moved. It cannot be larger than
	 * heap_size.
	 */
	__u64 heap_usage;

	/**
	 * Theoretical possible max. size of buffer which
	 * could be allocated in the given heap
	 */
	__u64 max_allocation;
};

struct drm_mga2_memory_info {
	struct drm_mga2_heap_info vram;
	struct drm_mga2_heap_info cpu_accessible_vram;
	struct drm_mga2_heap_info gtt;
};

#define MGA2_GEM_CPU_PREP_READ		(1 << 0)
#define MGA2_GEM_CPU_PREP_WRITE		(1 << 1)
#define MGA2_GEM_CPU_PREP_NOWAIT	(1 << 2)

struct drm_mga2_gem_cpu_prep {
	uint32_t handle;	/* in */
	uint32_t flags;		/* in */
};

struct drm_mga2_gem_cpu_fini {
	uint32_t handle;	/* in */
	uint32_t pad;
};

struct drm_mga2_virt_to_hndl {
	uint64_t virt;		/* in */
	uint32_t rw;		/* in */
	uint32_t nr_pages;	/* in/out */
	uint32_t handle;	/* out */
	uint32_t pad;
};

#endif /*__MGA2_DRM_H__*/
