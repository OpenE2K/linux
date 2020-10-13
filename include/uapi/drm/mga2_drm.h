#ifndef __MGA2_DRM_H__
#define __MGA2_DRM_H__

#include "drm.h"


#define DRM_MGA2_BCTRL			0x00	/* Add decriptor to BCTRL list */
#define DRM_MGA2_GEM_CREATE		0x01
#define DRM_MGA2_GEM_MMAP		0x02
#define DRM_MGA2_SYNC			0x03

#define DRM_IOCTL_MGA2_BCTRL		DRM_IOW(DRM_COMMAND_BASE + DRM_MGA2_BCTRL, struct drm_mga2_bctrl)
#define DRM_IOCTL_MGA2_GEM_CREATE	DRM_IOWR(DRM_COMMAND_BASE + DRM_MGA2_GEM_CREATE, struct drm_mga2_gem_create)
#define DRM_IOCTL_MGA2_GEM_MMAP		DRM_IOWR(DRM_COMMAND_BASE + DRM_MGA2_GEM_MMAP, struct drm_mga2_gem_mmap)
#define DRM_IOCTL_MGA2_SYNC		DRM_IO(DRM_COMMAND_BASE + DRM_MGA2_SYNC)

#define DRM_BCTRL_PAGES_NR	1

struct drm_mga2_bctrl {
	/* Ins */
	uint32_t	desc_handle;
	uint32_t	pad;
	uint64_t	buffers_ptr;
};

struct drm_mga2_buffers {
	uint32_t	nr;
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

#endif /*__MGA2_DRM_H__*/
