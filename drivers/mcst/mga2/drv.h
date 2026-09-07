/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __MGA2_DRV_H__
#define __MGA2_DRV_H__

#include <linux/module.h>
#include <linux/console.h>
#include <linux/pagemap.h>
#include <linux/component.h>
#include <linux/pci.h>
#include <linux/dma-buf.h>
#include <linux/regmap.h>
#include <linux/genalloc.h>
#include <linux/async.h>
#include <linux/of.h>
#include <linux/of_address.h>
#include <linux/of_device.h>
#include <linux/of_irq.h>
#include <linux/irq.h>
#include <linux/circ_buf.h>
#include <linux/swiotlb.h>
#include <linux/clk.h>
#include <linux/clk-provider.h>

#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_gem.h>
#include <drm/drm_crtc.h>
#include <drm/drm_atomic.h>
#include <drm/drm_framebuffer.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_crtc_helper.h>
#include <drm/drm_plane_helper.h>
#include <drm/drm_atomic_helper.h>
#include <drm/drm_probe_helper.h>
#include <drm/drm_panel.h>
#include <drm/drm_of.h>
#include <drm/drm_flip_work.h>
#include <drm/drm_debugfs.h>
#include <drm/drm_fourcc.h>
#include <drm/drm_vblank.h>
#include <drm/drm_blend.h>
#include <drm/drm_edid.h>
#include <drm/drm_aperture.h>
#include <drm/drm_managed.h>
#include <drm/drm_gem_framebuffer_helper.h>
#include <drm/ttm/ttm_bo_driver.h>

#include <video/videomode.h>
#include <video/of_display_timing.h>

#include <uapi/drm/mga2_drm.h>

#include "regs.h"

#define  MGA2_MAX_CRTS_NR	3
#define  MGA2_ENCODER_NR	1
#define  MGA2_HDMI_NR		2
#define  MGA2_CONNECTOR_MAX_NR  4

#define MGA2_RING_SIZE 256

struct auc2_st;
struct bctrl;


struct mga2 {
	struct drm_device *drm;
	void __iomem *regs;
	struct regmap *regmap;

#define MGA2_BCTRL_OFF	(1 << 31)
	int flags;
	int dev_id;
	int irq, hwirq;
	int of_overlay_id;

	unsigned long vram_paddr;
	struct drm_mm vram_mm;
	struct mutex  vram_mu;

	struct mutex bctrl_mu;
	struct bctrl *bctrl;
	bool bctrl_active;
	dma_addr_t bctrl_dma;
	int head, tail;

	u64 *ring;
	dma_addr_t ring_dma;
	struct auc2_st *status;
	dma_addr_t status_dma;
	u64 *desc;
	dma_addr_t desc_dma;
	struct desc1 *desc1;
	dma_addr_t desc1_dma;
	struct desc0 *desc0_waiting;
	dma_addr_t desc0_waiting_dma;
	struct desc0 *desc0_interrupt;
	dma_addr_t desc0_interrupt_dma;
	struct dma_fence *mga2_fence[MGA2_RING_SIZE];
	spinlock_t fence_lock;
	unsigned fence_seqno;
	atomic_t ring_int;

	/* page-flip handling */
	struct drm_pending_vblank_event *event[MGA2_MAX_CRTS_NR];

	/* overlay properties */
	struct {
		struct drm_property *colorkey_min;
		struct drm_property *colorkey_max;
		uint64_t colorkey_min_val;
		uint64_t colorkey_max_val;
	} props;
};


int mga2_get_version(const struct device *dev);

struct mga2_gem_object {
	struct drm_gem_object base;
	struct drm_mm_node node;

	void *vaddr;
	dma_addr_t dma_addr;

	struct sg_table *sgt;
	struct page **pages;
	enum dma_data_direction dma_dir;
	/**
	 * @read_domains: Read memory domains.
	 *
	 * These monitor which caches contain read/write data related to the
	 * object. When transitioning from one set of domains to another,
	 * the driver is called to ensure that caches are suitably flushed and
	 * invalidated.
	 */
	u16 read_domains;

	/**
	 * @write_domain: Corresponding unique write memory domain.
	 */
	u16 write_domain;

	struct dma_resv resv;
	/**
	 * @hw_unref_time: The time, when the object can be safely freed.
	 */
	unsigned long hw_unref_time;
	/**
	 * @framedur_us: frame duration in us.
	 */
	unsigned long framedur_us;
};

#define to_mga2_gem(x)	container_of(x, struct mga2_gem_object, base)

int mga2fb_bctrl_init(struct mga2 *mga2);
int mga2fb_bctrl_hw_init(struct mga2 *mga2);

void mga2_init_desc0_interrupt(struct mga2 *mga2);

struct drm_gem_object *mga2_create_object(struct drm_device *dev, size_t size);

#define DRM_FILE_PAGE_OFFSET ((0xFFFFFFFUL >> PAGE_SHIFT) + 1)

struct drm_gem_object *mga2_gem_create(struct drm_device *dev, size_t size,
				       u32 domain);
struct drm_gem_object *mga2_gem_create_with_handle(struct drm_file *file,
						   struct drm_device *dev,
						   size_t size, u32 domain,
						   u32 *handle);

int mga2_dumb_create(struct drm_file *file_priv,
			    struct drm_device *drm,
			    struct drm_mode_create_dumb *args);
int mga2_gem_dumb_map_offset(struct drm_file *file, struct drm_device *dev,
			    u32 handle, u64 *offset);
struct drm_gem_object *mga2_prime_import_sg_table(struct drm_device *dev,
				     struct dma_buf_attachment *attach,
				     struct sg_table *sgt);

int mga2_mmap(struct file *filp, struct vm_area_struct *vma);


void mga2_update_ptr(struct mga2 *mga2);

int mga2_auc2_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int mga2_bctrl_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);

int mga2_gem_create_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *filp);
int mga2_gem_mmap_ioctl(struct drm_device *dev, void *data,
			struct drm_file *filp);
int mga2_gem_sync_ioctl(struct drm_device *dev, void *data,
			struct drm_file *filp);
int mga2_virt_to_handle(struct drm_device *drm, void *data,
			struct drm_file *file);

#define MGA20_PCI_PROTO	0
#define MGA20_PROTO	1
#define MGA20		2
#define MGA25_PCI_PROTO	3
#define MGA25_PROTO	4
#define MGA25		5
#define MGA26_PCI_PROTO	6
#define MGA26_PROTO	7
#define MGA26		8
#define MGA26_PCIe	9
#define MGA26_PCIe_PROTO 10
#define MGA27_PCI_PROTO	11
#define MGA27_PROTO	12
#define MGA27		13
#define MGA2X_NR	14

static inline bool mga20(int subdevice)
{
	if (subdevice == MGA20 || subdevice == MGA20_PROTO)
		return true;
	return false;
}

static inline bool mga25(int subdevice)
{
	if (subdevice >= MGA25_PCI_PROTO)
		return true;
	return false;
}

static inline bool mga26(int subdevice)
{
	if (subdevice >= MGA26_PROTO)
		return true;
	return false;
}

static inline bool mga27(int subdevice)
{
	if (subdevice >= MGA27_PROTO)
		return true;
	return false;
}

static inline bool mga2_has_vram(int subdevice)
{
	switch (subdevice) {
	case MGA25_PROTO:
	case MGA26_PROTO:
	case MGA27_PROTO:
	case MGA25:
	case MGA26:
	case MGA27:
		return false;
	}
	return true;
}

static inline bool mga2_use_uncached(int subdevice)
{
	switch (subdevice) {
	case MGA26_PROTO:
	case MGA26:
		return true;
	}
	return false;
}

static inline bool mga2_proto(int subdevice)
{
	switch (subdevice) {
	case MGA25_PROTO:
	case MGA26_PROTO:
	case MGA27_PROTO:
		return true;
	}
	return false;
}

static inline bool mga2_pci_proto(int subdevice)
{
	switch (subdevice) {
	case MGA25_PCI_PROTO:
	case MGA26_PCI_PROTO:
	case MGA27_PCI_PROTO:
		return true;
	}
	return false;
}

extern int mga2_timeout_ms;
static inline int mga2_timeout(struct mga2 *mga2)
{
	return mga2_timeout_ms;
}

#if defined(CONFIG_DEBUG_FS)
int mga2_debugfs_bctrl(struct seq_file *s, void *data);
void mga2_debugfs_init(struct drm_minor *minor);
#endif


/* pll flags */
#define MGA2_PLL_USE_BIOS_DIVS        (1 << 0)
#define MGA2_PLL_NO_ODD_POST_DIV      (1 << 1)
#define MGA2_PLL_USE_REF_DIV          (1 << 2)
#define MGA2_PLL_LEGACY               (1 << 3)
#define MGA2_PLL_PREFER_LOW_REF_DIV   (1 << 4)
#define MGA2_PLL_PREFER_HIGH_REF_DIV  (1 << 5)
#define MGA2_PLL_PREFER_LOW_FB_DIV    (1 << 6)
#define MGA2_PLL_PREFER_HIGH_FB_DIV   (1 << 7)
#define MGA2_PLL_PREFER_LOW_POST_DIV  (1 << 8)
#define MGA2_PLL_PREFER_HIGH_POST_DIV (1 << 9)
#define MGA2_PLL_USE_FRAC_FB_DIV      (1 << 10)
#define MGA2_PLL_PREFER_CLOSEST_LOWER (1 << 11)
#define MGA2_PLL_USE_POST_DIV         (1 << 12)
#define MGA2_PLL_IS_LCD               (1 << 13)
#define MGA2_PLL_PREFER_MINM_OVER_MAXP (1 << 14)

struct mga2_pll {
	/* reference frequency */
	uint32_t reference_freq;

	/* fixed dividers */
	uint32_t reference_div;
	uint32_t post_div;

	/* pll in/out limits */
	uint32_t pll_in_min;
	uint32_t pll_in_max;
	uint32_t pll_out_min;
	uint32_t pll_out_max;
	uint32_t lcd_pll_out_min;
	uint32_t lcd_pll_out_max;
	uint32_t best_vco;

	/* divider limits */
	uint32_t min_ref_div;
	uint32_t max_ref_div;
	uint32_t min_post_div;
	uint32_t max_post_div;
	uint32_t min_feedback_div;
	uint32_t max_feedback_div;
	uint32_t min_frac_feedback_div;
	uint32_t max_frac_feedback_div;

	/* flags for the current clock */
	uint32_t flags;

	/* pll id */
	uint32_t id;
};

int mga2_pll_compute(const struct mga2_pll *pll,
			 const u32 freq,
			 u32 *dot_clock_p,
			 u32 *fb_div_p,
			 u32 *frac_fb_div_p,
			 u32 *ref_div_p,
			 u32 *post_div_p);

int __mga2_sync(struct mga2 *mga2);

#endif	/*__MGA2_DRV_H__*/
