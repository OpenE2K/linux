/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __MGA2_DRV_H__
#define __MGA2_DRV_H__

#include <linux/pci.h>
#include <linux/module.h>
#include <linux/console.h>
#include <linux/platform_device.h>
#include <linux/delay.h>

#include <drm/drm_drv.h>
#include <drm/drm_file.h>
#include <drm/drm_ioctl.h>
#include <drm/drm_irq.h>
#include <drm/drm_gem.h>
#include <drm/drm_crtc.h>
#include <drm/drm_atomic.h>
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

#include <uapi/drm/mga2_drm.h>
#include "mga2_regs.h"

#define  MGA2_MAX_CRTS_NR	3
#define  MGA2_ENCODER_NR	1
#define  MGA2_HDMI_NR		2

#define MGA2_RING_SIZE 256

struct mga2_fbdev;
struct auc2_st;
struct bctrl;

enum {
	MGA2_DVI,
	MGA2_HDMI1,
	MGA2_HDMI2,
	MGA2_LVDS,

	MGA2_CONNECTOR_NR
};

struct mga2_info {
	int regs_bar;
	int vram_bar;
	int dc_regs_base;
	int int_regs_base;
	int vid_regs_base;
	int mga2_crts_nr;
};
#define LVDS_FRAME_TABLE_SZ (7 * 5)
struct mga2 {
	struct drm_device *drm;
	void __iomem *regs;
	resource_size_t regs_phys;
	struct mga2_fbdev *fbdev;
#define MGA2_BCTRL_OFF	(1 << 31)
	int flags;
	int used_lvds_channels;
	u16 subdevice;
	struct mga2_info *info;
	u32 lvds_frame_table[LVDS_FRAME_TABLE_SZ];

	unsigned long base_freq;
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
	struct desc0 *desc0;
	dma_addr_t desc0_dma;
	struct dma_fence *mga2_fence[MGA2_RING_SIZE];
	spinlock_t fence_lock;
	unsigned fence_seqno;

	atomic_t ring_int;

	struct i2c_adapter     *dvi_i2c;
	struct platform_device *mga2_hdmi_device[MGA2_HDMI_NR];
	struct i2c_adapter     *hdmi_ddc[MGA2_HDMI_NR];

	/* page-flip handling */
	struct drm_pending_vblank_event *event[MGA2_MAX_CRTS_NR];

	struct msix_entry msix_entries[1];
};

struct mga2_fbdev {
	struct drm_fb_helper helper;
	struct list_head fbdev_list;
	dma_addr_t pixmap_dma;
};

int mga2_driver_load(struct drm_device *dev, unsigned long flags);
void mga2_driver_unload(struct drm_device *dev);
void mga2_lastclose(struct drm_device *dev);
void mga2_reset(struct drm_device *dev);

struct mga2_connector {
	struct drm_connector base;
	struct i2c_adapter *ddci2c;
	void __iomem *regs;
};

struct mga2_crtc {
	struct drm_crtc base;
	int index;
	struct drm_gem_object *cursor_bo;
	uint64_t cursor_offset;
	void __iomem *cursor_addr;
	void __iomem *regs;
	int pll;

	struct i2c_adapter *i2c;
	struct drm_pending_vblank_event *event;
	struct drm_flip_work fb_unref_work;
	unsigned long pending;
#define MGA2_PENDING_FB_UNREF		1
#define MGA2_PENDING_FB_UNREF_DISABLE	2

};

struct mga2_framebuffer {
	struct drm_framebuffer base;
	struct drm_gem_object *gobj;
};

struct mga2_gem_object {
	struct drm_gem_object base;
	struct drm_mm_node node;

	void *vaddr;
	dma_addr_t dma_addr;
	struct sg_table *sgt;
	struct page **pages;

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

};

#define to_mga2_obj(x) container_of(x, struct mga2_gem_object, base)
#define to_mga2_crtc(x) container_of(x, struct mga2_crtc, base)
#define to_mga2_connector(x) container_of(x, struct mga2_connector, base)
#define to_mga2_framebuffer(x) container_of(x, struct mga2_framebuffer, base)
#define to_mga2_fbdev(x) container_of(x, struct mga2_fbdev, helper)
#define to_mga2_gem(x)	container_of(x, struct mga2_gem_object, base)

int mga2_mode_init_hw(struct drm_device *dev);
int mga2_mode_init(struct drm_device *dev);
void mga2_mode_fini(struct drm_device *dev);
int mga2fb_bctrl_init(struct mga2 *mga2);
int mga2fb_bctrl_fini(struct mga2 *mga2);
int mga2fb_bctrl_hw_init(struct mga2 *mga2);
void mga2_crtc_hw_init(struct drm_crtc *crtc);

void mga2_mode_fini(struct drm_device *dev);

int mga2_framebuffer_init(struct drm_device *dev,
			  struct mga2_framebuffer *mga2_fb,
			  struct drm_mode_fb_cmd2 *mode_cmd,
			  struct drm_gem_object *obj);

int mga2_fbdev_init(struct drm_device *dev);
void mga2_fbdev_fini(struct drm_device *dev);
void mga2_fbdev_set_suspend(struct drm_device *dev, int state);

#define MGA2_MAX_HWC_WIDTH 64
#define MGA2_MAX_HWC_HEIGHT 64

#define MGA2_HWC_SIZE	(MGA2_MAX_HWC_WIDTH*MGA2_MAX_HWC_HEIGHT*4)

int mga2_cursor_move(struct drm_crtc *crtc, int x, int y);

void mga2_cursor_show(struct drm_crtc *crtc, u32 addr);
void mga2_cursor_hide(struct drm_crtc *crtc);
extern void mga2_gem_free_object(struct drm_gem_object *obj);
extern int mga2_dumb_create(struct drm_file *file,
			    struct drm_device *dev,
			    struct drm_mode_create_dumb *args);

#define DRM_FILE_PAGE_OFFSET ((0xFFFFFFFUL >> PAGE_SHIFT) + 1)

struct drm_gem_object *mga2_gem_create(struct drm_device *dev, size_t size,
				       u32 domain);
struct drm_gem_object *mga2_gem_create_with_handle(struct drm_file *file,
						   struct drm_device *dev,
						   size_t size, u32 domain,
						   u32 *handle);

int mga2_mmap(struct file *filp, struct vm_area_struct *vma);

int mga2_crtc_enable_vblank(struct drm_crtc *crtc);
void mga2_crtc_disable_vblank(struct drm_crtc *crtc);
irqreturn_t mga2_driver_irq_handler(int irq, void *arg);
void mga2_driver_irq_preinstall(struct drm_device *dev);
int mga2_driver_irq_postinstall(struct drm_device *dev);
void mga2_driver_irq_uninstall(struct drm_device *dev);
void mga2_irq_sw_irq_get(struct mga2 *mga2);
void mga2_irq_sw_irq_put(struct mga2 *mga2);

void mga2_update_ptr(struct mga2 *mga2);

int mga2_auc2_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);
int mga2_bctrl_ioctl(struct drm_device *dev, void *data, struct drm_file *filp);

int mga2_gem_create_ioctl(struct drm_device *dev, void *data,
			  struct drm_file *filp);
int mga2_gem_mmap_ioctl(struct drm_device *dev, void *data,
			struct drm_file *filp);
int mga2_gem_sync_ioctl(struct drm_device *dev, void *data,
			struct drm_file *filp);

#define MGA2_PCI_PROTO	0
#define MGA2_P2_PROTO	1
#define MGA2_P2		2
#define MGA25_PCI_PROTO	3
#define MGA25_PROTO	4
#define MGA25		5
#define MGA26_PCI_PROTO	6
#define MGA26_PROTO	7
#define MGA26		8

static inline bool mga2_p2(struct mga2 *mga2)
{
	if (mga2->subdevice == MGA2_P2 || mga2->subdevice == MGA2_P2_PROTO)
		return true;
	return false;
}

static inline bool mga25(struct mga2 *mga2)
{
	if (mga2->subdevice >= MGA25_PCI_PROTO)
		return true;
	return false;
}

static inline bool mga2_has_vram(struct mga2 *mga2)
{
	switch (mga2->subdevice) {
	case MGA25_PROTO:
	case MGA26_PROTO:
	case MGA25:
	case MGA26:
		return false;
	}
	return true;
}

static inline bool mga2_use_uncached(struct mga2 *mga2)
{
	switch (mga2->subdevice) {
	case MGA26_PROTO:
	case MGA26:
		return true;
	}
	return false;
}

static inline bool mga2_proto(struct mga2 *mga2)
{
	switch (mga2->subdevice) {
	case MGA25_PCI_PROTO:
	case MGA25_PROTO:
	case MGA26_PROTO:
	case MGA26_PCI_PROTO:
		return true;
	}
	return false;
}

static inline bool mga2_hdmi(struct mga2 *mga2)
{
	if (mga2->subdevice == MGA2_P2 || mga2->subdevice == MGA25)
		return true;
	return false;
}

extern int mga2_timeout_ms;
static inline int mga2_timeout(struct mga2 *mga2)
{
	return mga2_timeout_ms;
}


struct mga2_clk {
	int nr, od, nb;
	long long nf, nf_i, nf_f;
};

struct mga2_div {
	int pix, aux;
};

void mga2_pll_init_pixclock(struct i2c_adapter *adapter);
int _mga2_ext_pll_set_pixclock(int pll, struct i2c_adapter *adapter,
				  unsigned long clock_khz);

int mga2_calc_int_pll(struct mga2_clk *res, const unsigned long long fout,
		     unsigned long long *rfvco, unsigned long long *rerr);

int mga25_calc_int_pll(struct mga2_clk *res, const unsigned long long fout,
		     unsigned long long *rfvco, unsigned long long *rerr);

struct i2c_adapter *mga2_i2c_create(struct device *parent, resource_size_t regs,
			char *name, unsigned base_freq_hz,
			unsigned desired_freq_hz);
void mga2_i2c_destroy(struct i2c_adapter *i2c);

int mga2_dvi_init(struct drm_device *dev, void __iomem *regs,
		   resource_size_t regs_phys);
int mga2_debugfs_bctrl(struct seq_file *s, void *data);
int mga2_common_connector_init(struct drm_device *dev,
						resource_size_t regs_phys,
						int connector_type, bool i2c,
						uint32_t possible_crtcs);

#if defined(CONFIG_DEBUG_FS)
void mga2_debugfs_init(struct drm_minor *minor);
#endif

#define	__rvidc(__addr) readl(vid_regs +  \
				(MGA2_VID0_ ## __addr))
#define	__wvidc(__v, __addr) writel(__v, vid_regs + \
				(MGA2_VID0_ ## __addr))

#ifdef DEBUG
#define rvidc(__offset)				\
({								\
	unsigned __val = __rvidc(__offset);			\
	DRM_DEBUG_KMS("R: %x: %s\n", __val,  # __offset);	\
	__val;							\
})

#define wvidc(__val, __offset)					\
({								\
	unsigned __val2 = __val;				\
	DRM_DEBUG_KMS("W: %x: %s\n", __val2, # __offset);	\
	__wvidc(__val2, __offset);				\
})

#else
#define		rvidc		__rvidc
#define		wvidc		__wvidc
#endif


int drm_vblank_get(struct drm_device *dev, unsigned int pipe);
void drm_vblank_put(struct drm_device *dev, unsigned int pipe);

extern bool mga2_use_external_pll;
extern int mga2_lvds_channels;

/* low-level interface prime helpers */

struct sg_table *mga2_prime_get_sg_table(struct drm_gem_object *obj);
struct drm_gem_object *
mga2_prime_import_sg_table(struct drm_device *dev,
				  struct dma_buf_attachment *attach,
				  struct sg_table *sgt);
int mga2_prime_mmap(struct drm_gem_object *obj,
			   struct vm_area_struct *vma);
void *mga2_prime_vmap(struct drm_gem_object *obj);
void mga2_prime_vunmap(struct drm_gem_object *obj, void *vaddr);

struct drm_plane **mga2_layers_init(struct drm_device *drm);
void mga2_handle_vblank(struct drm_device *drm, int crtc);
int __mga2_sync(struct mga2 *mga2);

#endif	/*__MGA2_DRV_H__*/
