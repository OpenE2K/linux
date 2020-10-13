#ifndef __MGA2_DRV_H__
#define __MGA2_DRV_H__


#include <drm/drmP.h>
#include <drm/drm_crtc.h>
#include <drm/drm_fb_helper.h>
#include <drm/drm_crtc_helper.h>

#include <uapi/drm/mga2_drm.h>

#define DRIVER_AUTHOR		"MCST"

#define DRIVER_NAME		"mga2"
#define DRIVER_DESC		"MGA2"
#define DRIVER_DATE		"20120228"

#define DRIVER_MAJOR		0
#define DRIVER_MINOR		1
#define DRIVER_PATCHLEVEL	0

#define  MGA2_CRTS_NR		1
#define  MGA2_CRTS_MASK		((1 << MGA2_CRTS_NR) - 1)

#define  MGA2_ENCODER_NR	1
#define  MGA2_CONNECTOR_NR	1

struct mga2_fbdev;

struct mga2 {
	struct drm_device *drm;
	void __iomem *regs;
	struct mga2_fbdev *fbdev;
	u16 subdevice;
	unsigned long base_freq;
	unsigned long vram_paddr;
	int flags;
	struct drm_mm vram_mm;
	rwlock_t vram_lock;
	struct mutex bctrl_mu;
	struct bctrl *bctrl;
	dma_addr_t bctrl_dma;
	int head, tail;

	/* page-flip handling */
	struct drm_pending_vblank_event *event[MGA2_CRTS_NR];
};

int mga2_driver_load(struct drm_device *dev, unsigned long flags);
int mga2_driver_unload(struct drm_device *dev);
void mga2_lastclose(struct drm_device *dev);

struct mga2_i2c_chan {
	struct i2c_adapter adapter;
	struct drm_device *dev;
	void __iomem *regs;
};

struct mga2_connector {
	struct drm_connector base;
	struct mga2_i2c_chan *ddci2c;
};

struct mga2_crtc {
	struct drm_crtc base;
	int index;
	u8 lut_r[256], lut_g[256], lut_b[256];
	struct drm_gem_object *cursor_bo;
	uint64_t cursor_offset;
	void __iomem *cursor_addr;
	struct mga2_i2c_chan *i2c;
	void __iomem *regs;
	int pll;
	int clk_mult;
};

struct mga2_encoder {
	struct drm_encoder base;
	struct mga2_i2c_chan *txi2c;
	void __iomem *regs;
};

struct mga2_framebuffer {
	struct drm_framebuffer base;
	struct drm_gem_object *gobj;
};

struct bctrl_base {
	u32 next_lo;
	u32 next_hi;
	u32 status;
	u32 reserved;
} __attribute__ ((packed));

#define BCTRL_CMD_NR	8
#define BCTRL_DESC_NR	4

struct bctrl_desc {
	u32 next_lo;
	u32 next_hi;
	struct bctrl_cmd {
		u16 ctrl;
		u16 reg;
		u32 data;
	} cmd[BCTRL_CMD_NR] __attribute__ ((packed));
} __attribute__ ((packed));

struct bctrl {
	struct bctrl_base base;
	struct bctrl_desc desc[BCTRL_DESC_NR];
} __attribute__ ((packed));

struct mga2_fbdev {
	struct drm_fb_helper helper;
	struct mga2_framebuffer afb;
	struct list_head fbdev_list;
	dma_addr_t pixmap_dma;
};

#define to_mga2_crtc(x) container_of(x, struct mga2_crtc, base)
#define to_mga2_connector(x) container_of(x, struct mga2_connector, base)
#define to_mga2_encoder(x) container_of(x, struct mga2_encoder, base)
#define to_mga2_framebuffer(x) container_of(x, struct mga2_framebuffer, base)

extern int mga2_mode_init(struct drm_device *dev);
extern void mga2_mode_fini(struct drm_device *dev);

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

int mga2_cursor_set(struct drm_crtc *crtc,
		    struct drm_file *file_priv,
		    uint32_t handle, uint32_t width, uint32_t height);
int mga2_cursor_move(struct drm_crtc *crtc, int x, int y);

void mga2_show_cursor(struct drm_crtc *crtc, u32 addr);
void mga2_hide_cursor(struct drm_crtc *crtc);

extern void mga2_gem_free_object(struct drm_gem_object *obj);

extern int mga2_dumb_create(struct drm_file *file,
			    struct drm_device *dev,
			    struct drm_mode_create_dumb *args);
extern int mga2_dumb_destroy(struct drm_file *file,
			     struct drm_device *dev, uint32_t handle);

extern int mga2_dumb_mmap_offset(struct drm_file *file,
				 struct drm_device *dev,
				 uint32_t handle, uint64_t * offset);

#define DRM_FILE_PAGE_OFFSET ((0xFFFFFFFUL >> PAGE_SHIFT) + 1)

struct drm_gem_object *mga2_gem_create(struct drm_device *dev, size_t size,
				       u32 domain);
struct drm_gem_object *mga2_gem_create_with_handle(struct drm_file *file,
						   struct drm_device *dev,
						   size_t size, u32 domain,
						   u32 *handle);

int mga2_mmap(struct file *filp, struct vm_area_struct *vma);

u32 mga2_vblank_count(struct drm_device *dev, int crtc);
int mga2_enable_vblank(struct drm_device *dev, int crtc);
void mga2_disable_vblank(struct drm_device *dev, int crtc);
irqreturn_t mga2_driver_irq_handler(int irq, void *arg);
void mga2_driver_irq_preinstall(struct drm_device *dev);
int mga2_driver_irq_postinstall(struct drm_device *dev);
void mga2_driver_irq_uninstall(struct drm_device *dev);

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

static inline bool mga2_p2(struct mga2 *mga2)
{
	if (mga2->subdevice == MGA2_P2 || mga2->subdevice == MGA2_P2_PROTO)
		return true;
	return false;
}
#endif
