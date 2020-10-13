/*
 * Copyright 2012 Red Hat Inc.
 * Copyright (c) 2012-2013 ZAO "MCST". All rights reserved.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the
 * "Software"), to deal in the Software without restriction, including
 * without limitation the rights to use, copy, modify, merge, publish,
 * distribute, sub license, and/or sell copies of the Software, and to
 * permit persons to whom the Software is furnished to do so, subject to
 * the following conditions:
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NON-INFRINGEMENT. IN NO EVENT SHALL
 * THE COPYRIGHT HOLDERS, AUTHORS AND/OR ITS SUPPLIERS BE LIABLE FOR ANY CLAIM,
 * DAMAGES OR OTHER LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR
 * OTHERWISE, ARISING FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE
 * USE OR OTHER DEALINGS IN THE SOFTWARE.
 *
 * The above copyright notice and this permission notice (including the
 * next paragraph) shall be included in all copies or substantial portions
 * of the Software.
 *
 */
/*
 * Authors: Dave Airlie <airlied@redhat.com>
 *	    Alexander Troosh <troosh@mcst.ru>
 */

#ifndef __MCST_DRV_H__
#define __MCST_DRV_H__

#define CH() DRM_INFO("%s:%d %s\n", __FILE__, __LINE__, __func__)

#include "drm_fb_helper.h"

#include "ttm/ttm_bo_api.h"
#include "ttm/ttm_bo_driver.h"
#include "ttm/ttm_placement.h"
#include "ttm/ttm_memory.h"
#include "ttm/ttm_module.h"

#include <linux/i2c.h>
#include <linux/i2c-algo-bit.h>

#define DRIVER_AUTHOR		"Alexander Troosh"

#define DRIVER_NAME		"mcst"
#define DRIVER_DESC		"MCST MGA cards driver"
#define DRIVER_DATE		"20130125"

#define DRIVER_MAJOR		0
#define DRIVER_MINOR		1
#define DRIVER_PATCHLEVEL	0

#define PCI_CHIP_MCST_MGA3D	0x800c
#define PCI_CHIP_MCST_MGA	0x8000

#define MGA_MODEL_PMUP2_0	0x80	/*PMUP2 version (PCI), head #0*/
#define MGA_MODEL_PMUP2_1	0xc0	/*PMUP2 version (PCI), head #1*/

/* This type of card support MSI? */
#define MCST_CARD_SUPPORT_MSI(chip)  0

/**
 * MCST MGA chip families
 */
enum mcst_family {
	MCST_UNSUPPORTED_MGA = 0,
	MCST_MGA,
	MCST_MGA3D,
};

/**
 * Indexes of pci_dev.resource[]
 */
#define PCI_MGA_MMIO_BAR    0
#define PCI_MGA_FBMEM_BAR   1
#define PCI_MGA_I2C_BAR     2


#define MCST_MAX_CHANNEL_NR 16

#define MCST_MAX_CRTC_NR 2

struct mcst_fbdev;


struct mcst_channel {
	struct drm_device *dev;
	struct list_head list;
	int id;

	struct {
		bool active;
		char name[32];
		struct drm_info_list info;
	} debugfs;
};


struct mcst_private {
	struct drm_device *dev;
	int id;

	void __iomem *ioregs[MCST_MAX_CRTC_NR];
	void __iomem *i2cregs;

	enum mcst_family chip;
	unsigned int firmware_version;

	bool vga2_clone;
#if 0
	uint32_t dram_bus_width;
	uint32_t dram_type;
	uint32_t mclk;
#endif
	uint32_t vram_size;

/*	struct mcst_crtc[MCST_MAX_CRTC_NR];*/

	struct mcst_fbdev *fbdev;

	int fb_mtrr;

	struct {
		struct drm_global_reference mem_global_ref;
		struct ttm_bo_global_ref bo_global_ref;
		struct ttm_bo_device bdev;
	} ttm;

	/* interrupt handling */
	void (*irq_handler[MCST_MAX_CRTC_NR][32])(struct drm_device *);
	bool msi_enabled;
	spinlock_t context_switch_lock;

#if 0
	struct drm_gem_object *cursor_cache;
	uint64_t cursor_cache_gpu_addr;
	struct ttm_bo_kmap_obj cache_kmap;
	int next_cursor;
#endif

	struct {
		spinlock_t lock;
		struct mcst_channel *ptr[MCST_MAX_CHANNEL_NR];
	} channels;

	struct mcst_channel *channel;

	struct {
		struct dentry *channel_root;
	} debugfs;

};



int mcst_driver_load(struct drm_device *dev, unsigned long flags);
int mcst_driver_unload(struct drm_device *dev);

struct mcst_gem_object;



/*******************************************************************************
 * MCST MGA MMIO Registers
 *******************************************************************************
 */
#define REG_CTRL	0x000	/* Control Register */
#define REG_STAT	0x004	/* Status Register */
#define REG_HTIM	0x008	/* Horizontal Timing Register */
#define REG_VTIM	0x00c	/* Vertical Timing Register */
#define REG_HVLEN	0x010	/* Horizontal and Vertical Length Register */
#define REG_VBARa	0x014	/* Video Memory Base Address Register A */
#define REG_VBARb	0x018	/* Video Memory Base Address Register B */
#define REG_TST_D	0x01C	/* Test Mode */

#define REG_C0XY	0x030	/* Cursor 0 X,Y Register */
#define REG_C0BAR	0x034	/* Cursor0 Base Address register */
#define REG_C0CR	0x040	/* Cursor0 Color Registers */

#define REG_PCLT	0x800	/* 8bpp Pseudo Color Lockup Table */


#define REG_DDC		0x0D0	/* GPIO bits SDA & SCL for DDC */

#define REG_STAMP	0x0FC	/* Firmware version and timestamp 0xVVYYMMDD */

/**
 * Control Register REG_CTRL
 */

/* for Processor operation */
#define CTRL_WORDS16_IN_WORDS32_TWISTER (0x1<<31)
#define CTRL_IN_WORDS16_TWISTER		(0x1<<30)

#define CTRL_SAP
#define CTRL_HC1R_32	0	     /* Hardware Cursor1 Resolution 32x32 */
#define CTRL_HC1R_64	(0x1<<25)    /*				    64x64 */
#define CTRL_HC1E	(0x1<<24)    /* Hardware Cursor1 Enabled */
#define CTRL_HC0R_32	0	     /* Hardware Cursor0 Resolution 32x32 */
#define CTRL_HC0R_64	(0x1<<21)    /*				    64x64 */
#define CTRL_HC0E	(0x1<<20)    /* Hardware Cursor0 Enabled */
#define CTRL_TST	(0x1<<17)    /* TODO: ????? */
/* Blanking Polarization Level */
#define CTRL_BL_POS	0	     /*  Positive */
#define CTRL_BL_NEG	(0x1<<15)    /*  Negative */

/* Synchronization Pulse Polarization Level */
#define CTRL_CSYNC_NEG	(0x1<<14)    /* Composite Negative  */
#define CTRL_VSYNC_NEG	(0x1<<13)    /* Vertical Negative   */
#define CTRL_HSYNC_NEG	(0x1<<12)    /* Horizontal Negative */

#define CTRL_PC_GRAY	0	     /* 8-bit Pseudo Color Grayscale */
#define CTRL_PC_PSEUDO	(0x1<<11)    /*		     Pseudo Color    */

#define CTRL_CD_8BPP	0	     /* Color Depth	8bpp */
#define CTRL_CD_16BPP	(0x1<<9)     /*		       16bpp */
#define CTRL_CD_24BPP	(0x2<<9)     /*		       24bpp */
#define CTRL_CD_32BPP	(0x3<<9)     /*		       32bpp */
#define CTRL_CD_MASK	(0x3<<9)

/* Video Memory Burst Length */
#define CTRL_VBL_1	0	     /*  1 cycle	      */
#define CTRL_VBL_2	(0x1<<7)     /*  2 cycles	      */
#define CTRL_VBL_4	(0x2<<7)     /*  4 cycles	      */
#define CTRL_VBL_8	(0x3<<7)     /*  8 cycles	      */
#define CTRL_VBL1024	(0x203<<7)   /* 16 cycles (extension) */

#define CTRL_CBSWE	(0x1<<6)     /* CLUT  Bank Switching Enable */
#define CTRL_VBSWE	(0x1<<5)     /* Video Bank Switching Enable */
#define CTRL_CBSIE	(0x1<<4)     /* CLUT  Bank Switch Interrupt Enable */
#define CTRL_VBSIE	(0x1<<3)     /* Video Bank Switch Interrupt Enable */
#define CTRL_HIE	(0x1<<2)     /* HSync Interrupt Enable */
#define CTRL_VIE	(0x1<<1)     /* VSync Interrupt Enable */
#define CTRL_VEN	(0x1<<0)     /* Video Enable */


/* Status Register REG_STAT */
#define STAT_HC1A	(0x1<<24)	/* Hardware cursor1 available */
#define STAT_HC0A	(0x1<<20)	/* Hardware cursor0 available */
#define STAT_ACMP	(0x1<<17)	/* Active CLUT Memory Page */
#define STAT_AVMP	(0x1<<16)	/* Active Video Memory Page */

/* Interrupt Pending bits */
#define STAT_CBSINT_BIT_NUM  7	      /* CLUT Bank Switch    */
#define STAT_VBSINT_BIT_NUM  6	      /* Bank Switch	     */
#define STAT_HINT_BIT_NUM    5	      /* Horizontal	     */
#define STAT_VINT_BIT_NUM    4	      /* Vertical	     */
#define STAT_LUINT_BIT_NUM   1	      /* Line FIFO Under-Run */
#define STAT_SINT_BIT_NUM    0	      /* System Error	     */

#define STAT_CBSINT_MASK   (1<<STAT_CBSINT_BIT_NUM)
#define STAT_VBSINT_MASK   (1<<STAT_VBSINT_BIT_NUM)
#define STAT_HINT_MASK	   (1<<STAT_HINT_BIT_NUM)
#define STAT_VINT_MASK	   (1<<STAT_VINT_BIT_NUM)
#define STAT_LUINT_MASK    (1<<STAT_LUINT_BIT_NUM)
#define STAT_SINT_MASK	   (1<<STAT_SINT_BIT_NUM)

/* Mask of all interrupts pending bits */
#define REG_STAT_IRQS_MASK (STAT_CBSINT_MASK | STAT_VBSINT_MASK \
		| STAT_HINT_MASK  | STAT_VINT_MASK \
		| STAT_LUINT_MASK | STAT_SINT_MASK)

/*******************************************************************************
 * MMIO BitBlt Module Registers
 *******************************************************************************
 */
#define REG_BB_CTRL	0x1000	/* BitBlt control register (write only) */
#define REG_BB_STAT	0x1000	/* BitBlt status register (read only)	*/

#define REG_BB_WINDOW	0x1004	/* Operation geometry */
#define REG_BB_SADDR	0x1008	/* Source start address */
#define REG_BB_DADDR	0x100c	/* Destination start address */
#define REG_BB_PITCH	0x1010	/* */
#define REG_BB_BG	0x1014	/* Background color */
#define REG_BB_FG	0x1018	/* Foreground color */

/* BitBlt status register bits */
#define BB_STAT_PROCESS (0x1<<31) /* 1 - processing operation, 0 - idle */
#define BB_STAT_FULL	(0x1<<30) /* 1 - pipeline full */
#define BB_STAT_DMA	(0x1<<26) /* DMA support */

/* BitBlt control register bits */
#define BB_CTRL_CMD_MASK	0xC0000000
#define BB_CTRL_CMD_START		(0x1<<31)
#define BB_CTRL_CMD_ABORT		(0x1<<30)
#define BB_CTRL_DDMA_EN			(0x1<<21)
#define BB_CTRL_BITS_IN_BYTE_TWISTER	(0x1<<22)

#define BB_CTRL_DDMA_EN		(0x1<<21)
#define BB_CTRL_SDMA_EN		(0x1<<20)
#define BB_CTRL_SOFFS_MASK	(0x7<<16)


/* See Bug 59994 */
#define REG_DDC_SDA_HI 3
#define REG_DDC_SDA_LO 2
#define REG_DDC_SCL_HI 12
#define REG_DDC_SCL_LO 8

#define REG_DDC_SDA_INPUT_MASK 1
#define REG_DDC_SCL_INPUT_MASK 4

/**
 * Functions for access to display controller, bitblt and other modules
 * registers
 */
#define __mcst_io_read(x) \
	static inline \
u##x mcst_io_read##x(struct mcst_private *mcst, int cell, u32 reg) \
{\
	u##x val = 0;\
	val = ioread##x(mcst->ioregs[cell] + reg);\
	return val;\
}

__mcst_io_read(8);
__mcst_io_read(16);
__mcst_io_read(32);
#undef __mcst_io_read

#define __mcst_io_write(x) \
	static inline \
void mcst_io_write##x(struct mcst_private *mcst, int cell, u32 reg, u##x val) \
{\
	iowrite##x(val, mcst->ioregs[cell] + reg);\
}

__mcst_io_write(8);
__mcst_io_write(16);
__mcst_io_write(32);
#undef __mcst_io_write


/**
 * Functions for access to I2C module registers
 */
#define __mcst_i2c_read(x) \
	static inline \
u##x mcst_i2c_read##x(struct mcst_private *mcst, int cell, u32 reg) \
{\
	u##x val = 0;\
	val = ioread##x(mcst->ioregs[cell] + reg);\
	return val;\
}

__mcst_i2c_read(8);
__mcst_i2c_read(16);
__mcst_i2c_read(32);
#undef __mcst_i2c_read

#define __mcst_i2c_write(x) \
	static inline void \
mcst_i2c_write##x(struct mcst_private *mcst, int cell, u32 reg, u##x val) \
{\
	iowrite##x((val), mcst->ioregs[cell] + reg);\
}

__mcst_i2c_write(8);
__mcst_i2c_write(16);
__mcst_i2c_write(32);
#undef __mcst_i2c_write


struct mcst_i2c_chan {
	struct i2c_adapter adapter;
	struct drm_device *dev;
	struct i2c_algo_bit_data bit;
	int cell;
};

struct mcst_connector {
	struct drm_connector base;
	struct mcst_i2c_chan *i2c;
};

struct mcst_crtc {
	struct drm_crtc base;
	int cell;			       /* index of CRTC */

	u8 lut_r[256], lut_g[256], lut_b[256];
	struct drm_gem_object *cursor_bo;
	uint64_t cursor_addr;
	int cursor_width, cursor_height;
	u8 offset_x, offset_y;
};

struct mcst_encoder {
	struct drm_encoder base;
};

struct mcst_framebuffer {
	struct drm_framebuffer base;
	struct drm_gem_object *obj;
};

struct mcst_fbdev {
	struct drm_fb_helper helper;
	struct mcst_framebuffer mfb;
	struct list_head fbdev_list;
	void *sysram;
	int size;
	struct ttm_bo_kmap_obj mapping;

	struct {
		spinlock_t lock;
		bool active;
		unsigned x1;
		unsigned y1;
		unsigned x2;
		unsigned y2;
	} dirty;
};

#define to_mcst_crtc(x) container_of(x, struct mcst_crtc, base)
#define to_mcst_connector(x) container_of(x, struct mcst_connector, base)
#define to_mcst_encoder(x) container_of(x, struct mcst_encoder, base)
#define to_mcst_framebuffer(x) container_of(x, struct mcst_framebuffer, base)


extern int mcst_mode_init(struct drm_device *dev);
extern void mcst_mode_fini(struct drm_device *dev);

int mcst_framebuffer_init(struct drm_device *dev,
		struct mcst_framebuffer *mcst_fb,
		struct drm_mode_fb_cmd2 *mode_cmd,
		struct drm_gem_object *obj);

int mcst_fbdev_init(struct drm_device *dev);
void mcst_fbdev_fini(struct drm_device *dev);
void mcst_fbdev_set_suspend(struct drm_device *dev, int state);

struct mcst_bo {
	struct ttm_buffer_object bo;
	struct ttm_placement placement;
	struct ttm_bo_kmap_obj kmap;
	struct drm_gem_object gem;
	u32 placements[3];
	int pin_count;
};
#define gem_to_mcst_bo(gobj) container_of((gobj), struct mcst_bo, gem)

static inline struct mcst_bo *
mcst_bo(struct ttm_buffer_object *bo)
{
	return container_of(bo, struct mcst_bo, bo);
}


#define to_mcst_obj(x) container_of(x, struct mcst_gem_object, base)

#define MCST_MM_ALIGN_SHIFT 4
#define MCST_MM_ALIGN_MASK ((1 << MCST_MM_ALIGN_SHIFT) - 1)

extern int mcst_dumb_create(struct drm_file *file,
		struct drm_device *dev,
		struct drm_mode_create_dumb *args);
extern int mcst_dumb_destroy(struct drm_file *file,
		struct drm_device *dev,
		uint32_t handle);

extern int mcst_gem_init_object(struct drm_gem_object *obj);
extern void mcst_gem_free_object(struct drm_gem_object *obj);
extern int mcst_dumb_mmap_offset(struct drm_file *file,
		struct drm_device *dev,
		uint32_t handle,
		uint64_t *offset);

#if BITS_PER_LONG == 64
#define DRM_FILE_PAGE_OFFSET ((0xFFFFFFFFUL >> PAGE_SHIFT) + 1)
#else
#define DRM_FILE_PAGE_OFFSET ((0xFFFFFFFUL >> PAGE_SHIFT) + 1)
#endif

int mcst_mm_init(struct mcst_private *mcst);
void mcst_mm_fini(struct mcst_private *mcst);

int mcst_bo_create(struct drm_device *dev, int size, int align,
		uint32_t flags, struct mcst_bo **pmcstbo);

int mcst_gem_create(struct drm_device *dev,
		u32 size, bool iskernel,
		struct drm_gem_object **obj);

int mcst_bo_pin(struct mcst_bo *bo, u32 pl_flag, u64 *gpu_addr);
int mcst_bo_unpin(struct mcst_bo *bo);

int mcst_bo_reserve(struct mcst_bo *bo, bool no_wait);
void mcst_bo_unreserve(struct mcst_bo *bo);
void mcst_ttm_placement(struct mcst_bo *bo, int domain);
int mcst_bo_push_sysram(struct mcst_bo *bo);
int mcst_mmap(struct file *filp, struct vm_area_struct *vma);


/* mcst_pll.c */
void mcst_pll_init_pixclock(void __iomem *i2c_mmio);
void mcst_pll_set_pixclock(int output, void __iomem *i2c_mmio,
			   uint32_t pixclock);


/* mcst_irq.c */
extern int	   mcst_irq_init(struct drm_device *);
extern void	   mcst_irq_fini(struct drm_device *);
extern irqreturn_t mcst_irq_handler(DRM_IRQ_ARGS);
extern void	   mcst_irq_register(struct drm_device *, int cell,
				     int status_bit,
				     void (*)(struct drm_device *));
extern void	   mcst_irq_unregister(struct drm_device *, int cell,
				       int status_bit);
extern void	   mcst_irq_preinstall(struct drm_device *);
extern int	   mcst_irq_postinstall(struct drm_device *);
extern void	   mcst_irq_uninstall(struct drm_device *);

extern int mcst_msi;

extern int  mcst_enable_vblank(struct drm_device *dev, int crtc_num);
extern void mcst_disable_vblank(struct drm_device *dev, int crtc_num);

#endif
