/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*#define DEBUG*/
#include "drv.h"

MODULE_PARM_DESC(nofbaccel, "Disable fbcon acceleration");
static int mga2_nofbaccel = 0;
module_param_named(nofbaccel, mga2_nofbaccel, int, 0400);
MODULE_PARM_DESC(nohwcursor, "Disable hardware cursor");
static int mga2_nohwcursor = 0;
module_param_named(nohwcursor, mga2_nohwcursor, int, 0400);

#define	__rfb(__addr) readl(mga2->regs + __addr)
#define	__wfb(__v, __addr) writel(__v, mga2->regs + __addr)

#ifdef DEBUG
#define rfb(__offset)				\
({								\
	unsigned __val = __rfb(__offset);			\
	/*DRM_DEBUG_KMS("R: %x: %s\n", __val, # __offset);*/	\
	__val;							\
})

#define wfb(__val, __offset)					\
({								\
	unsigned __val2 = __val;				\
	DRM_DEBUG_KMS("W: %x: %s\n", __val2, # __offset);	\
	/*printk(KERN_DEBUG"%x %x\n",  MGA2_DC0_ ## __offset, __val2);*/	\
	__wfb(__val2, __offset);				\
})

#else
#define		rfb		__rfb
#define		wfb		__wfb
#endif

static int get_free_desc(struct mga2 *mga2);
static int append_desc(struct mga2 *mga2, struct mga2_gem_object *mo);
static struct mga2_gem_object *mga2_auc_ioctl(struct drm_device *dev,
					void *data, struct drm_file *filp);
static void __mga2_update_ptr(struct mga2 *mga2);

#include "bctrl.c"
#include "auc2.c"
#include "fbdev.c"


int mga2fb_bctrl_hw_init(struct mga2 *mga2)
{
	int ret = 0;
	if (mga25(mga2->dev_id))
		ret = mga2fb_auc2_hw_init(mga2);
	if (ret)
		return ret;
	return __mga2fb_bctrl_hw_init(mga2);
}

int mga2fb_bctrl_init(struct mga2 *mga2)
{
	int ret = 0;

	if (mga25(mga2->dev_id))
		ret = mga2fb_auc2_init(mga2);
	if (ret)
		return ret;
	ret = __mga2fb_bctrl_init(mga2);
	if (ret)
		return ret;
	return mga2fb_bctrl_hw_init(mga2);
}

int mga2_gem_sync_ioctl(struct drm_device *drm, void *data,
			struct drm_file *filp)
{
	struct mga2 *mga2 = drm->dev_private;
	return __mga2_sync(mga2);
}
