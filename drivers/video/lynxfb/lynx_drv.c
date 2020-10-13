/*******************************************************************
*Copyright (c) 2012 by Silicon Motion, Inc. (SMI)
*Permission is hereby granted, free of charge, to any person obtaining a copy
*of this software and associated documentation files (the "Software"), to deal
*in the Software without restriction, including without limitation the rights to
*use, copy, modify, merge, publish, distribute, sublicense, and/or sell copies
*of the Software, and to permit persons to whom the Software is furnished to
*do so, subject to the following conditions:
*
*THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND,
*EXPRESS OR IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES
*OF MERCHANTABILITY, FITNESS FOR A PARTICULAR PURPOSE AND
*NONINFRINGEMENT.  IN NO EVENT SHALL Mill.Chen and Monk.Liu OR COPYRIGHT
*HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER LIABILITY,
*WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING
*FROM, OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR
*OTHER DEALINGS IN THE SOFTWARE.
*******************************************************************/
#include <linux/version.h>
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 10)
#include <linux/config.h>
#endif
#include <linux/kernel.h>
#include <linux/module.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/fb.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/pci.h>

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
/* no below two header files in 2.6.9 */
#include <linux/platform_device.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/screen_info.h>
#else
/* nothing by far */
#endif
#include <linux/vmalloc.h>
#include<linux/pagemap.h>
#include <linux/console.h>
#ifdef CONFIG_MTRR
#include <asm/mtrr.h>
#endif

#include "lynx_drv.h"
#include "ver.h"
#include "lynx_hw750.h"
#include "lynx_accel.h"
#include "lynx_cursor.h"

#include "modedb.c"

int smi_indent;
#ifdef MODULE
static void __exit lynxfb_exit(void);
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
static int lynxfb_setup(char *);
static int __init lynxfb_init(void);
#else
int __init lynxfb_setup(char *);
int __init lynxfb_init(void);
#endif

/* chip specific setup routine */
static void sm750fb_setup(struct lynx_share *, char *);
static int lynxfb_pci_probe(struct pci_dev *,
				      const struct pci_device_id *);
static void lynxfb_pci_remove(struct pci_dev *);

#ifdef CONFIG_PM
static int lynxfb_suspend(struct pci_dev *, pm_message_t);
static int lynxfb_resume(struct pci_dev *);
#endif

#ifdef CONFIG_FB_LYNXFB_DOMAINS
static int lynxfb_set_fbinfo(struct fb_info *, int, int);
#else
static int lynxfb_set_fbinfo(struct fb_info *, int);
#endif
static int lynxfb_ops_check_var(struct fb_var_screeninfo *,
				struct fb_info *);
static int lynxfb_ops_set_par(struct fb_info *);
static int lynxfb_ops_setcolreg(unsigned, unsigned, unsigned, unsigned,
				unsigned, struct fb_info *);
static int lynxfb_ops_blank(int, struct fb_info *);
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
static int lynxfb_ops_cursor(struct fb_info *, struct fb_cursor *);
#endif
/*
#ifdef __BIG_ENDIAN
ssize_t lynxfb_ops_write(struct fb_info *info, const char __user *buf,
size_t count, loff_t *ppos);
ssize_t lynxfb_ops_read(struct fb_info *info, char __user *buf,
size_t count, loff_t *ppos);
#endif
*/

typedef void (*PROC_SPEC_SETUP) (struct lynx_share *, char *);
typedef int (*PROC_SPEC_MAP) (struct lynx_share *, struct pci_dev *);
typedef int (*PROC_SPEC_INITHW) (struct lynx_share *, struct pci_dev *);

/* common var for all device */
int g_hwcursor = 1;
int g_noaccel;
#ifdef CONFIG_MTRR
int g_nomtrr;
#endif
const char *g_fbmode[] = { NULL, NULL };
const char *g_fbmode_tmp[] = { NULL, NULL };
const char *g_def_fbmode = "800x600-8@60";
const char *g_max_fbmode = "1920x1080-32@60";
char *g_settings;
int g_dualview;
#ifdef MODULE
char *g_option;
#endif

/* if not use spin_lock, system will die if user load driver
 *and immediatly unload driver frequently (dual)*/
static inline void myspin_lock(spinlock_t * sl)
{
	struct lynx_share *share;
	share = container_of(sl, struct lynx_share, slock);
	if (share->dual) {
		spin_lock(sl);
	}
}

static inline void myspin_unlock(spinlock_t * sl)
{
	struct lynx_share *share;
	share = container_of(sl, struct lynx_share, slock);
	if (share->dual) {
		spin_unlock(sl);
	}
}

static const struct fb_videomode lynx750_ext[] = {
	/*      1024x600-60 VESA        [1.71:1]        */
	{NULL, 60, 1024, 600, 20423, 144, 40, 18, 1, 104, 3,
	 FB_SYNC_HOR_HIGH_ACT | FB_SYNC_VERT_HIGH_ACT,
	 FB_VMODE_NONINTERLACED},

	/*      1024x600-70 VESA */
	{NULL, 70, 1024, 600, 17211, 152, 48, 21, 1, 104, 3,
	 FB_SYNC_HOR_HIGH_ACT | FB_SYNC_VERT_HIGH_ACT,
	 FB_VMODE_NONINTERLACED},

	/*      1024x600-75 VESA */
	{NULL, 75, 1024, 600, 15822, 160, 56, 23, 1, 104, 3,
	 FB_SYNC_HOR_HIGH_ACT | FB_SYNC_VERT_HIGH_ACT,
	 FB_VMODE_NONINTERLACED},

	/*      1024x600-85 VESA */
	{NULL, 85, 1024, 600, 13730, 168, 56, 26, 1, 112, 3,
	 FB_SYNC_HOR_HIGH_ACT | FB_SYNC_VERT_HIGH_ACT,
	 FB_VMODE_NONINTERLACED},

	/*      720x480 */
	{NULL, 60, 720, 480, 37427, 88, 16, 13, 1, 72, 3,
	 FB_SYNC_HOR_HIGH_ACT | FB_SYNC_VERT_HIGH_ACT,
	 FB_VMODE_NONINTERLACED},

	/*      1280x720                [1.78:1]        */
	{NULL, 60, 1280, 720, 13426, 162, 86, 22, 1, 136, 3,
	 FB_SYNC_HOR_HIGH_ACT | FB_SYNC_VERT_HIGH_ACT,
	 FB_VMODE_NONINTERLACED},

	/* 1280x768@60 */
	{NULL, 60, 1280, 768, 12579, 192, 64, 20, 3, 128, 7,
	 FB_SYNC_HOR_HIGH_ACT | FB_SYNC_VERT_HIGH_ACT,
	 FB_VMODE_NONINTERLACED},

	{NULL, 60, 1360, 768, 11804, 208, 64, 23, 1, 144, 3,
	 FB_SYNC_HOR_HIGH_ACT | FB_VMODE_NONINTERLACED},

	/*      1360 x 768      [1.77083:1]     */
	{NULL, 60, 1360, 768, 11804, 208, 64, 23, 1, 144, 3,
	 FB_SYNC_HOR_HIGH_ACT | FB_SYNC_VERT_HIGH_ACT,
	 FB_VMODE_NONINTERLACED},

	/*      1368 x 768      [1.78:1]        */
	{NULL, 60, 1368, 768, 11647, 216, 72, 23, 1, 144, 3,
	 FB_SYNC_HOR_HIGH_ACT | FB_SYNC_VERT_HIGH_ACT,
	 FB_VMODE_NONINTERLACED},

	/*      1440 x 900              [16:10] */
	{NULL, 60, 1440, 900, 9392, 232, 80, 28, 1, 152, 3,
	 FB_SYNC_VERT_HIGH_ACT, FB_VMODE_NONINTERLACED},

	/*      1440x960                [15:10] */
	{NULL, 60, 1440, 960, 8733, 240, 88, 30, 1, 152, 3,
	 FB_SYNC_HOR_HIGH_ACT | FB_SYNC_VERT_HIGH_ACT,
	 FB_VMODE_NONINTERLACED},

	/*      1920x1080       [16:9]  */
	{NULL, 60, 1920, 1080, 6734, 148, 88, 41, 1, 44, 3,
	 FB_SYNC_VERT_HIGH_ACT, FB_VMODE_NONINTERLACED},
};


static struct pci_device_id smi_pci_table[] = {
	{PCI_VENDOR_ID_SMI, PCI_DEVID_LYNX_EXP, PCI_ANY_ID, PCI_ANY_ID, 0,
	 0, 0},
	{PCI_VENDOR_ID_SMI, PCI_DEVID_LYNX_SE, PCI_ANY_ID, PCI_ANY_ID, 0,
	 0, 0},
	{PCI_VENDOR_ID_SMI, PCI_DEVID_LYNX_EM, PCI_ANY_ID, PCI_ANY_ID, 0,
	 0, 0},
	{PCI_VENDOR_ID_SMI, PCI_DEVID_LYNX_3DM, PCI_ANY_ID, PCI_ANY_ID, 0,
	 0, 0},
	{PCI_VENDOR_ID_SMI, PCI_DEVID_VOYAGER, PCI_ANY_ID, PCI_ANY_ID, 0,
	 0, 0},
	{0,}
};

static struct pci_driver lynxfb_driver = {
	.name = _moduleName_,
	.id_table = smi_pci_table,
	.probe = lynxfb_pci_probe,
	.remove = lynxfb_pci_remove,
#ifdef CONFIG_PM
	.suspend = lynxfb_suspend,
	.resume = lynxfb_resume,
#endif
};


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
/* no hardware cursor supported under version 2.6.10, kernel bug */
static int lynxfb_ops_cursor(struct fb_info *info,
			     struct fb_cursor *fbcursor)
{
	struct lynxfb_par *par;
	struct lynxfb_crtc *crtc;
	struct lynx_cursor *cursor;

	par = info->par;
	crtc = &par->crtc;
	cursor = &crtc->cursor;

	if (fbcursor->image.width > cursor->maxW ||
	    fbcursor->image.height > cursor->maxH ||
	    fbcursor->image.depth > 1) {
		return -ENXIO;
	}

	cursor->disable(cursor);
	if (fbcursor->set & FB_CUR_SETSIZE) {
		cursor->setSize(cursor, fbcursor->image.width,
				fbcursor->image.height);
	}

	if (fbcursor->set & FB_CUR_SETPOS) {
		cursor->setPos(cursor,
			       fbcursor->image.dx - info->var.xoffset,
			       fbcursor->image.dy - info->var.yoffset);
	}

	if (fbcursor->set & FB_CUR_SETCMAP) {
		/* get the 16bit color of kernel means */
		u16 fg, bg;
		fg = ((info->cmap.
		       red[fbcursor->image.fg_color] & 0xf800)) | ((info->
								    cmap.
								    green
								    [fbcursor->
								     image.
								     fg_color]
								    &
								    0xfc00)
								   >> 5) |
		    ((info->cmap.
		      blue[fbcursor->image.fg_color] & 0xf800) >> 11);

		bg = ((info->cmap.
		       red[fbcursor->image.bg_color] & 0xf800)) | ((info->
								    cmap.
								    green
								    [fbcursor->
								     image.
								     bg_color]
								    &
								    0xfc00)
								   >> 5) |
		    ((info->cmap.
		      blue[fbcursor->image.bg_color] & 0xf800) >> 11);

		cursor->setColor(cursor, fg, bg);
	}


	if (fbcursor->set & (FB_CUR_SETSHAPE | FB_CUR_SETIMAGE)) {

		cursor->setData(cursor,
				fbcursor->rop,
				fbcursor->image.data, fbcursor->mask);
	}

	if (fbcursor->enable) {
		cursor->enable(cursor);
	}

	return 0;
}

#endif

static void lynxfb_ops_fillrect(struct fb_info *info,
				const struct fb_fillrect *region)
{
	struct lynxfb_par *par;
	struct lynx_share *share;
	unsigned int base, pitch, Bpp, rop;
	u32 color;

	if (info->state != FBINFO_STATE_RUNNING) {
		return;
	}

	par = info->par;
	share = par->share;

	/* each time 2d function begin to work, below three variable always need
	 *be set, seems we can put them together in some place  */
	base = par->crtc.oScreen;
	pitch = info->fix.line_length;
	Bpp = info->var.bits_per_pixel >> 3;

	color =
	    (Bpp ==
	     1) ? region->color : ((u32 *) info->pseudo_palette)[region->
								 color];
	rop = (region->rop != ROP_COPY) ? HW_ROP2_XOR : HW_ROP2_COPY;

	myspin_lock(&share->slock);
	share->accel.de_fillrect(&share->accel,
				 base, pitch, Bpp,
				 region->dx, region->dy,
				 region->width, region->height,
				 color, rop);
	myspin_unlock(&share->slock);
}

static void lynxfb_ops_copyarea(struct fb_info *info,
				const struct fb_copyarea *region)
{
	struct lynxfb_par *par;
	struct lynx_share *share;
	unsigned int base, pitch, Bpp;

	par = info->par;
	share = par->share;

	/* each time 2d function begin to work, below three variable always need
	 *be set, seems we can put them together in some place  */
	base = par->crtc.oScreen;
	pitch = info->fix.line_length;
	Bpp = info->var.bits_per_pixel >> 3;

	myspin_lock(&share->slock);
	share->accel.de_copyarea(&share->accel,
				 base, pitch, region->sx, region->sy,
				 base, pitch, Bpp, region->dx, region->dy,
				 region->width, region->height,
				 HW_ROP2_COPY);
	myspin_unlock(&share->slock);
}

static void lynxfb_ops_imageblit(struct fb_info *info,
				 const struct fb_image *image)
{
	unsigned int base, pitch, Bpp;
	unsigned int fgcol, bgcol;
	struct lynxfb_par *par;
	struct lynx_share *share;

	par = info->par;
	share = par->share;
	/* each time 2d function begin to work, below three variable always need
	 *be set, seems we can put them together in some place  */
	base = par->crtc.oScreen;
	pitch = info->fix.line_length;
	Bpp = info->var.bits_per_pixel >> 3;

	if (image->depth == 1) {
		if (info->fix.visual == FB_VISUAL_TRUECOLOR ||
		    info->fix.visual == FB_VISUAL_DIRECTCOLOR) {
			fgcol =
			    ((u32 *) info->pseudo_palette)[image->
							   fg_color];
			bgcol =
			    ((u32 *) info->pseudo_palette)[image->
							   bg_color];
			switch (info->var.bits_per_pixel) {
			case 16:
				fgcol = cpu_to_le16(fgcol);
				bgcol = cpu_to_le16(bgcol);
				break;
			case 24:
			case 32:
				fgcol = cpu_to_le32(fgcol);
				bgcol = cpu_to_le32(bgcol);
				break;
			}
		} else {
			fgcol = image->fg_color;
			bgcol = image->bg_color;
		}
		goto _do_work;
	}
	return;
      _do_work:
	myspin_lock(&share->slock);
	share->accel.de_imageblit(&share->accel,
				  image->data, image->width >> 3, 0,
				  base, pitch, Bpp,
				  image->dx, image->dy,
				  image->width, image->height,
				  fgcol, bgcol, HW_ROP2_COPY);
	myspin_unlock(&share->slock);
}

static int lynxfb_ops_pan_display(struct fb_var_screeninfo *var,
				  struct fb_info *info)
{
	struct lynxfb_par *par;
	struct lynxfb_crtc *crtc;
	int ret;
	ENTER();

	if (!info)
		LEAVE(-EINVAL);

	ret = 0;
	par = info->par;
	crtc = &par->crtc;
#ifdef CONFIG_FB_LYNXFB_DOMAINS
	ret = crtc->proc_panDisplay(crtc, var, info, crtc->domain);
#else
	ret = crtc->proc_panDisplay(crtc, var, info);
#endif

	LEAVE(ret);
}

static struct fb_ops lynxfb_ops = {
	.owner = THIS_MODULE,
	.fb_check_var = lynxfb_ops_check_var,
	.fb_set_par = lynxfb_ops_set_par,
	.fb_setcolreg = lynxfb_ops_setcolreg,
	.fb_blank = lynxfb_ops_blank,
	/* will be hooked by hardware */
	.fb_fillrect = cfb_fillrect,
	.fb_imageblit = cfb_imageblit,
	.fb_copyarea = cfb_copyarea,
	/* cursor */
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
	.fb_cursor = lynxfb_ops_cursor,
#else
	.fb_cursor = soft_cursor,
#endif
};

static size_t spec_size[] = {
	[SPC_SM750] = sizeof(struct sm750_share),
};

static PROC_SPEC_SETUP setup_rout[] = {
	[SPC_SM750] = sm750fb_setup,
};

static PROC_SPEC_MAP map_rout[] = {
	[SPC_SM750] = hw_sm750_map,
};

static PROC_SPEC_INITHW inithw_rout[] = {
	[SPC_SM750] = hw_sm750_inithw,
};
static int g_specId;

#ifdef CONFIG_PM
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 10)
static u32 pci_state[16];

static int lynxfb_suspend(struct pci_dev *pdev, pm_message_t mesg)
{
	int ret;
	struct fb_info *info;
	struct lynx_share *share;

	ENTER();
	ret = 0;
	share = pci_get_drvdata(pdev);

	if (mesg != 2 || mesg == pdev->dev.power_state)
		return ret;

	/* suspend */
	acquire_console_mutex();

	info = share->fbinfo[0];
	if (info) {
		fb_set_suspend(info, 1);
	}

	info = share->fbinfo[1];

	if (info) {
		fb_set_suspend(info, 1);
	}

	/* hardware suspend stuffs */
	if (mesg == 2 && share->suspend)
		share->suspend(share);

	pci_save_state(pdev, &pci_state);
	pci_disable_device(pdev);
	ret = pci_set_power_state(pdev, mesg);

	release_console_mutex();
	pdev->dev.power_state = mesg;
	LEAVE(ret);
}

static int lynxfb_resume(struct pci_dev *pdev)
{
	int ret;
	struct fb_info *info;
	struct lynx_share *share;
	struct lynxfb_par *par;
	struct lynxfb_crtc *crtc;
	struct lynx_cursor *cursor;

	ENTER();
	share = pci_get_drvdata(pdev);
	ret = 0;

	acquire_console_mutex();

	pci_set_power_state(pdev, 0);
	pci_restore_state(pdev, &pci_state);
	pci_enable_device(pdev);

	if (pdev->dev.power_state == 2 && share->resume)
		share->resume(share);

	(*inithw_rout[g_specId]) (share, pdev);

	info = share->fbinfo[0];
	if (info) {
		par = info->par;
		crtc = &par->crtc;
		cursor = &crtc->cursor;
		memset_io(cursor->vstart, 0x0, cursor->size);
		lynxfb_ops_set_par(info);
		fb_set_suspend(info, 0);
	}

	info = share->fbinfo[1];

	if (info) {
		par = info->par;
		crtc = &par->crtc;
		cursor = &crtc->cursor;
		memset_io(cursor->vstart, 0x0, cursor->size);
		lynxfb_ops_set_par(info);
		fb_set_suspend(info, 0);
	}

	release_console_mutex();
	pdev->dev.power_state = 0;
	LEAVE(ret);
}


#else
static int lynxfb_suspend(struct pci_dev *pdev, pm_message_t mesg)
{
	struct fb_info *info;
	struct lynx_share *share;
	int ret;
	ENTER();

	if (mesg.event == pdev->dev.power.power_state.event)
		LEAVE(0);

	ret = 0;
	share = pci_get_drvdata(pdev);
	switch (mesg.event) {
	case PM_EVENT_FREEZE:
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 19)
	case PM_EVENT_PRETHAW:
#endif
		pdev->dev.power.power_state = mesg;
		LEAVE(0);
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
	acquire_console_mutex();
#else
	console_lock();
#endif
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 24)
	if (mesg.event & PM_EVENT_SUSPEND) {
#else
	if (mesg.event & PM_EVENT_SLEEP) {
#endif
		info = share->fbinfo[0];
		if (info)
			fb_set_suspend(info, 1);	/* 1 means do suspend */

		info = share->fbinfo[1];
		if (info)
			fb_set_suspend(info, 1);	/* 1 means do suspend */

		ret = pci_save_state(pdev);
		if (ret) {
			err_msg("error:%d occured in pci_save_state\n",
				ret);
			LEAVE(ret);
		}

		/* set chip to sleep mode       */
		if (share->suspend)
			(*share->suspend) (share);

		pci_disable_device(pdev);
		ret =
		    pci_set_power_state(pdev,
					pci_choose_state(pdev, mesg));
		if (ret) {
			err_msg
			    ("error:%d occured in pci_set_power_state\n",
			     ret);
			LEAVE(ret);
		}
	}

	pdev->dev.power.power_state = mesg;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
	release_console_mutex();
#else
	console_unlock();
#endif
	LEAVE(ret);
}

static int lynxfb_resume(struct pci_dev *pdev)
{
	struct fb_info *info;
	struct lynx_share *share;

	struct lynxfb_par *par;
	struct lynxfb_crtc *crtc;
	struct lynx_cursor *cursor;

	int ret;
	ENTER();

	ret = 0;
	share = pci_get_drvdata(pdev);

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
	acquire_console_mutex();
#else
	console_lock();
#endif

	ret = pci_set_power_state(pdev, PCI_D0);
	if (ret != 0) {
		err_msg("error:%d occured in pci_set_power_state\n", ret);
		LEAVE(ret);
	}


	if (pdev->dev.power.power_state.event != PM_EVENT_FREEZE) {
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
		/* for linux 2.6.35 and lower */
		ret = pci_restore_state(pdev);
		if (ret != 0) {
			err_msg("error:%d occured in pci_restore_state\n",
				ret);
			LEAVE(ret);
		}
#else
		pci_restore_state(pdev);
#endif
		ret = pci_enable_device(pdev);
		if (ret != 0) {
			err_msg("error:%d occured in pci_enable_device\n",
				ret);
			LEAVE(ret);
		}
		pci_set_master(pdev);
	}
	if (share->resume)
		(*share->resume) (share);

	(*inithw_rout[g_specId]) (share, pdev);


	info = share->fbinfo[0];

	if (info) {
		par = info->par;
		crtc = &par->crtc;
		cursor = &crtc->cursor;
		memset_io(cursor->vstart, 0x0, cursor->size);
		lynxfb_ops_set_par(info);
		fb_set_suspend(info, 0);
	}

	info = share->fbinfo[1];

	if (info) {
		par = info->par;
		crtc = &par->crtc;
		cursor = &crtc->cursor;
		memset_io(cursor->vstart, 0x0, cursor->size);
		lynxfb_ops_set_par(info);
		fb_set_suspend(info, 0);
	}

#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 35)
	release_console_mutex();
#else
	console_unlock();
#endif
	LEAVE(ret);
}
#endif
#endif

static int lynxfb_ops_check_var(struct fb_var_screeninfo *var,
				struct fb_info *info)
{
	struct lynxfb_par *par;
	struct lynxfb_crtc *crtc;
	struct lynxfb_output *output;
	struct lynx_share *share;
	int ret;
	resource_size_t request;

	ENTER();
	par = info->par;
	crtc = &par->crtc;
	output = &par->output;
	share = par->share;
	ret = 0;

	dbg_msg("check var:%dx%d-%d\n",
		var->xres, var->yres, var->bits_per_pixel);


	switch (var->bits_per_pixel) {
	case 8:
	case 16:
	case 24:		/* support 24 bpp for only lynx712/722/720 */
	case 32:
		break;
	default:
		err_msg("bpp %d not supported\n", var->bits_per_pixel);
		ret = -EINVAL;
		goto exit;
	}

	switch (var->bits_per_pixel) {
	case 8:
		info->fix.visual = FB_VISUAL_PSEUDOCOLOR;
		var->red.offset = 0;
		var->red.length = 8;
		var->green.offset = 0;
		var->green.length = 8;
		var->blue.offset = 0;
		var->blue.length = 8;
		var->transp.length = 0;
		var->transp.offset = 0;
		break;
	case 16:
		var->red.offset = 11;
		var->red.length = 5;
		var->green.offset = 5;
		var->green.length = 6;
		var->blue.offset = 0;
		var->blue.length = 5;
		var->transp.length = 0;
		var->transp.offset = 0;
		info->fix.visual = FB_VISUAL_TRUECOLOR;
		break;
	case 24:
	case 32:
		var->red.length = 8;
		var->blue.length = 8;
		var->green.length = 8;
		var->transp.length = 0;
#ifdef	__LITTLE_ENDIAN
		var->transp.offset = 24;
		var->red.offset = 16;
		var->green.offset = 8;
		var->blue.offset = 0;
#elif	defined(__BIG_ENDIAN)
		var->transp.offset = 0;
		var->red.offset = 8;
		var->green.offset = 16;
		var->blue.offset = 24;
#else
#error	Endianess not defined
#endif	/*__BIG_ENDIAN*/

		info->fix.visual = FB_VISUAL_TRUECOLOR;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	var->height = var->width = -1;
	var->accel_flags = FB_ACCELF_TEXT;

	/* check if current fb's video memory big enought to hold the onscreen */
	request = var->xres_virtual * (var->bits_per_pixel >> 3);
	/* defaulty crtc->channel go with par->index */

	request = PADDING(crtc->line_pad, request);
	request = request * var->yres_virtual;
	if (crtc->vidmem_size < request) {
		err_msg("not enough video memory for mode\n");
		LEAVE(-ENOMEM);
	}

#ifdef CONFIG_FB_LYNXFB_DOMAINS
	ret = output->proc_checkMode(output, var, output->domain);
	if (!ret)
		ret = crtc->proc_checkMode(crtc, var, crtc->domain);
#else
	ret = output->proc_checkMode(output, var);
	if (!ret)
		ret = crtc->proc_checkMode(crtc, var);
#endif /* CONFIG_FB_LYNXFB_DOMAINS */
      exit:
	LEAVE(ret);
}

static int lynxfb_ops_set_par(struct fb_info *info)
{
	struct lynxfb_par *par;
	struct lynx_share *share;
	struct lynxfb_crtc *crtc;
	struct lynxfb_output *output;
	struct fb_var_screeninfo *var;
	struct fb_fix_screeninfo *fix;
	int ret;
	unsigned int line_length;
	ENTER();

	if (!info)
		LEAVE(-EINVAL);

	ret = 0;
	par = info->par;
	share = par->share;
	crtc = &par->crtc;
	output = &par->output;
	var = &info->var;
	fix = &info->fix;

	/* fix structur is not so FIX ... */
	line_length = var->xres_virtual * var->bits_per_pixel / 8;
	line_length = PADDING(crtc->line_pad, line_length);
	fix->line_length = line_length;
	dbg_msg("fix->line_length = %d\n", fix->line_length);

	/* var->red, green, blue, transp are need to be set by driver
	 *and these data should be set before setcolreg routine
	 **/

	switch (var->bits_per_pixel) {
	case 8:
		fix->visual = FB_VISUAL_PSEUDOCOLOR;
		var->red.offset = 0;
		var->red.length = 8;
		var->green.offset = 0;
		var->green.length = 8;
		var->blue.offset = 0;
		var->blue.length = 8;
		var->transp.length = 0;
		var->transp.offset = 0;
		break;
	case 16:
		var->red.offset = 11;
		var->red.length = 5;
		var->green.offset = 5;
		var->green.length = 6;
		var->blue.offset = 0;
		var->blue.length = 5;
		var->transp.length = 0;
		var->transp.offset = 0;
		fix->visual = FB_VISUAL_TRUECOLOR;
		break;
	case 24:
	case 32:
		var->red.length = 8;
		var->blue.length = 8;
		var->green.length = 8;
		var->transp.length = 0;
#ifdef	__LITTLE_ENDIAN
		var->transp.offset = 24;
		var->red.offset = 16;
		var->green.offset = 8;
		var->blue.offset = 0;
#elif	defined(__BIG_ENDIAN)
		var->transp.offset = 0;
		var->red.offset = 8;
		var->green.offset = 16;
		var->blue.offset = 24;
#else
#error	Endianess not defined
#endif	/*__BIG_ENDIAN*/

		fix->visual = FB_VISUAL_TRUECOLOR;
		break;
	default:
		ret = -EINVAL;
		break;
	}
	var->height = var->width = -1;
	var->accel_flags = FB_ACCELF_TEXT;

	if (ret) {
		err_msg("pixel bpp format not satisfied\n.");
		LEAVE(ret);
	}
#ifdef CONFIG_FB_LYNXFB_DOMAINS
	ret = crtc->proc_setMode(crtc, var, fix, crtc->domain);
	if (!ret)
		ret = output->proc_setMode(output, var, fix, output->domain);
#else
	ret = crtc->proc_setMode(crtc, var, fix);
	if (!ret)
		ret = output->proc_setMode(output, var, fix);
#endif /* CONFIG_FB_LYNXFB_DOMAINS */
	LEAVE(ret);
}
static inline unsigned int chan_to_field(unsigned int chan,
					 struct fb_bitfield *bf)
{
	chan &= 0xffff;
	chan >>= 16 - bf->length;
	return chan << bf->offset;
}

static int lynxfb_ops_setcolreg(unsigned regno, unsigned red,
				unsigned green, unsigned blue,
				unsigned transp, struct fb_info *info)
{
	struct lynxfb_par *par;
	struct lynxfb_crtc *crtc;
	struct fb_var_screeninfo *var;
	int ret;

	par = info->par;
	crtc = &par->crtc;
	var = &info->var;
	ret = 0;

	dbg_msg("regno=%d, red=%d, green=%d, blue=%d\n", regno, red, green, blue);
	if (regno > 256) {
		err_msg("regno = %d\n", regno);
		LEAVE(-EINVAL);
	}

	if (info->var.grayscale)
		red = green = blue =
		    (red * 77 + green * 151 + blue * 28) >> 8;

	if (var->bits_per_pixel == 8
	    && info->fix.visual == FB_VISUAL_PSEUDOCOLOR) {
		red >>= 8;
		green >>= 8;
		blue >>= 8;

#ifdef CONFIG_FB_LYNXFB_DOMAINS
		ret = crtc->proc_setColReg(crtc, regno, red, green, blue, crtc->domain);
#else
		ret = crtc->proc_setColReg(crtc, regno, red, green, blue);
#endif /* CONFIG_FB_LYNXFB_DOMAINS */
		goto exit;
	}

	if (info->fix.visual == FB_VISUAL_TRUECOLOR && regno < 256) {
		u32 val;
		val = chan_to_field(red, &var->red);
		val |= chan_to_field(green, &var->green);
		val |= chan_to_field(blue, &var->blue);
		if (var->bits_per_pixel == 16)
			val = cpu_to_le16(val);
		par->pseudo_palette[regno] = val;
		goto exit;
	}

	ret = -EINVAL;

      exit:
	return ret;
	LEAVE(ret);

}

static int lynxfb_ops_blank(int blank, struct fb_info *info)
{
	struct lynxfb_par *par;
	struct lynxfb_output *output;
	ENTER();
	dbg_msg("blank = %d.\n", blank);
	par = info->par;
	output = &par->output;
#ifdef CONFIG_FB_LYNXFB_DOMAINS
	LEAVE(output->proc_setBLANK(output, blank, output->domain));
#else
	LEAVE(output->proc_setBLANK(output, blank));
#endif /* CONFIG_FB_LYNXFB_DOMAINS */
}
static int sm750fb_set_drv(struct lynxfb_par *par)
{
	int ret;
	struct lynx_share *share;
	struct sm750_share *spec_share;
	struct lynxfb_output *output;
	struct lynxfb_crtc *crtc;
	ENTER();
	ret = 0;

	share = par->share;
	spec_share = container_of(share, struct sm750_share, share);
	output = &par->output;
	crtc = &par->crtc;

	crtc->vidmem_size =
	    (share->dual) ? share->vidmem_size >> 1 : share->vidmem_size;
	/* setup crtc and output member */
	spec_share->hwCursor = g_hwcursor;

	crtc->proc_setMode = hw_sm750_crtc_setMode;
	crtc->proc_checkMode = hw_sm750_crtc_checkMode;
	crtc->proc_setColReg = hw_sm750_setColReg;
	crtc->proc_panDisplay = hw_sm750_pan_display;
	crtc->clear = hw_sm750_crtc_clear;
	crtc->line_pad = 16;
	/*crtc->xpanstep = crtc->ypanstep = crtc->ywrapstep = 0; */
	crtc->xpanstep = 8;
	crtc->ypanstep = 1;
	crtc->ywrapstep = 0;

	output->proc_setMode = hw_sm750_output_setMode;
	output->proc_checkMode = hw_sm750_output_checkMode;

	output->proc_setBLANK =
	    (share->revid ==
	     SM750LE_REVISION_ID) ? hw_sm750le_setBLANK :
	    hw_sm750_setBLANK;
	output->clear = hw_sm750_output_clear;
	/* chip specific phase */
	share->accel.de_wait =
	    (share->revid ==
	     SM750LE_REVISION_ID) ? hw_sm750le_deWait : hw_sm750_deWait;
	switch (spec_share->state.dataflow) {
	case sm750_simul_pri:
		output->paths = sm750_pnc;
		crtc->channel = sm750_primary;
		crtc->oScreen = 0;
		crtc->vScreen = share->pvMem;
		inf_msg("use simul primary mode\n");
		break;
	case sm750_simul_sec:
		output->paths = sm750_pnc;
		crtc->channel = sm750_secondary;
		crtc->oScreen = 0;
		crtc->vScreen = share->pvMem;
		break;
	case sm750_dual_normal:
		if (par->index == 0) {
			output->paths = sm750_panel;
			crtc->channel = sm750_primary;
			crtc->oScreen = 0;
			crtc->vScreen = share->pvMem;
		} else {
			output->paths = sm750_crt;
			crtc->channel = sm750_secondary;
			/* not consider of padding stuffs for oScreen, need fix */
			crtc->oScreen = (share->vidmem_size >> 1);
			crtc->vScreen = share->pvMem + crtc->oScreen;
		}
		break;
	case sm750_dual_swap:
		if (par->index == 0) {
			output->paths = sm750_panel;
			crtc->channel = sm750_secondary;
			crtc->oScreen = 0;
			crtc->vScreen = share->pvMem;
		} else {
			output->paths = sm750_crt;
			crtc->channel = sm750_primary;
			/* not consider of padding stuffs for oScreen, need fix */
			crtc->oScreen = (share->vidmem_size >> 1);
			crtc->vScreen = share->pvMem + crtc->oScreen;
		}
		break;
	default:
		ret = -EINVAL;
	}

	LEAVE(ret);
}

#ifdef CONFIG_FB_LYNXFB_DOMAINS
static int lynxfb_set_fbinfo(struct fb_info *info, int index, int domain)
#else
static int lynxfb_set_fbinfo(struct fb_info *info, int index)
#endif
{
	int i;
	struct lynxfb_par *par;
	struct lynx_share *share;
	struct lynxfb_crtc *crtc;
	struct lynxfb_output *output;
	struct fb_var_screeninfo *var;
	struct fb_fix_screeninfo *fix;

	const struct fb_videomode *pdb[] = {
		NULL, NULL, vesa_modes,
	};
	int cdb[] = { 0, 0, VESA_MODEDB_SIZE };
	static const char *mdb_desc[] = {
		"driver prepared modes",
		"kernel prepared default modedb",
		"kernel HELPERS prepared vesa_modes",
	};

#define sm502_ext lynx750_ext
	static const struct fb_videomode *ext_table[] =
	    { lynx750_ext, NULL, sm502_ext };
	static size_t ext_size[] =
	    { ARRAY_SIZE(lynx750_ext), 0, ARRAY_SIZE(sm502_ext) };

	static const char *fixId[][2] = {
		{"sm750_fb1", "sm750_fb2"},
	};

	int ret, line_length;
	ENTER();
	ret = 0;
	par = (struct lynxfb_par *) info->par;
	share = par->share;
	crtc = &par->crtc;
	output = &par->output;
#ifdef CONFIG_FB_LYNXFB_DOMAINS
	crtc->domain = domain;
	output->domain = domain;
	share->accel.domain = domain;
#endif /* CONFIG_FB_LYNXFB_DOMAINS */
	var = &info->var;
	fix = &info->fix;

	/* set index */
	par->index = index;
	output->channel = &crtc->channel;

	sm750fb_set_drv(par);
	lynxfb_ops.fb_pan_display = lynxfb_ops_pan_display;

	/* set current cursor variable and proc pointer,
	 *must be set after crtc member initialized */

	crtc->cursor.offset = crtc->oScreen + crtc->vidmem_size - 1024;
	crtc->cursor.mmio =
	    share->pvReg + 0x800f0 + (int) crtc->channel * 0x140;

	inf_msg("crtc->cursor.mmio = %p\n", crtc->cursor.mmio);
	crtc->cursor.maxH = crtc->cursor.maxW = 64;
	crtc->cursor.size = crtc->cursor.maxH * crtc->cursor.maxW * 2 / 8;
	crtc->cursor.disable = hw_cursor_disable;
	crtc->cursor.enable = hw_cursor_enable;
	crtc->cursor.setColor = hw_cursor_setColor;
	crtc->cursor.setPos = hw_cursor_setPos;
	crtc->cursor.setSize = hw_cursor_setSize;
	crtc->cursor.setData = hw_cursor_setData;
	crtc->cursor.vstart = share->pvMem + crtc->cursor.offset;

	crtc->cursor.share = share;
	memset_io(crtc->cursor.vstart, 0, crtc->cursor.size);
	if (!g_hwcursor) {
		lynxfb_ops.fb_cursor = NULL;
		crtc->cursor.disable(&crtc->cursor);
	}
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 10)
	/* hardware cursor broken under low version kernel */
	lynxfb_ops.fb_cursor = soft_cursor;
#endif

	/* set info->fbops, must be set before fb_find_mode */
	if (!share->accel_off) {
		/* use 2d acceleration */
		lynxfb_ops.fb_fillrect = lynxfb_ops_fillrect;
		lynxfb_ops.fb_copyarea = lynxfb_ops_copyarea;
		lynxfb_ops.fb_imageblit = lynxfb_ops_imageblit;
	}
	info->fbops = &lynxfb_ops;

	if (!g_fbmode[index]) {
		g_fbmode[index] = g_def_fbmode;
		if (index)
			g_fbmode[index] = g_fbmode[0];
	}

	pdb[0] = ext_table[g_specId];
	cdb[0] = ext_size[g_specId];

	for (i = 0; i < 3; i++) {
		/* no NULL pointer passed to fb_find_mode @4 */
		if (pdb[i] == NULL) {
#if LINUX_VERSION_CODE < KERNEL_VERSION(2, 6, 10)
			pdb[i] = &modedb2[0];
			cdb[i] = nmodedb2;
#endif
		}

		ret = fb_find_mode(var, info, g_fbmode[index],
				   pdb[i], cdb[i], NULL, 8);

		if (ret == 1) {
			inf_msg("success! use specified mode:%s in %s\n",
				g_fbmode[index], mdb_desc[i]);
			break;
		} else if (ret == 2) {
			war_msg
			    ("use specified mode:%s in %s, with an ignored refresh rate\n",
			     g_fbmode[index], mdb_desc[i]);
			break;
		} else if (ret == 3) {
			war_msg("wanna use default mode\n");
			/*                      break; */
		} else if (ret == 4) {
			war_msg("fall back to any valid mode\n");
		} else {
			war_msg("ret = %d, fb_find_mode failed, with %s\n",
				ret, mdb_desc[i]);
		}
	}

#ifdef CONFIG_FB_LYNXFB_DOMAINS
	g_fbmode[0] = g_fbmode_tmp[0];
	g_fbmode[1] = g_fbmode_tmp[1];
#endif /* CONFIG_FB_LYNXFB_DOMAINS */
	/* some member of info->var had been set by fb_find_mode */

	inf_msg("Member of info->var is :\n\
				xres=%d\n\
				yres=%d\n\
				xres_virtual=%d\n\
				yres_virtual=%d\n\
				xoffset=%d\n\
				yoffset=%d\n\
				bits_per_pixel=%d\n \
				...\n", var->xres, var->yres, var->xres_virtual, var->yres_virtual, var->xoffset, var->yoffset, var->bits_per_pixel);

	/* set par */
	par->info = info;

	/* set info */
	line_length = PADDING(crtc->line_pad,
			      (var->xres_virtual * var->bits_per_pixel /
			       8));

	info->pseudo_palette = &par->pseudo_palette[0];
	info->screen_base = crtc->vScreen;
	dbg_msg("screen_base vaddr = %p\n", info->screen_base);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 10)
	info->screen_size = line_length * var->yres_virtual;
#endif
	info->flags = FBINFO_FLAG_DEFAULT | 0;

	/* set info->fix */
	fix->type = FB_TYPE_PACKED_PIXELS;
	fix->type_aux = 0;
	fix->xpanstep = crtc->xpanstep;
	fix->ypanstep = crtc->ypanstep;
	fix->ywrapstep = crtc->ywrapstep;
	fix->accel = FB_ACCEL_NONE;

	strlcpy(fix->id, fixId[g_specId][index], sizeof(fix->id));


	fix->smem_start = crtc->oScreen + share->vidmem_start;
	inf_msg("fix->smem_start = %lx\n", fix->smem_start);

	/* according to mmap experiment from user space application,
	 *fix->mmio_len should not larger than virtual size
	 *(xres_virtual x yres_virtual x ByPP)
	 *Below line maybe buggy when user mmap fb dev node and write
	 *data into the bound over virtual size
	 **/
	fix->smem_len = crtc->vidmem_size;
	inf_msg("fix->smem_len = %x\n", fix->smem_len);
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 10)
	info->screen_size = fix->smem_len;
#endif

	fix->line_length = line_length;
	fix->mmio_start = share->vidreg_start;
	inf_msg("fix->mmio_start = %lx\n", fix->mmio_start);
	fix->mmio_len = share->vidreg_size;
	inf_msg("fix->mmio_len = %x\n", fix->mmio_len);
	switch (var->bits_per_pixel) {
	case 8:
		fix->visual = FB_VISUAL_PSEUDOCOLOR;
		break;
	case 16:
	case 32:
		fix->visual = FB_VISUAL_TRUECOLOR;
		break;
	}

	/* set var */
	var->activate = FB_ACTIVATE_NOW;
	var->accel_flags = 0;
	var->vmode = FB_VMODE_NONINTERLACED;

	dbg_msg
	    ("#1 show info->cmap : \nstart=%d, len=%d, red=%p, green=%p, blue=%p, transp=%p\n",
	     info->cmap.start, info->cmap.len, info->cmap.red,
	     info->cmap.green, info->cmap.blue, info->cmap.transp);

	ret = fb_alloc_cmap(&info->cmap, 256, 0);
	if (ret < 0) {
		err_msg("Could not allcate memory for cmap.\n");
		goto exit;
	}

	dbg_msg
	    ("#2 show info->cmap : \nstart=%d, len=%d, red=%p, green=%p, blue=%p, transp=%p\n",
	     info->cmap.start, info->cmap.len, info->cmap.red,
	     info->cmap.green, info->cmap.blue, info->cmap.transp);

      exit:
	lynxfb_ops_check_var(var, info);
	/*    lynxfb_ops_set_par(info); */
	LEAVE(ret);
}

static int lynxfb_pci_probe(struct pci_dev *pdev,
			      const struct pci_device_id *ent)
{
	struct fb_info *info[] = { NULL, NULL };
	struct lynx_share *share = NULL;

	void *spec_share = NULL;
	size_t spec_offset = 0;
	int fbidx;
	ENTER();

	/* enable device */
	if (pci_enable_device(pdev)) {
		err_msg("can not enable device.\n");
		goto err_enable;
	}

	switch (ent->device) {
	case PCI_DEVID_LYNX_EXP:
	case PCI_DEVID_LYNX_SE:
		g_specId = SPC_SM750;
		/* though offset of share in sm750_share is 0,
		 *we use this marcro as the same */
		spec_offset = offsetof(struct sm750_share, share);
		break;
	default:
		break;
	}

	dbg_msg("spec_offset = %ld\n", spec_offset);
	spec_share = kzalloc(spec_size[g_specId], GFP_KERNEL);
	if (!spec_share) {
		err_msg("Could not allocate memory for share.\n");
		goto err_share;
	}

	/* setting share structure */
	share = (struct lynx_share *) (spec_share + spec_offset);
	share->fbinfo[0] = share->fbinfo[1] = NULL;
	share->devid = pdev->device;
#if LINUX_VERSION_CODE <= KERNEL_VERSION(2, 6, 22)
	u32 temp;
	pci_read_config_dword(pdev, PCI_CLASS_REVISION, &temp);
	share->revid = temp & 0xFF;
#else
	share->revid = pdev->revision;
#endif

	inf_msg("share->revid = %02x\n", share->revid);
	share->pdev = pdev;
#ifdef CONFIG_MTRR
	share->mtrr_off = g_nomtrr;
	share->mtrr.vram = 0;
	share->mtrr.vram_added = 0;
#endif
	share->accel_off = g_noaccel;
	share->dual = g_dualview;
	spin_lock_init(&share->slock);

	if (!share->accel_off) {
		/* hook deInit and 2d routines, notes that below hw_xxx
		 *routine can work on most of lynx chips
		 *if some chip need specific function, please hook it in smXXX_set_drv
		 *routine */
		share->accel.de_init = hw_de_init;
		share->accel.de_fillrect = hw_fillrect;
		share->accel.de_copyarea = hw_copyarea;
		share->accel.de_imageblit = hw_imageblit;
		inf_msg("enable 2d acceleration\n");
	} else {
		inf_msg("disable 2d acceleration\n");
	}

	/* call chip specific setup routine  */
	(*setup_rout[g_specId]) (share, g_settings);

	/* call chip specific mmap routine */
	if ((*map_rout[g_specId]) (share, pdev)) {
		err_msg("Memory map failed\n");
		goto err_map;
	}
#ifdef CONFIG_MTRR
	if (!share->mtrr_off) {
		inf_msg("enable mtrr\n");
		share->mtrr.vram = mtrr_add(share->vidmem_start,
					    share->vidmem_size,
					    MTRR_TYPE_WRCOMB, 1);

		if (share->mtrr.vram < 0) {
			/* don't block driver with the failure of MTRR */
			err_msg("Unable to setup MTRR.\n");
		} else {
			share->mtrr.vram_added = 1;
			inf_msg("MTRR added succesfully\n");
		}
	}
#endif
	inf_msg("sm%3x mmio address = %p\n", share->devid, share->pvReg);

	pci_set_drvdata(pdev, share);

	/* call chipInit routine */
	(*inithw_rout[g_specId]) (share, pdev);

	/* detect 502 need no disp driver
	 *beware that other chips except 502 should not touch g_502nodisp
	 *(remain g_502nodisp always 0)
	 *so regularily, below if line will not affect other chips' behaviour
	 **/
	/*      if (!g_no502disp) { */
	/* allocate frame buffer info structor according to g_dualview */
	fbidx = 0;
      ALLOC_FB:
	info[fbidx] =
	    framebuffer_alloc(sizeof(struct lynxfb_par), &pdev->dev);
	if (!info[fbidx]) {
		err_msg("Could not allocate framebuffer #%d.\n", fbidx);
		if (fbidx == 0)
			goto err_info0_alloc;
		else
			goto err_info1_alloc;
	} else {
		int errno;
#ifdef CONFIG_FB_LYNXFB_DOMAINS
		int domain;
#endif
		struct lynxfb_par *par;
		inf_msg("framebuffer #%d alloc okay\n", fbidx);
		share->fbinfo[fbidx] = info[fbidx];
		par = info[fbidx]->par;
		par->share = share;

		/* set fb_info structure */
#ifdef CONFIG_FB_LYNXFB_DOMAINS
		domain = pci_domain_nr(pdev->bus);
		if (lynxfb_set_fbinfo(info[fbidx], fbidx, domain)) {
#else
		if (lynxfb_set_fbinfo(info[fbidx], fbidx)) {
#endif /* CONFIG_FB_LYNXFB_DOMAINS */
			err_msg("Failed to initial fb_info #%d.\n", fbidx);
			if (fbidx == 0)
				goto err_info0_set;
			else
				goto err_info1_set;
		}

		/* register frame buffer */
		inf_msg("Ready to register framebuffer #%d.\n", fbidx);
		errno = register_framebuffer(info[fbidx]);
		if (errno < 0) {
			err_msg("Failed to register fb_info #%d. err %d\n",
				fbidx, errno);
			if (fbidx == 0)
				goto err_register0;
			else
				goto err_register1;
		}
		inf_msg("Accomplished register framebuffer #%d.\n", fbidx);
	}

	/* no dual view by far */
	fbidx++;
	if (share->dual && fbidx < 2)
		goto ALLOC_FB;
/*		}*/

	LEAVE(0);

      err_register1:
      err_info1_set:
	framebuffer_release(info[1]);
      err_info1_alloc:
	unregister_framebuffer(info[0]);
      err_register0:
      err_info0_set:
	framebuffer_release(info[0]);
      err_info0_alloc:
      err_map:
	kfree(spec_share);
      err_share:
      err_enable:
	LEAVE(-ENODEV);
}

static void lynxfb_pci_remove(struct pci_dev *pdev)
{
	struct fb_info *info;
	struct lynx_share *share;
	void *spec_share;
	struct lynxfb_par *par;
	int cnt;
	ENTER();

	cnt = 2;
	share = pci_get_drvdata(pdev);

	while (cnt-- > 0) {
		info = share->fbinfo[cnt];
		if (!info)
			continue;
		par = info->par;

		unregister_framebuffer(info);
		/* clean crtc & output allocations */
#ifdef CONFIG_FB_LYNXFB_DOMAINS
		par->crtc.clear(&par->crtc, (&par->crtc)->domain);
		par->output.clear(&par->output, (&par->crtc)->domain);
#else
		par->crtc.clear(&par->crtc);
		par->output.clear(&par->output);
#endif /* CONFIG_FB_LYNXFB_DOMAINS */
		/* release frame buffer */
		framebuffer_release(info);
	}
#ifdef CONFIG_MTRR
	if (share->mtrr.vram_added)
		mtrr_del(share->mtrr.vram, share->vidmem_start,
			 share->vidmem_size);
#endif
	/*      pci_release_regions(pdev); */

	iounmap(share->pvReg);
	iounmap(share->pvMem);

	switch (share->devid) {
	case PCI_DEVID_LYNX_EXP:
	case PCI_DEVID_LYNX_SE:
		spec_share =
		    container_of(share, struct sm750_share, share);
		break;
	default:
		spec_share = share;
	}
	kfree(g_settings);
	kfree(spec_share);
	pci_set_drvdata(pdev, NULL);
	LEAVE();
}


/* 	chip specific g_option configuration routine */
static void sm750fb_setup(struct lynx_share *share, char *src)
{
	struct sm750_share *spec_share;
	char *opt;
#ifdef CAP_EXPENSION
	char *exp_res;
#endif
	int swap;
	ENTER();

	spec_share = container_of(share, struct sm750_share, share);
#ifdef CAP_EXPENSIION
	exp_res = NULL;
#endif
	swap = 0;

	spec_share->state.initParm.chip_clk = 0;
	spec_share->state.initParm.mem_clk = 0;
	spec_share->state.initParm.master_clk = 0;
	spec_share->state.initParm.powerMode = 0;
	spec_share->state.initParm.setAllEngOff = 0;
	spec_share->state.initParm.resetMemory = 1;

	/*defaultly turn g_hwcursor on for both view */
	g_hwcursor = 3;

	if (!src || !*src) {
		war_msg("no specific g_option.\n");
		goto NO_PARAM;
	}

	while ((opt = strsep(&src, ":")) != NULL && *opt != 0) {
		err_msg("opt=%s\n", opt);
		err_msg("src=%s\n", src);

		if (!strncmp(opt, "swap", strlen("swap")))
			swap = 1;
		else if (!strncmp(opt, "nocrt", strlen("nocrt")))
			spec_share->state.nocrt = 1;
		else if (!strncmp(opt, "36bit", strlen("36bit")))
			spec_share->state.pnltype = sm750_doubleTFT;
		else if (!strncmp(opt, "18bit", strlen("18bit")))
			spec_share->state.pnltype = sm750_dualTFT;
		else if (!strncmp(opt, "24bit", strlen("24bit")))
			spec_share->state.pnltype = sm750_24TFT;
#ifdef CAP_EXPANSION
		else if (!strncmp(opt, "exp:", strlen("exp:")))
			exp_res = opt + strlen("exp:");
#endif
		else if (!strncmp(opt, "nohwc0", strlen("nohwc0")))
			g_hwcursor &= ~0x1;
		else if (!strncmp(opt, "nohwc1", strlen("nohwc1")))
			g_hwcursor &= ~0x2;
		else if (!strncmp(opt, "nohwc", strlen("nohwc")))
			g_hwcursor = 0;
		else {
			if (!g_fbmode[0]) {
				g_fbmode[0] = opt;
				inf_msg("find fbmode0 : %s\n",
					g_fbmode[0]);
			} else if (!g_fbmode[1]) {
				g_fbmode[1] = opt;
				inf_msg("find fbmode1 : %s\n",
					g_fbmode[1]);
			} else {
				war_msg("How many view you wann set?\n");
			}
		}
	}
#ifdef CAP_EXPANSION
	if (getExpRes
	    (exp_res, &spec_share->state.xLCD, &spec_share->state.yLCD)) {
		/* seems exp_res is not valid */
		spec_share->state.xLCD = spec_share->state.yLCD = 0;
	}
#endif

      NO_PARAM:
	if (share->revid != SM750LE_REVISION_ID) {
		if (share->dual) {
			if (swap)
				spec_share->state.dataflow =
				    sm750_dual_swap;
			else
				spec_share->state.dataflow =
				    sm750_dual_normal;
		} else {
			if (swap)
				spec_share->state.dataflow =
				    sm750_simul_sec;
			else
				spec_share->state.dataflow =
				    sm750_simul_pri;
		}
	} else {
		/* SM750LE only have one crt channel */
		spec_share->state.dataflow = sm750_simul_sec;
		/* sm750le do not have complex attributes */
		spec_share->state.nocrt = 0;
	}

	LEAVE();
}


#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
static int __init lynxfb_setup(char *options)
#else
int __init lynxfb_setup(char *options)
#endif
{
	int len;
	char *opt, *tmp;
	ENTER();

	if (!options || !*options) {
		war_msg("no options.\n");
		LEAVE(0);
	}

	inf_msg("options:%s\n", options);

	len = strlen(options) + 1;
	g_settings = kmalloc(len, GFP_KERNEL);
	if (!g_settings)
		LEAVE(-ENOMEM);

	memset(g_settings, 0, len);
	tmp = g_settings;

	/*      Notes:
	   char *strsep(char **s, const char *ct);
	   @s: the string to be searched
	   @ct :the characters to search for

	   strsep() updates @options to pointer after the first found token
	   it also returns the pointer ahead the token.
	 */
	while ((opt = strsep(&options, ":")) != NULL) {
		/* options that mean for any lynx chips are configured here */
		if (!strncmp(opt, "noaccel", strlen("noaccel")))
			g_noaccel = 1;
#ifdef CONFIG_MTRR
		else if (!strncmp(opt, "nomtrr", strlen("nomtrr")))
			g_nomtrr = 1;
#endif
		else if (!strncmp(opt, "dual", strlen("dual")))
			g_dualview = 1;
		else {
			strcat(tmp, opt);
			tmp += strlen(opt);
			if (options != NULL)
				*tmp++ = ':';
			else
				*tmp++ = 0;
		}
	}

	/* misc g_settings are transport to chip specific routines */
	inf_msg("parameter left for chip specific analysis:%s\n",
		g_settings);
	LEAVE(0);
}

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
static int __init lynxfb_init()
{
	char *option;
	int ret;
	smi_indent = 0;
	ENTER();
#ifdef MODULE
	option = g_option;
#else
	if (fb_get_options("lynxfb", &option))
		LEAVE(-ENODEV);
#endif

	lynxfb_setup(option);
	ret = pci_register_driver(&lynxfb_driver);
	LEAVE(ret);
}
#else				/* kernel version >= 2.6.10 */
int __init lynxfb_init(void)
{
	char *option;
	int ret;
	smi_indent = 0;
	ENTER();
	claim();
#ifdef MODULE
	option = g_option;
	lynxfb_setup(option);
#else
	/* do nothing */
#endif
	ret = pci_register_driver(&lynxfb_driver);
	LEAVE(ret);
}
#endif
module_init(lynxfb_init);

#ifdef MODULE
static void __exit lynxfb_exit()
{
	ENTER();
	inf_msg(_moduleName_ " exit\n");
	pci_unregister_driver(&lynxfb_driver);
	LEAVE();
}

module_exit(lynxfb_exit);
#endif

#ifdef MODULE
#if LINUX_VERSION_CODE > KERNEL_VERSION(2, 6, 10)
module_param(g_option, charp, S_IRUGO);
#else
	/* be ware that PARM and param */
MODULE_PARM(g_option, "s");
#endif

MODULE_PARM_DESC(g_option,
		 "\n\t\tCommon options:\n"
		 "\t\tnoaccel:disable 2d capabilities\n"
		 "\t\tnomtrr:disable MTRR attribute for video memory\n"
		 "\t\tdualview:dual frame buffer feature enabled\n"
		 "\t\tnohwc:disable hardware cursor\n"
		 "\t\tUsual example:\n"
		 "\t\tinsmod ./lynxfb.ko g_option=\"noaccel, nohwc, 1280x1024-8@60\"\n"
		 "\t\tFor more detail chip specific options, please refer to \"Lynxfb User Mnual\" or readme\n");
#endif

MODULE_AUTHOR("monk liu<monk.liu@siliconmotion.com>");
MODULE_DESCRIPTION("Frame buffer driver for SMI(R) " SUPPORT_CHIP
		   " chipsets");
MODULE_LICENSE("Dual BSD/GPL");
MODULE_DEVICE_TABLE(pci, smi_pci_table);
