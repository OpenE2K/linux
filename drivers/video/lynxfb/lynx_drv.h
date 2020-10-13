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
#ifndef LYNXDRV_H_
#define LYNXDRV_H_


#define DEBUG		0

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 17)
#else
typedef unsigned long resource_size_t;
#endif

#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
#else
#define SEPARATOR 1
typedef int pm_message_t;
#endif

/* please use revision id to distinguish sm750le and sm750*/
#define SPC_SM750 	0
#define SPC_SM712 	1
#define SPC_SM502   2
/*#define SPC_SM750LE 8*/

#define PCI_VENDOR_ID_SMI 	0x126f
#define PCI_DEVID_LYNX_EXP	0x0750
#define PCI_DEVID_LYNX_SE	0x0718
#define PCI_DEVID_LYNX_EM	0x0712
#define PCI_DEVID_LYNX_3DM	0x0720
#define PCI_DEVID_VOYAGER 	0x0501

/*#define SUPPORT_ARCH "x86, x86_64"*/
/*#define SUPPORT_CHIP "lynx Express(750)/lynx 750LE/Lynx SE(718)/Lynx EM(712)/lynx 3DM(720/722) voyager(502/107)"*/

/*#define _version_	"4.0.1"*/
#define _moduleName_ "lynxfb"
#define PFX _moduleName_ ": "
#define err_msg(fmt, args...) printk(KERN_ERR PFX fmt, ## args)
#define war_msg(fmt, args...) printk(KERN_WARNING PFX fmt, ## args)
#define inf_msg(fmt, args...) printk(KERN_INFO PFX fmt, ## args)
/* below code also works ok, but there must be no KERN_INFO prefix */
/*#define inf_msg(...) printk(__VA_ARGS__)*/

#if (DEBUG == 1)
/* debug level == 1 */
#define dbg_msg(fmt, args...) printk(KERN_DEBUG PFX fmt, ## args)
#define ENTER()	printk(KERN_DEBUG PFX "%*c %s\n", smi_indent++, '>', __func__)
#define LEAVE(...)	\
	do {				\
	printk(KERN_DEBUG PFX "%*c %s\n", --smi_indent, '<', __func__); \
	return __VA_ARGS__; \
	} while (0)

#elif (DEBUG == 2)
/* debug level == 2*/
#define dbg_msg(fmt, args...) printk(KERN_ERR PFX fmt, ## args)
#define ENTER()	printk(KERN_ERR PFX "%*c %s\n", smi_indent++, '>', __func__)

#define LEAVE(...)	\
	do {				\
	printk(KERN_ERR PFX "%*c %s\n", --smi_indent, '<', __func__); \
	return __VA_ARGS__; \
	} while (0)

#ifdef inf_msg
#undef inf_msg
#endif

#define inf_msg(fmt, args...) printk(KERN_ERR PFX fmt, ## args)
#else
/* no debug */
#define dbg_msg(...)
#define ENTER()
#define LEAVE(...)	\
	do {	\
	return __VA_ARGS__; \
	} while (0)	\

#endif

#define MB(x) ((x)<<20)
#define MHZ(x) ((x) * 1000000)
/* align should be 2, 4, 8, 16 */
#define PADDING(align, data) (((data)+(align)-1)&(~((align)-1)))
extern int smi_indent;


struct lynx_accel {
#ifdef CONFIG_FB_LYNXFB_DOMAINS
	int domain;
#endif
	/* base virtual address of DPR registers */
	void __iomem *dprBase;
	/* base virtual address of de data port */
	void __iomem *dpPortBase;

	/* function fointers */
	void (*de_init) (struct lynx_accel *);

#ifdef CONFIG_FB_LYNXFB_DOMAINS
	int (*de_wait) (int);	/* see if hardware ready to work */
#else
	int (*de_wait) (void);	/* see if hardware ready to work */
#endif

	int (*de_fillrect) (struct lynx_accel *, u32, u32, u32,
			    u32, u32, u32, u32, u32, u32);

	int (*de_copyarea) (struct lynx_accel *, u32, u32, u32, u32,
			    u32, u32, u32, u32, u32, u32, u32, u32);

	int (*de_imageblit) (struct lynx_accel *, const char *, u32, u32,
			     u32, u32, u32, u32, u32, u32, u32, u32, u32,
			     u32);

};

/* 	lynx_share stands for a presentation of two frame buffer
	that use one smi adaptor , it is similar to a basic class of C++
*/
struct lynx_share {
	/* common members */
	u16 devid;
	u8 revid;
	struct pci_dev *pdev;
	struct fb_info *fbinfo[2];
	struct lynx_accel accel;
	int accel_off;
	int dual;
#ifdef CONFIG_MTRR
	int mtrr_off;
	struct {
		int vram;
		int vram_added;
	} mtrr;
#endif
	/* all smi graphic adaptor got below attributes */
	resource_size_t vidmem_start;
	resource_size_t vidreg_start;
	resource_size_t vidmem_size;
	resource_size_t vidreg_size;
	void __iomem *pvReg;
	void __iomem *pvMem;
	/* locks */
	spinlock_t slock;
	/* function pointers */
	void (*suspend) (struct lynx_share *);
	void (*resume) (struct lynx_share *);
};

struct lynx_cursor {
	/* cursor width , height and size */
	int w;
	int h;
	int size;
	/* hardware limitation */
	int maxW;
	int maxH;
	/* base virtual address and offset  of cursor image */
	char __iomem *vstart;
	int offset;
	/* mmio addr of hw cursor */
	volatile char __iomem *mmio;
	/* the lynx_share of this adaptor */
	struct lynx_share *share;
	/* proc_routines */
	void (*enable) (struct lynx_cursor *);
	void (*disable) (struct lynx_cursor *);
	void (*setSize) (struct lynx_cursor *, int, int);
	void (*setPos) (struct lynx_cursor *, int, int);
	void (*setColor) (struct lynx_cursor *, u32, u32);
	void (*setData) (struct lynx_cursor *, u16, const u8 *,
			 const u8 *);
};

struct lynxfb_crtc {
	unsigned char __iomem *vCursor;	/*virtual address of cursor */
	unsigned char __iomem *vScreen;	/*virtual address of on_screen */
	int oCursor;		/*cursor address offset in vidmem */
	int oScreen;		/*onscreen address offset in vidmem */
	int channel;		/* which channel this crtc stands for */
	resource_size_t vidmem_size;	/* this view's video memory max size */

	/* below attributes belong to info->fix, their value depends on specific adaptor */
	u16 line_pad;		/* padding information:0, 1, 2, 4, 8, 16, ... */
	u16 xpanstep;
	u16 ypanstep;
	u16 ywrapstep;

	void *priv;
#ifdef CONFIG_FB_LYNXFB_DOMAINS
	int domain;
	int (*proc_setMode) (struct lynxfb_crtc *,
			     struct fb_var_screeninfo *,
			     struct fb_fix_screeninfo *i,
			     int);

	int (*proc_checkMode) (struct lynxfb_crtc *,
			       struct fb_var_screeninfo *,
			       int);
	int (*proc_setColReg) (struct lynxfb_crtc *, ushort, ushort,
			       ushort, ushort, int);
	void (*clear) (struct lynxfb_crtc *, int);
	/* pan display */
	int (*proc_panDisplay) (struct lynxfb_crtc *,
				const struct fb_var_screeninfo *,
				const struct fb_info *,
				int);
#else /* !CONFIG_FB_LYNXFB_DOMAINS: */
	int (*proc_setMode) (struct lynxfb_crtc *,
			     struct fb_var_screeninfo *,
			     struct fb_fix_screeninfo *);

	int (*proc_checkMode) (struct lynxfb_crtc *,
			       struct fb_var_screeninfo *);
	int (*proc_setColReg) (struct lynxfb_crtc *, ushort, ushort,
			       ushort, ushort);
	void (*clear) (struct lynxfb_crtc *);
	/* pan display */
	int (*proc_panDisplay) (struct lynxfb_crtc *,
				const struct fb_var_screeninfo *,
				const struct fb_info *);
#endif /* !CONFIG_FB_LYNXFB_DOMAINS */
	/* cursor information */
	struct lynx_cursor cursor;
};

struct lynxfb_output {
	int dpms;
	int paths;
	/*      which paths(s) this output stands for, for sm750:
	   paths=1:means output for panel paths
	   paths=2:means output for crt paths
	   paths=3:means output for both panel and crt paths
	 */

	int *channel;
	/*      which channel these outputs linked with, for sm750:
	 *channel=0 means primary channel
	 *channel=1 means secondary channel
	 output->channel ==> &crtc->channel
	 */
	void *priv;
#ifdef CONFIG_FB_LYNXFB_DOMAINS
	int domain;
	int (*proc_setMode) (struct lynxfb_output *,
			     struct fb_var_screeninfo *,
			     struct fb_fix_screeninfo *,
			     int);

	int (*proc_checkMode) (struct lynxfb_output *,
			       struct fb_var_screeninfo *,
			       int);
	int (*proc_setBLANK) (struct lynxfb_output *, int,
			       int);
	void (*clear) (struct lynxfb_output *, int);
#else /* !CONFIG_FB_LYNXFB_DOMAINS: */
	int (*proc_setMode) (struct lynxfb_output *,
			     struct fb_var_screeninfo *,
			     struct fb_fix_screeninfo *);

	int (*proc_checkMode) (struct lynxfb_output *,
			       struct fb_var_screeninfo *);
	int (*proc_setBLANK) (struct lynxfb_output *, int);
	void (*clear) (struct lynxfb_output *);
#endif /* !CONFIG_FB_LYNXFB_DOMAINS */
};

struct lynxfb_par {
	/* either 0 or 1 for dual head adaptor, 0 is the older one registered */
	int index;
	unsigned int pseudo_palette[256];
	struct lynxfb_crtc crtc;
	struct lynxfb_output output;
	struct fb_info *info;
	struct lynx_share *share;
};

#ifndef offsetof
#define offsetof(TYPE, MEMBER) ((size_t) &((TYPE *)0)->MEMBER)
#endif


#define PS_TO_HZ(ps)	\
			({ 	\
			unsigned long long hz = 1000*1000*1000*1000ULL;	\
			do_div(hz, ps);	\
			(unsigned long)hz; `})


static inline unsigned long ps_to_hz(unsigned int psvalue)
{
	unsigned long long numerator = 1000 * 1000 * 1000 * 1000ULL;
	/* 10^12 / picosecond period gives frequency in Hz */
	do_div(numerator, psvalue);
	return (unsigned long) numerator;
}



#endif
