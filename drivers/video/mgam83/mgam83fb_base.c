/* MGA-M83 framebuffer driver

 * make -C ../linux-2.6.14 SUBDIRS=$PWD modules
 *
 * Copyright (C) 2005-2006, Alexander Shmelev <ashmelev@task.sun.mcst.ru>
 *
 * To specify a video mode at bootup, use the following boot options:
 *	video=mgam83fb:<xres>x<yres>[-<bpp>][@refresh]
 * 
 * Supported resolutions: 
 *	640x480, 800x600, 1024x768, 1280x1024, 1600x1200
 * Supported depths:
 *	8bpp, 16bpp, 24bpp, 32bpp
 *
 * Details about modes can be found in Linux/Documentation/fb/modedb.txt
 *
 * History:
 *	1.0	PCI model support only
 *	1.1	SBUS model support added
 *	2.0	Linux-2.6 version
 */

/* Debuging - mga debug, dma debug */

#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/fb.h>
#include <linux/init.h>
#include <linux/proc_fs.h>
#include <linux/rmap.h>
#include <linux/dma-mapping.h>
#include <linux/interrupt.h>
#include <asm/mman.h>
#include <asm/uaccess.h>
#ifdef CONFIG_E90
#include <asm/e90.h>	
#endif
#ifdef CONFIG_E90_FASTBOOT
#include <asm/bootinfo.h>
#endif
#include <linux/pci.h>
#include <asm/io.h>
#include "mgam83fb.h"
#ifdef CONFIG_FB_SOFT_CURSOR
extern int  soft_cursor(struct fb_info *info, struct fb_cursor *cursor);
#endif
static char *mgam83fb_default_mode = "1024x768-8@60";
static int next_index = 0;
static bool use_irq = 0;

/*******************************************************************************
 * Structures
 *******************************************************************************
 */
struct mgam83fb_par {
	struct version		vers;
	int			index;		// MGAM index

	struct {
#ifdef __sparc__
		int		iospace;	// iospace
#endif
		unsigned long 	base;		// phys address
		uint8_t*	vbase;		// virtual address
		unsigned int	len;
	} mem;
	struct {
		unsigned long 	base;	// phys address
		uint8_t*	vbase;	// virtual address
		unsigned int	len;
	} mmio;
	struct {
		unsigned long 	base;	// phys address
		uint8_t*	vbase;	// virtual address
		unsigned int	len;
	} i2c;

	struct {
		void* 		kvaddr;
		unsigned long	ioaddr;
		unsigned int	size;
	} video_buf;

	struct pci_dev *pdev;
	struct fb_info* info;
	int dma_not_supported;

	/* Current videomode **************************************************/
	__u32 xres;                     // visible resolution
	__u32 yres;
	__u32 xres_virtual;             // virtual resolution
	__u32 yres_virtual;
	__u32 xoffset;                  // offset from virtual to visible
	__u32 yoffset;                  // resolution

	__u32 bits_per_pixel;           // Bits per pixel

	__u32 pixclock;                 // pixel clock in ps (pico seconds)
	__u32 left_margin;              // time from sync to picture
	__u32 right_margin;             // time from picture to sync
	__u32 upper_margin;             // time from sync to picture
	__u32 lower_margin;
	__u32 hsync_len;                // length of horizontal sync
	__u32 vsync_len;                // length of vertical sync

	__u32 sync;

	u32     pseudo_palette[16];
			
};


/*******************************************************************************
 * Prototypes
 *******************************************************************************
 */
/* Framebuffer entry points */
static int mgam83fb_check_var(struct fb_var_screeninfo* var, struct fb_info* info);
static int mgam83fb_set_par(struct fb_info* info);
static int mgam83fb_setcolreg(unsigned regno, unsigned red, unsigned green,
			unsigned blue, unsigned transp,
			struct fb_info *info);
#if defined(__e2k__)
static int mgam83fb_mmap(struct fb_info *info, struct vm_area_struct *vma);
#endif
void __proc_init( struct mgam83fb_par* p );
int mgafb_proc_write(struct file *file, const char *buffer, unsigned long count, void *data);
int mgafb_proc_read(char *buf, char **start, off_t off, int count, int *eof, void *data);
void __fb_fill ( struct mgam83fb_par* p );
void __dump_var( const struct fb_var_screeninfo* var );
void __dump_par( const struct mgam83fb_par* p );
void __dump_mmio( struct mgam83fb_par* p );

#undef MGAM_TRACE_FUNC
#ifdef MGAM_TRACE_FUNC
extern void mgam_trace_func(unsigned int i);
#define trace_func(x) mgam_trace_func(x)
#else
#define trace_func(x)
#endif

/* After the sync (FULL) bug is fixed must be removed (defined) */
#undef AFTER_FIXING_SYNC_BUG

/*******************************************************************************
 * MMIO BitBlt Module Registers
 *******************************************************************************
 */
#define REG_BB_CTRL	0x1000	/* BitBlt module control register (write only)*/
#define REG_BB_STAT	0x1000	/* BitBlt module status register (read only) */

#define REG_BB_WINDOW	0x1004	/* Operation geometry */
#define REG_BB_SADDR	0x1008	/* Source start address */
#define REG_BB_DADDR	0x100c	/* Destination start address */
#define REG_BB_PITCH	0x1010	/* */
#define REG_BB_BG	0x1014	/* Background color */
#define REG_BB_FG	0x1018	/* Foreground color */

/* BitBlt status register bits */
#define BB_STAT_PROCESS	(0x1<<31) /* 1 - processing operation, 0 - idle */
#define BB_STAT_FULL	(0x1<<30) /* 1 - pipeline full */
#define BB_STAT_DMA	(0x1<<26) /* DMA support */


#define BB_CTRL_CMD_MASK	0xC0000000
#define BB_CTRL_CMD_START		(0x1<<31)
#define BB_CTRL_CMD_ABORT		(0x1<<30)

#define BB_CTRL_HALFWORD_TWISTER	(0x1<<24)
#define BB_CTRL_BYTES_TWISTER		(0x1<<23)
#define BB_CTRL_BITS_IN_BYTE_TWISTER	(0x1<<22)

#define BB_CTRL_DDMA_EN			(0x1<<21)
#define BB_CTRL_SDMA_EN			(0x1<<20)
#define BB_CTRL_SOFFS_MASK	(0x7<<16)

/* Binary raster operations */
#define BB_CTRL_ROP_MASK		0x0000F000

#define BB_CTRL_ROP_0			(0x0<<12)	/* clear */
#define BB_CTRL_ROP_AND			(0x1<<12)	/* and */
#define BB_CTRL_ROP_NOT_SRC_AND_DST	(0x2<<12)	/* andReverse */
#define BB_CTRL_ROP_DST			(0x3<<12)	/* copy */
#define BB_CTRL_ROP_SRC_AND_NOT_DST	(0x4<<12)	/* andInverted */
#define BB_CTRL_ROP_SRC			(0x5<<12)	/* noop */
#define BB_CTRL_ROP_XOR			(0x6<<12)	/* xor */
#define BB_CTRL_ROP_OR			(0x7<<12)	/* or */
#define BB_CTRL_ROP_NOR			(0x8<<12)	/* nor */
#define BB_CTRL_ROP_NXOR		(0x9<<12)	/* equiv */
#define BB_CTRL_ROP_NOT_SRC		(0xa<<12)	/* invert */
#define BB_CTRL_ROP_NOT_SRC_OR_DST	(0xb<<12)	/* orReverse */
#define BB_CTRL_ROP_NOT_DST		(0xc<<12)	/* copyInverted */
#define BB_CTRL_ROP_SRC_OR_NOT_DST	(0xd<<12)	/* orInverted */
#define BB_CTRL_ROP_NAND		(0xe<<12)	/* nand */
#define BB_CTRL_ROP_1			(0xf<<12)	/* set */


#define BB_CTRL_HDIR	(0x1<<5)
#define BB_CTRL_VDIR	(0x1<<6)

#define BB_CTRL_CE_EN		(0x1<<0)
#define BB_CTRL_PAT_EN		(0x1<<1)
#define BB_CTRL_SFILL_EN	(0x1<<2)
#define BB_CTRL_TR_EN		(0x1<<4)

#define BB_CTRL_SRC_MODE	(0x1<<7)

#define BB_CTRL_TERM_00		(0x0<<8)
#define BB_CTRL_TERM_01		(0x1<<8)
#define BB_CTRL_TERM_10		(0x2<<8)


#define BB_CTRL_BPP_8	        (0x0<<10)
#define BB_CTRL_BPP_16	        (0x1<<10)
#define BB_CTRL_BPP_24	        (0x2<<10)
#define BB_CTRL_BPP_32	        (0x3<<10)
#ifdef __BIG_ENDIAN
#define BB_CTRL_BPP_CD_8	(BB_CTRL_BPP_8)
#define BB_CTRL_BPP_CD_16	(BB_CTRL_BPP_16 | 0x0800000)
#define BB_CTRL_BPP_CD_24	(BB_CTRL_BPP_24 | 0x1800000)
#define BB_CTRL_BPP_CD_32	(BB_CTRL_BPP_32 | 0x1800000)
#else  /* __BIG_ENDIAN */
#define BB_CTRL_BPP_CD_8	BB_CTRL_BPP_8
#define BB_CTRL_BPP_CD_16	BB_CTRL_BPP_16
#define BB_CTRL_BPP_CD_24	BB_CTRL_BPP_24
#define BB_CTRL_BPP_CD_32	BB_CTRL_BPP_32
#endif /* __BIG_ENDIAN */

/*******************************************************************************
 * MMIO Registers
 *******************************************************************************
 */
static void MMIO_WRITE( struct mgam83fb_par* p, unsigned long reg, uint32_t val )
{
	TRACE_MSG( "MMIO[0x%03lx] <= 0x%08x\n", reg, val );

	switch( p->vers.bus ) {
	case BUS_TYPE_PCI :
		writel( val, (void*)((unsigned long)p->mmio.vbase + reg) );
		break;
	default :
		printk( KERN_WARNING "Cannot write to mmio: unsupported MGA/M video card model!\n" );
	}
		
	TRACE_MSG( "Sleeping 10 msecs...\n" );
}

static uint32_t MMIO_READ( struct mgam83fb_par* p, unsigned long reg )
{
	uint32_t result;

	switch( p->vers.bus ) {
	case BUS_TYPE_PCI :
		result = readl( (void*)((unsigned long) p->mmio.vbase + reg) );
		break;
	default :
		result = ~(uint32_t)0;
		printk( KERN_WARNING "Cannot write to mmio: unsupported MGA/M video card model!\n" );
	}
	TRACE_MSG( "MMIO[0x%03lx] => 0x%08x\n", reg, result );
	return result;
}

/*******************************************************************************
 * External entry points
 *******************************************************************************
 */

static struct { struct fb_bitfield transp, red, green, blue; } ver_05_2009_colors[] = {
	{ {  0, 0, 0}, {  0, 8, 0}, { 0, 8, 0}, { 0, 8, 0} }, 	// 8bpp
	{ {  0, 0, 0}, { 11, 5, 0}, { 5, 6, 0}, { 0, 5, 0} },	// 16bpp
#ifdef __LITTLE_ENDIAN
	{ {  0, 0, 0}, { 16, 8, 0}, { 8, 8, 0}, { 0, 8, 0} },	// 24bpp
#else /* __BIG_ENDIAN */
	{ {  0, 0, 0}, { 0, 8, 0}, { 8, 8, 0}, { 16, 8, 0} },	// 24bpp
#endif
	{ { 24, 8, 0}, { 16, 8, 0}, { 8, 8, 0}, { 0, 8, 0} },	// 32bpp
};

static struct { struct fb_bitfield transp, red, green, blue; } ver_old_colors[] = {
#ifdef __LITTLE_ENDIAN
	{ {  0, 0, 0}, {  0, 8, 0}, { 0, 8, 0}, { 0, 8, 0} },	// 8bpp
	{ {  0, 0, 0}, { 11, 5, 0}, { 5, 6, 0}, { 0, 5, 0} },	// 16bpp
	{ {  0, 0, 0}, { 16, 8, 0}, { 8, 8, 0}, { 0, 8, 0} },   // 24bpp
	{ {  0, 8, 0}, {  8, 8, 0}, {16, 8, 0}, {24, 8, 0} },	// 32bpp
#else
	{ {  0, 0, 0}, {  0, 8, 0}, { 0, 8, 0}, { 0, 8, 0} },	// 8bpp
	{ {  0, 0, 0}, { 11, 5, 0}, { 5, 6, 0}, { 0, 5, 0} },	// 16bpp
	{ {  0, 0, 0}, {  0, 8, 0}, { 8, 8, 0}, {16, 8, 0} },   // 24bpp
	{ { 24, 8, 0}, { 16, 8, 0}, { 8, 8, 0}, { 0, 8, 0} },	// 32bpp
#endif /* __LITTLE_ENDIAN */
};

static struct { struct fb_bitfield transp, red, green, blue; } colors[4];

void set_up_colors_bounds(struct mgam83fb_par* p)
{
	printk("entering set_up_colors bounds routine, revision = %d\n",
		p->vers.revision);
	if (p->vers.revision >= VER_05_2009
		    && p->vers.revision != MGA_MODEL_PMUP2_0
		    && p->vers.revision != MGA_MODEL_PMUP2_1) {
		printk("using ver_05_2009_colors map\n");
		memcpy(colors, ver_05_2009_colors, sizeof(colors)); 
	} else {
		printk("using ver_old_colors map\n");
		memcpy(colors, ver_old_colors, sizeof(colors));
	}
	return;
}

static int mgam83fb_check_var(struct fb_var_screeninfo* var, struct fb_info* info)
{
	struct mgam83fb_par* p = (struct mgam83fb_par*)info->par;	
	int colors_index = (var->bits_per_pixel>>3) - 1;	// Index in colors table

	DEBUG_MSG("mgam83fb: mgam83fb_check_var start\n");	
	if ( (var->vmode & FB_VMODE_MASK) == FB_VMODE_INTERLACED ) {
		INFO_MSG( "mode %dx%dx%d rejected, interlaced not supported\n",
			var->xres, var->yres, var->bits_per_pixel);
return -EINVAL;
	}

	if ( 	var->bits_per_pixel != 8 &&
		var->bits_per_pixel != 16 &&
		var->bits_per_pixel != 24 &&
		var->bits_per_pixel != 32 ) 
	{
		INFO_MSG( "mode %dx%dx%d rejected, color depth invalid\n",
			var->xres, var->yres, var->bits_per_pixel);
		printk("mgam83fb: mgam83fb_check_var finish with error\n");
		return -EINVAL;
	}

	if (var->xres_virtual * var->yres_virtual * ( var->bits_per_pixel >> 3) > p->mem.len) {
		INFO_MSG( "mode %dx%dx%d rejected, not enough memory\n",
			var->xres, var->yres, var->bits_per_pixel);
		printk("mgam83fb: mgam83fb_check_var finish with error\n");
		return -EINVAL;
	}

	var->red 	= colors[colors_index].red;
	var->green 	= colors[colors_index].green;
	var->blue 	= colors[colors_index].blue;
	var->transp 	= colors[colors_index].transp;
	DEBUG_MSG("mgam83fb: mgam83fb_check_var finish\n");

	return 0;
}

static int __set_mode(struct mgam83fb_par *p)
{
	struct fb_info *info = p->info;
	struct fb_var_screeninfo *var = &info->var;
	int hsync = p->hsync_len;				// The Horizontal Syncronization Time (Sync Pulse )
	int hgdel = p->left_margin;				// The Horizontal Gate Delay Time (Back Porch)
	int hgate = p->xres;					// The Horizontal Gate Time (Active Time)
	int hlen = hsync + hgdel + hgate + p->right_margin;	// The Horizontal Length Time (Line Total)
	int vsync = p->vsync_len;				// The Vertical Syncronization Time (Sync Pulse )
	int vgdel = p->upper_margin;				// The Vertical Gate Delay Time (Back Porch)
	int vgate = p->yres;					// The Vertical Gate Time (Active Time)
	int vlen = vsync + vgdel + vgate + p->lower_margin;	// The Vertical Length Time (Frame total)
	int vbl = CTRL_VBL1024;					// Video Memory Burst Length
	int ctrl = CTRL_BL_NEG | vbl;


	CHECKPOINT_ENTER;

	/* MGA device always works in little endian mode */
	switch( p->bits_per_pixel ) {
	case 8 :
		ctrl |= CTRL_CD_8BPP | CTRL_PC_PSEUDO;
		break;
	case 16 :
		ctrl |= CTRL_CD_16BPP;
		if (p->vers.revision >= VER_05_2009
		    && p->vers.revision != MGA_MODEL_PMUP2_0
		    && p->vers.revision != MGA_MODEL_PMUP2_1){	
#ifdef __LITTLE_ENDIAN
			/* Turn off bytes-in-half word twister (seted by default) */
			ctrl |= CTRL_IN_WORDS16_TWISTER;
#endif
		}
		break;
	case 24 :
		ctrl |= CTRL_CD_24BPP;
                DEBUG_MSG("mga: revision = %d\n", p->vers.revision);
		if (p->vers.revision >= VER_05_2009
		    && p->vers.revision != MGA_MODEL_PMUP2_0
		    && p->vers.revision != MGA_MODEL_PMUP2_1){
#ifndef  __LITTLE_ENDIAN
			DEBUG_MSG("mga: New version! not __LE\n");
			DEBUG_MSG("ctrl to setup is 0x%x\n", ctrl);
#endif
		}
		break;
	case 32 :
		ctrl |= CTRL_CD_32BPP;
		if (p->vers.revision >= VER_05_2009
		    && p->vers.revision != MGA_MODEL_PMUP2_0
		    && p->vers.revision != MGA_MODEL_PMUP2_1){
#ifdef __LITTLE_ENDIAN
			/* Turn off half words twister (seted by default ) */
			ctrl |= CTRL_WORDS16_IN_WORDS32_TWISTER;
			/* Turn off bytes-in-half word twister (seted by default) */
			ctrl |= CTRL_IN_WORDS16_TWISTER;
#endif
		}
		break;
	default:
		ERROR_MSG( "Invalid color depth: %s %s %d\n", __FILE__, __FUNCTION__, __LINE__ );
		CHECKPOINT_LEAVE;
		return -EINVAL;
	}

	ctrl |= ( p->sync & FB_SYNC_COMP_HIGH_ACT ) ? CTRL_CSYNC_HIGH : CTRL_CSYNC_LOW;
	ctrl |= ( p->sync & FB_SYNC_VERT_HIGH_ACT ) ? CTRL_VSYNC_HIGH : CTRL_VSYNC_LOW;
	ctrl |= ( p->sync & FB_SYNC_HOR_HIGH_ACT  ) ? CTRL_HSYNC_HIGH : CTRL_HSYNC_LOW;

	hsync--, hgdel--, hgate--, vsync--, vgdel--, vgate--, hlen--, vlen--;
	trace_func(18);
	MMIO_WRITE( p, REG_CTRL, ctrl );
	mdelay(1);
	trace_func(19);
	MMIO_WRITE( p, REG_HTIM, hsync << 24 | hgdel << 16 | hgate );
	trace_func(20);
	MMIO_WRITE( p, REG_VTIM, vsync << 24 | vgdel << 16 | vgate );
	trace_func(21);
	MMIO_WRITE( p, REG_HVLEN, hlen << 16 | vlen );
	trace_func(22);
	MMIO_WRITE(p, REG_VBARa, var->yoffset * info->fix.line_length);

	DEBUG_MSG( "hsync: %d hgdel: %d hgate %d\n", hsync, hgdel, hgate );
	DEBUG_MSG( "vsync: %d vgdel: %d vgate %d\n", vsync, vgdel, vgate );
	DEBUG_MSG( "hlen: %d vlen: %d\n", hlen, vlen );
	trace_func(23);
	MMIO_WRITE(p, REG_CTRL, ctrl | CTRL_VEN);
	mdelay(1);

	CHECKPOINT_LEAVE;
	return 0;
}

#ifdef CONFIG_E90
# define DEBUG_MSG_SET_PAR_MODE		0
#else
# define DEBUG_MSG_SET_PAR_MODE		0
#endif
#if DEBUG_MSG_SET_PAR_MODE
# define DEBUG_MSG_SET_PAR prom_printf
#else
# define DEBUG_MSG_SET_PAR(...)
#endif

static int mgam83fb_set_par(struct fb_info* info)
{
	struct fb_var_screeninfo* mode = &info->var;
	struct mgam83fb_par* p = (struct mgam83fb_par*)info->par;	

	CHECKPOINT_ENTER;

	DEBUG_MSG_SET_PAR("mgam83fb_set_par: start\n");
	/* Update fix */
	info->fix.visual	= (mode->bits_per_pixel == 8) ? FB_VISUAL_PSEUDOCOLOR : FB_VISUAL_TRUECOLOR;
	info->fix.line_length	= mode->xres_virtual * (mode->bits_per_pixel >> 3) ;

	/* Update par */
	p->xres			= mode->xres;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->xres = 0x%x\n", p->xres);
	p->yres			= mode->yres;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->yres = 0x%x\n", p->yres);
	p->xres_virtual		= mode->xres_virtual;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->xres_virtual = 0x%x\n", p->xres_virtual);
	p->yres_virtual		= mode->yres_virtual;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->yres_virtual = 0x%x\n", p->yres_virtual);
	p->xoffset		= mode->xoffset;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->xoffset = 0x%x\n", p->xoffset);
	p->yoffset		= mode->yoffset;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->yoffset = 0x%x\n", p->yoffset);
	p->left_margin		= mode->left_margin;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->left_margin = 0x%x\n", p->left_margin);
	p->right_margin		= mode->right_margin;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->right_margin = 0x%x\n", p->right_margin);
	p->hsync_len		= mode->hsync_len;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->hsync_len = 0x%x\n", p->hsync_len);
	p->upper_margin		= mode->upper_margin;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->upper_margin = 0x%x\n", p->upper_margin);
	p->lower_margin		= mode->lower_margin;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->lower_margin = 0x%x\n",	p->lower_margin );
	p->vsync_len		= mode->vsync_len;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->vsync_len = 0x%x\n", p->vsync_len);
	p->bits_per_pixel	= mode->bits_per_pixel;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->bits_per_pixel = 0x%x\n", p->bits_per_pixel);
	p->pixclock		= mode->pixclock;
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->pixclock = 0x%x\n", p->pixclock);
	DEBUG_MSG_SET_PAR("mgam83fb_set_par: p->sync = 0x%x\n", p->sync);	

#ifdef MGA_DEBUG
	__dump_par( p );
#endif
	DEBUG_MSG_SET_PAR( KERN_DEBUG " xres:%d yres:%d xvirt:%d yvirt:%d bpp:%d\n",
		p->xres, p->yres,
		p->xres_virtual, p->yres_virtual, p->bits_per_pixel);
	DEBUG_MSG_SET_PAR( KERN_DEBUG " pixclock:%d left:%d right:%d upper:%d "
		"lower:%d hslen:%d vslen:%d\n",
		p->pixclock, p->left_margin, p->right_margin,
		p->upper_margin, p->lower_margin,
		p->hsync_len, p->vsync_len);

	/* Turning of display*/
	MMIO_WRITE(p, REG_CTRL, MMIO_READ(p, REG_CTRL) & ~CTRL_VEN);

	trace_func(3);	
	__set_pixclock( &p->vers, (unsigned long)p->i2c.vbase, p->pixclock );
	trace_func(17);
	__set_mode( p );
	trace_func(24);

#ifdef MGA_DEBUG
	__dump_mmio( p );
#endif
	DEBUG_MSG_SET_PAR("mgam83fb_set_par finish\n");
	return 0;
}


static int mgam83_get_cmap_len(int bpp)
{
	switch(bpp) {
	case 8:		return 256;	/* pseudocolor... 256 entries HW palette */
	case 16:
	case 24:
	case 32:	return 16;	/* directcolor... 16 entries SW palette */
	default:	return 0;
	}
}

static inline u16 flip_16 (u16 l)
{
	return ((l&0xff)<<8) | ((l>>8)&0xff);
}

static int mgam83fb_setcolreg(unsigned regno, unsigned red, unsigned green,
			   unsigned blue, unsigned transp,
			   struct fb_info *info)
{
	struct mgam83fb_par* p = (struct mgam83fb_par*)info->par;	

	trace_func(25);
	DEBUG_MSG("mgam83fb_setcolreg start\n");
	if (regno >= mgam83_get_cmap_len(p->bits_per_pixel)){  /* no. of hw registers */
		DEBUG_MSG("mgam83fb: mgam83fb_setcolreg finish with error\n");
		return -EINVAL;
	}
	/* grayscale works only partially under directcolor */
	if (info->var.grayscale) {
		/* grayscale = 0.30*R + 0.59*G + 0.11*B */
		red = green = blue = (red * 77 + green * 151 + blue * 28) >> 8;
	}

	red 	>>= (16 - info->var.red.length);
	green 	>>= (16 - info->var.green.length);
	blue 	>>= (16 - info->var.blue.length);
	transp 	>>= (16 - info->var.transp.length);

	if (info->fix.visual == FB_VISUAL_PSEUDOCOLOR) {
		uint32_t val = (red << 16) | (green << 8) | blue;
		DEBUG_MSG("Using pseudocolors\n");
		// using CLUT0
		trace_func(26);
		MMIO_WRITE( p, 0x800 + regno * 4, val );
	}

	/* Truecolor has hardware independent palette */
	if (info->fix.visual == FB_VISUAL_TRUECOLOR) {
		u32 v;

		DEBUG_MSG("Using truecolors\n");
		if (regno >= 16){
			INFO_MSG("mgam83fb_setcolreg finish "
			       "with error, regno = 0x%x\n", regno);
			return -EINVAL;
		}

		v = 	(red << info->var.red.offset) |
			(green << info->var.green.offset) |
			(blue << info->var.blue.offset) |
			(transp << info->var.transp.offset);
		DEBUG_MSG("setcolreg: red off = %d, green off = %d,"
			"blue off = %d, v = 0x%x\n", info->var.red.offset,
			info->var.green.offset, info->var.blue.offset, v);
		if (p->vers.revision < VER_05_2009){
#ifdef __LITTLE_ENDIAN
			if (p->bits_per_pixel == 16){
				u16 tmp_v = 0;
				tmp_v = (u16)v;
				v = flip_16(tmp_v);
			}
#endif
		}
			// 16bpp, 24bpp or 32bpp
		trace_func(27);
		((u32*)(info->pseudo_palette))[regno] = v;
	}
	trace_func(28);
	DEBUG_MSG("mgam83fb_setcolreg finish\n");
	return 0;
}

struct dma_mem {
	unsigned long phys_addr;	/* dma addr */
	size_t size;
};

struct dma_mem32 {
	u32 phys_addr;        /* dma addr */
	unsigned int size;
};

struct ker_dma_mem {
	unsigned long phys_addr;	/* dma addr */
	void * kvaddr;
	void *mapaddr;
	size_t size;
	struct ker_dma_mem *next;
};

#define FBIOALLOC_DMA_MEM	0x4631
#define FBIOFREE_ALL_DMA_MEMS	0x4632
#define FBIOWHOAMI		0x4633

#define	DEBUG_IOCTL_MSG_ON	0
#define DEBUG_IOCTL_MSG		if (DEBUG_IOCTL_MSG_ON)	printk

static int 
mgam83fb_ioctl(struct fb_info *info,
			unsigned int cmd, unsigned long arg)
{
	void		*kvaddr = NULL;
	struct dma_mem		dmem;
	int	order;	
	struct page *map, *mapend;
	struct mgam83fb_par* par = (struct mgam83fb_par*)info->par;
	void __user *argp = (void __user *)arg;

	DEBUG_IOCTL_MSG("mgam83fb_ioctl: cmd = 0x%x\n", cmd);
	switch (cmd) {
	   case FBIOWHOAMI:
		return 0;
	   case FBIOALLOC_DMA_MEM:
		if (!par->video_buf.ioaddr) {
	                if (copy_from_user(&dmem, argp, sizeof(dmem))) {
				DEBUG_IOCTL_MSG("mgam83fb_ioctl: can't copy_from_user\n");
				return -EFAULT;
			}
			DEBUG_IOCTL_MSG("mgam83fb_ioctl: Ask to alloc 0x%lx bytes\n", (unsigned long)dmem.size);
			order = get_order(dmem.size);
			if (order >= MAX_ORDER) {
				DEBUG_IOCTL_MSG("mgam83fb_ioctl: order fail\n");
				return -ENOMEM;
			}
			DEBUG_IOCTL_MSG("mgam83fb_ioctl: order = %d\n", order);
			kvaddr = (void *)__get_free_pages(GFP_KERNEL | GFP_DMA, order);

			if (!kvaddr){
				DEBUG_IOCTL_MSG("mgam83fb_ioctl: failed to alloc dma buffer\n");
				return -ENOMEM;
			}
			mapend = virt_to_page (kvaddr + (PAGE_SIZE << order) - 1);
			for (map = virt_to_page(kvaddr); map <= mapend; map++) {
				SetPageReserved(map);
			}
			par->video_buf.ioaddr = pci_map_single(par->pdev, (void *)kvaddr, dmem.size,
							PCI_DMA_BIDIRECTIONAL);
			
			par->video_buf.kvaddr = kvaddr;
			dmem.phys_addr = par->video_buf.ioaddr;
			par->video_buf.size = dmem.size;
		} else {
			dmem.size = par->video_buf.size;
			dmem.phys_addr = par->video_buf.ioaddr;
		}
		DEBUG_IOCTL_MSG("FBIOALLOC_DMA_MEM: kvaddr = 0x%08lx; dmem.phys_addr = 0x%08lx\n",
				(unsigned long)par->video_buf.kvaddr, dmem.phys_addr);

		if (copy_to_user(argp, &dmem, sizeof(dmem))){
			DEBUG_IOCTL_MSG("mgam83fb_ioctl: failed to copy_to_user\n");
			return -EFAULT;
		}		
		return 0;
	   default:
		DEBUG_IOCTL_MSG("Unsupported cmd 0x%x\n", cmd);
		return -EINVAL;
	}
}


#ifdef CONFIG_COMPAT
static int
mgam83fb_compat_ioctl(struct fb_info *info, unsigned int cmd,
		      unsigned long arg)
{
	unsigned long kvaddr;
	struct dma_mem32	dmem;
	int	order;
	struct page *map, *mapend;
	struct mgam83fb_par* par = (struct mgam83fb_par*)info->par;
	void __user *argp = (void __user *)arg;

	switch (cmd) {
	    case FBIOWHOAMI:
		return 0;
	    case FBIOALLOC_DMA_MEM:
		if (!par->video_buf.ioaddr) {
			if (copy_from_user(&dmem, argp, sizeof(dmem))) {
				return -EFAULT;
			}
			DEBUG_IOCTL_MSG("mgam83fbicompat__ioctl: Ask to alloc 0x%x bytes\n", dmem.size);
			order = get_order(dmem.size);
			if (order >= MAX_ORDER) {
				DEBUG_IOCTL_MSG("mgam83fb_ioctl: order fail\n");
				return -ENOMEM;
			}

			kvaddr = __get_free_pages(GFP_KERNEL | GFP_DMA, order);

			if (!kvaddr){
				DEBUG_IOCTL_MSG("mgam83fb_compat__ioctl: failed to alloc dma buffer\n");
				return -ENOMEM;
			}
			mapend = virt_to_page (kvaddr + (PAGE_SIZE << order) - 1);
			for (map = virt_to_page(kvaddr); map <= mapend; map++) {
				SetPageReserved(map);
			}
			par->video_buf.ioaddr = pci_map_single(par->pdev, (void *)kvaddr, dmem.size,
							PCI_DMA_BIDIRECTIONAL);
			par->video_buf.kvaddr = (void *) kvaddr;
			par->video_buf.size = dmem.size;
			dmem.phys_addr = (u32)par->video_buf.ioaddr;
		} else {
			dmem.size = par->video_buf.size;
			dmem.phys_addr = (u32)par->video_buf.ioaddr;
		}
		DEBUG_IOCTL_MSG("FBIOALLOC_DMA_MEM: kvaddr = 0x%08lx; dmem.phys_addr = 0x%08x / 0x%08lx\n",
			(unsigned long)par->video_buf.kvaddr, dmem.phys_addr, par->video_buf.ioaddr);

		if (copy_to_user(argp, &dmem, sizeof(dmem))){
			DEBUG_IOCTL_MSG("mgam83fb_compat_ioctl: failed to copy_to_user\n");
			return -EFAULT;
		}
		return 0;
	    default:
		return -ENOIOCTLCMD;
	}
}
#endif

#define	DEBUG_MMAP_MSG_ON	0
#define DEBUG_MMAP_MSG		if (DEBUG_MMAP_MSG_ON)	printk

static int mgam83fb_mmap(struct fb_info *info, struct vm_area_struct *vma)
{
	unsigned long off;
	unsigned long start;
	struct mgam83fb_par* p = (struct mgam83fb_par*)info->par;
	u32 len;
	unsigned long pfn;

	off = vma->vm_pgoff << PAGE_SHIFT;

	vma->vm_pgoff = off >> PAGE_SHIFT;
	/* frame buffer memory */
	start = info->fix.smem_start;
	len = PAGE_ALIGN((start & ~PAGE_MASK) + info->fix.smem_len);
	DEBUG_MMAP_MSG("mgam83fb_mmap: start = 0x%lx, off = 0x%lx, len = 0x%x\n", 
							start, off, len);
	/* off that's in range of 0..."fb len" corresponds to framebuffer  */
	/* off that's in range of "fb len"..."io len" corresponds to mmio */
	if (off < len) {
		DEBUG_MMAP_MSG("mgam83fb_mmap: given off corresponds to fbmem\n");
#ifdef CONFIG_E2K
		vma->vm_page_prot = (cpu_has(CPU_FEAT_WC_PCI_PREFETCH)) ?
				pgprot_writecombine(vma->vm_page_prot) :
				pgprot_noncached(vma->vm_page_prot);
#endif
	}

	if ((off >= len) && (off < 0x80000000)) {
		/* memory mapped io */
		DEBUG_MMAP_MSG("mgam83fb_mmap: given off corresponds to mmio\n");
		off -= len;
		start = info->fix.mmio_start;
		len = PAGE_ALIGN((start & ~PAGE_MASK) + info->fix.mmio_len);
#ifdef CONFIG_E2K
		vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#endif
	}

	if (off >= 0x80000000) {
		if (vma->vm_end - vma->vm_start > p->video_buf.size) {
                        DEBUG_MMAP_MSG("%s: Len to map too big 0x%x > 0x%x\n", 
					__FUNCTION__, len, p->video_buf.size);
			return -EINVAL;
		}
		if (!p->video_buf.ioaddr) {
			DEBUG_MMAP_MSG("%s: Video buf not allocated\n", __FUNCTION__);
			return -ENOMEM;
		}
		off = virt_to_phys(p->video_buf.kvaddr);
		DEBUG_MMAP_MSG("%s: dvma_pha = 0x%08lx\n", __FUNCTION__, off);
		vma->vm_pgoff = off >> PAGE_SHIFT;
		vma->vm_flags |= VM_IO;
#if defined(__e2k__)
		if (vma->vm_flags & VM_WRITECOMBINED)
			vma->vm_page_prot =
				pgprot_writecombine(vma->vm_page_prot);
#endif
		if (remap_pfn_range(vma, vma->vm_start,
                                off >> PAGE_SHIFT,
                                vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
			DEBUG_MMAP_MSG("Mapping failed\n");
                       return -EAGAIN;
                }

		DEBUG_MMAP_MSG("mgam83fb_mmap: mapping done successfully"
			" to addr 0x%08lx\n", vma->vm_start);
		return 0;	
	}

	start &= PAGE_MASK;
	if ((off + vma->vm_end - vma->vm_start) > len)
		return -EINVAL;

	off += start;
	vma->vm_pgoff = off >> PAGE_SHIFT;
	/* This is an IO map - tell maydump to skip this VMA */
	vma->vm_flags |= VM_IO | VM_IO;

#if !defined(__e2k__) 
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#endif

	DEBUG_MMAP_MSG("%s: mapping iospace 0x%08lx to 0x%08lx - 0x%08lx\n",
		__FUNCTION__, off, vma->vm_start,  vma->vm_end);
#ifdef CONFIG_E90
	pfn = MK_IOSPACE_PFN(0xa, (off >> PAGE_SHIFT));
#else
	pfn = off >> PAGE_SHIFT;
#endif
	if (io_remap_pfn_range(vma, vma->vm_start, pfn,
			     	vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
		DEBUG_MMAP_MSG("Mapping failed\n");
		return -EAGAIN;
	}

	return 0;
}

struct dma_image {
	unsigned long 	virt_addr;
	dma_addr_t	dma_addr;
	size_t		size;
};

static unsigned int rnum = 0;
static struct dma_image d_image[2];


static inline void mgam83fb_do_sync(struct mgam83fb_par *p)
{
	while (MMIO_READ(p, BBR0) & PROCESS)
		barrier();
}

#ifdef CONFIG_MGA_HWIMAGEBLIT

#define FB_WRITEL fb_writel
#define FB_READL  fb_readl


static int expand_dma_buf(struct pci_dev *dev, struct dma_image *d,
			  size_t size)
{
	struct page *map, *mapend;
	int order;

	/* Free previous allocated pages */
	if (d->size != 0) {
		mapend = virt_to_page(d->virt_addr + d->size - 1);

		for (map = virt_to_page(d->virt_addr); map <= mapend; map++)
			ClearPageReserved(map);

		pci_unmap_single(dev, d->dma_addr, d->size, PCI_DMA_FROMDEVICE);
		free_pages(d->virt_addr, get_order(d->size));
	}

	/* Allocate new pages */
	order = get_order(size);
	size  = PAGE_SIZE << order;

	d->virt_addr = __get_free_pages(GFP_KERNEL | GFP_DMA, order);
	if (!d->virt_addr)
		goto zero_d;

	mapend = virt_to_page(d->virt_addr + size - 1);
	for (map = virt_to_page(d->virt_addr); map <= mapend; map++)
		SetPageReserved(map);
	d->dma_addr = pci_map_single(dev, (void *)d->virt_addr,
				     size, PCI_DMA_FROMDEVICE);
	if (pci_dma_mapping_error(dev, d->dma_addr))
		goto clear_page;

	d->size = size;

	return 0;

clear_page:
	for (map = virt_to_page(d->virt_addr); map <= mapend; map++)
		ClearPageReserved(map);

	free_pages(d->virt_addr, order);
zero_d:
	d->size = 0;
	d->virt_addr = 0;
	d->dma_addr = 0;
	return -ENOMEM;
}

static void mgam83fb_imageblit(struct fb_info *p, const struct fb_image *image)
{
	struct mgam83fb_par* par = (struct mgam83fb_par*)p->par;
	u32 fgcolor, bgcolor;
	u32 Bpp = p->var.bits_per_pixel / 8;
	u32 dx, dy, width, height;
	size_t size;
	unsigned line_length; /* bytes per line */
	u32 dst_idx, src_idx;
	u8 *sf, *st;
	unsigned cbpp;
	unsigned ctrl = BB_CTRL_CE_EN | BB_CTRL_SDMA_EN |
			BB_CTRL_CMD_START | BB_CTRL_ROP_SRC |
			BB_CTRL_SRC_MODE | BITS_IN_BYTE_TWISTER;

	if (p->state != FBINFO_STATE_RUNNING)
		return;

	if (par->vers.revision < VER_05_2009 ||
	    par->vers.revision == MGA_MODEL_PMUP2_0 ||
	    par->vers.revision == MGA_MODEL_PMUP2_1) {
		cfb_imageblit(p, image);
		return;
	}

	if (par->dma_not_supported) {
		cfb_imageblit(p, image);
		return;
	}

	if ((p->flags & FBINFO_HWACCEL_DISABLED)) {
		cfb_imageblit(p, image);
		return;
	}

	switch (Bpp) {
	case 4:
		cbpp = BB_CTRL_BPP_32;
		break;
	case 3:
		cbpp = BB_CTRL_BPP_24;
		break;
	case 2:
		cbpp = BB_CTRL_BPP_16;
		break;
	case 1:
		cbpp = BB_CTRL_BPP_8;
		break;
	default:
		return;
	};

	dx = image->dx;
	dy = image->dy;

	width  = image->width;
	height = image->height;

	size = width * height * Bpp; /* Size in bytes */

	if (d_image[rnum].size < size) {
		if (expand_dma_buf(par->pdev, &d_image[rnum], size)) {
			cfb_imageblit(p, image);
			return;
		}
	}

	st = (u8 *)d_image[rnum].virt_addr;
	sf = (u8 *)image->data;

	mgam83fb_do_sync(par);

	memcpy(st, sf, size);

	line_length = p->var.xres_virtual * Bpp;
	src_idx = d_image[rnum].dma_addr;
	dst_idx = dy * line_length + dx  * Bpp;

	if (p->fix.visual == FB_VISUAL_TRUECOLOR ||
		p->fix.visual == FB_VISUAL_DIRECTCOLOR) {
		fgcolor = ((u32 *)(p->pseudo_palette))[image->fg_color];
		bgcolor = ((u32 *)(p->pseudo_palette))[image->bg_color];
	} else {
		fgcolor = image->fg_color;
		bgcolor = image->bg_color;
	}

	MMIO_WRITE(par, REG_BB_FG, fgcolor);
	MMIO_WRITE(par, REG_BB_BG, bgcolor);
	MMIO_WRITE(par, BBR1, ((height << 16) | width * Bpp));
	MMIO_WRITE(par, BBR2, src_idx);
	MMIO_WRITE(par, BBR3, dst_idx);
	MMIO_WRITE(par, BBR4, (line_length << 16));

	ctrl |= cbpp;

	MMIO_WRITE(par, BBR0, ctrl);

	rnum = rnum ^ 1;
}
#endif

#ifdef CONFIG_MGA_HWCOPYAREA
static void mgam83fb_copyarea(struct fb_info *info, const struct fb_copyarea *region)
{
	struct mgam83fb_par* p = (struct mgam83fb_par*)info->par;
	unsigned int line_length = info->var.xres_virtual * (info->var.bits_per_pixel >> 3);		/* Bytes */
	unsigned int command = 0;
	struct fb_copyarea modded;
	u32 dx = region->dx, dy = region->dy;
	u32 sx = region->sx, sy = region->sy;
	int dst_idx = 0, src_idx = 0;
	u32 spitch = line_length;
	u32 dpitch = line_length;
	u32 width = 0;
	u32 height = 0;
	u32 vxres, vyres;

	modded.width  = region->width;
	modded.height = region->height;

	if ((info->flags & FBINFO_HWACCEL_DISABLED)) {
		cfb_copyarea(info, region);
		return;
	}

	vxres = info->var.xres_virtual;
	vyres = info->var.yres_virtual;

	if(!region->width || !region->height ||
	   sx >= vxres || sy >= vyres ||
	   dx >= vxres || dy >= vyres)
		return;

	if(sx + modded.width > vxres)  modded.width = vxres - sx;
	if(dx + modded.width > vxres)  modded.width = vxres - dx;
	if(sy + modded.height > vyres) modded.height = vyres - sy;
	if(dy + modded.height > vyres) modded.height = vyres - dy;

	width = ((modded.width)*(info->var.bits_per_pixel >> 3)); /* window lenght in bytes */
	height = modded.height;  /* number of lines */

	if (sy < dy){
		sy = sy + height;
		dy = dy + height;
	}
	dst_idx = dy*line_length + dx*(info->var.bits_per_pixel >> 3); /* Bytes */
	src_idx = sy*line_length + sx*(info->var.bits_per_pixel >> 3); /* Bytes */

	mgam83fb_do_sync(p);

	MMIO_WRITE(p, BBR1, ((height << 16) | width));
	MMIO_WRITE(p, BBR2, src_idx);
	MMIO_WRITE(p, BBR3, dst_idx);
	MMIO_WRITE(p, BBR4, ((dpitch << 16) | spitch));

	command |= (ROP_05 | START);
	if (sy < dy){
		command |= VDIR;
	}

	MMIO_WRITE(p, BBR0, command);

}
#endif

/*
 *         fb_blank - NOT a required function. Blanks the display.
 *      @blank_mode: the blank mode we want.
 *      @info: frame buffer structure that represents a single frame buffer
 *
 *      Blank the screen if blank_mode != FB_BLANK_UNBLANK, else unblank.
 *      Return 0 if blanking succeeded, != 0 if un-/blanking failed due to
 *      e.g. a video mode which doesn't support it.
 *
 *      Implements VESA suspend and powerdown modes on hardware that supports
 *      disabling hsync/vsync:
 *
 *      FB_BLANK_NORMAL = display is blanked, syncs are on.
 *      FB_BLANK_HSYNC_SUSPEND = hsync off
 *      FB_BLANK_VSYNC_SUSPEND = vsync off
 *      FB_BLANK_POWERDOWN =  hsync and vsync off
 *
 *      If implementing this function, at least support FB_BLANK_UNBLANK.
 *      Return !0 for any modes that are unimplemented.
 *
 */
static int mgam83fb_blank(int blank, struct fb_info *info)
{
	struct mgam83fb_par *p = (struct mgam83fb_par *)info->par;
	u32 val = MMIO_READ(p, REG_CTRL);

	switch (blank) {
	case FB_BLANK_UNBLANK: /* Unblanking */
		val |= CTRL_VEN;
		break;

	case FB_BLANK_NORMAL: /* Normal blanking */
	case FB_BLANK_VSYNC_SUSPEND: /* VESA blank (vsync off) */
	case FB_BLANK_HSYNC_SUSPEND: /* VESA blank (hsync off) */
	case FB_BLANK_POWERDOWN: /* Poweroff */
		val &= ~CTRL_VEN;
		break;
	}

	MMIO_WRITE(p, REG_CTRL, val);
	return 0;
}

/*
 *      fb_fillrect - REQUIRED function. Can use generic routines if
 *			 non acclerated hardware and packed pixel based.
 *			 Draws a rectangle on the screen.
 *
 *      @info: frame buffer structure that represents a single frame buffer
 *	@region: The structure representing the rectangular region we
 *		 wish to draw to.
 *
 *	This drawing operation places/removes a retangle on the screen
 *	depending on the rastering operation with the value of color which
 *	is in the current color depth format.
 */
void mgam83fb_fillrect(struct fb_info *info, const struct fb_fillrect *rect)
{
	struct fb_var_screeninfo *var = &info->var;
	struct mgam83fb_par *p = (struct mgam83fb_par *)info->par;

	u32 x = rect->dx; u32 y = rect->dy;
	u32 height = rect->height; u32 width = rect->width;
	u32 pitch = info->fix.line_length;
	u32 Bpp = info->var.bits_per_pixel >> 3;

	u32 color = (Bpp == 1) ? rect->color :
		((u32 *) info->pseudo_palette)[rect->color];
	u32 rop = (rect->rop != ROP_COPY) ? BB_CTRL_ROP_XOR : BB_CTRL_ROP_SRC;

	u32 ctrl = rop | BB_CTRL_CE_EN | BB_CTRL_SFILL_EN
			| ((Bpp - 1) & 0x3) << 10;

	u32 daddr = var->yoffset * pitch + y * pitch + x * Bpp;

	mgam83fb_do_sync(p);

	MMIO_WRITE(p, REG_BB_FG, color);
	MMIO_WRITE(p, REG_BB_WINDOW, (height << 16) | (width * Bpp));
	MMIO_WRITE(p, REG_BB_DADDR, daddr);
	MMIO_WRITE(p, REG_BB_PITCH, pitch << 16 | 0);
	MMIO_WRITE(p, REG_BB_CTRL, ctrl | BB_CTRL_CMD_START);
}

/*
 *      pan_display - NOT a required function. Pans the display.
 *      @var: frame buffer variable screen structure
 *      @info: frame buffer structure that represents a single frame buffer
 *
 *	Pan (or wrap, depending on the `vmode' field) the display using the
 *	`xoffset' and `yoffset' fields of the `var' structure.
 *	If the values don't fit, return -EINVAL.
 *
 *      Returns negative errno on error, or zero on success.
 */
static int mgam83fb_pan_display(struct fb_var_screeninfo *var,
			      struct fb_info *info)
{
	struct mgam83fb_par *p = (struct mgam83fb_par *)info->par;
	u32 addr = var->yoffset * info->fix.line_length;

	if (var->xoffset)
		return -EINVAL;
	MMIO_WRITE(p, REG_VBARa, addr);
	return 0;
}

/*
 *	   fb_sync - NOT a required function. Normally the accel engine
 *		     for a graphics card take a specific amount of time.
 *		     Often we have to wait for the accelerator to finish
 *		     its operation before we can write to the framebuffer
 *		     so we can have consistent display output.
 *
 *      @info: frame buffer structure that represents a single frame buffer
 *
 *      If the driver has implemented its own hardware-based drawing function,
 *      implementing this function is highly recommended.
 */

static int mgam83fb_sync(struct fb_info *info)
{
	struct mgam83fb_par *p = (struct mgam83fb_par *)info->par;
	mgam83fb_do_sync(p);
	return 0;
}

/*
 * Driver initialization
 */ 

static struct fb_ops mgam83fb_ops = {
	.owner          = THIS_MODULE,

	.fb_check_var   = mgam83fb_check_var,
	.fb_set_par	= mgam83fb_set_par,
	.fb_setcolreg	= mgam83fb_setcolreg,
	.fb_blank	= mgam83fb_blank,
	.fb_ioctl	= mgam83fb_ioctl,
#ifdef CONFIG_COMPAT
	.fb_compat_ioctl = mgam83fb_compat_ioctl,
#endif
	.fb_mmap	= mgam83fb_mmap,
	.fb_pan_display	= mgam83fb_pan_display,
	.fb_sync	= mgam83fb_sync,
	.fb_fillrect    = mgam83fb_fillrect,	/*HW function*/
#ifdef CONFIG_MGA_HWCOPYAREA
	.fb_copyarea    = mgam83fb_copyarea,	/*HW function*/
#else
	.fb_copyarea    = cfb_copyarea,		/*Generic function*/
#endif		
#ifdef CONFIG_MGA_HWIMAGEBLIT
	.fb_imageblit   = mgam83fb_imageblit,	/*HW function*/
#else
	.fb_imageblit   = cfb_imageblit,	/*Generic function*/
#endif
};

static irqreturn_t mga_debug_handler(int irq, void *data)
{
	struct mgam83fb_par *p = data;
	uint32_t stat = MMIO_READ(p, REG_STAT);

	/* Check if bit 0 or bit 1 are set */
	if (stat & 0x3) {
		printk(KERN_ALERT "mga_debug_handler: stat=0x%08lx\n",
				  (unsigned long)stat);
		/*
		 * All magic constants were received from Maxim Vorontsov.
		 * See bug62291 for details.
		 */
		MMIO_WRITE(p, REG_STAT, 0xf3);
		return IRQ_HANDLED;
	}
	return IRQ_NONE;
}

static int __fb_init(struct fb_info *info)
{
	struct mgam83fb_par *p = (struct mgam83fb_par *)info->par;
	int retval;

	INFO_MSG("MEM : base 0x%08lx vbase 0x%08lx len 0x%lx\n",
		(unsigned long)p->mem.base, (unsigned long)p->mem.vbase,
		(unsigned long)p->mem.len );
	INFO_MSG("MMIO: base 0x%08lx vbase 0x%08lx len 0x%lx\n",
		(unsigned long)p->mmio.base, (unsigned long)p->mmio.vbase,
		(unsigned long)p->mmio.len );
	INFO_MSG("I2C : base 0x%08lx vbase 0x%08lx len 0x%lx\n",
		(unsigned long)p->i2c.base, (unsigned long)p->i2c.vbase,
		(unsigned long)p->i2c.len );

	/* 
	 * Here we set the screen_base to the virtual memory address
	 * for the framebuffer.
	 */
	info->screen_base = p->mem.vbase;	// Framebuffer virtual memory
	info->fbops = &mgam83fb_ops;
	
	strncpy( info->fix.id, "mcst_mga", 8 );
	info->fix.smem_start	= p->mem.base;
	info->fix.smem_len	= p->mem.len;
	info->fix.type		= FB_TYPE_PACKED_PIXELS;
	info->fix.type_aux	= 0;
	info->fix.xpanstep	= 0;
	info->fix.ypanstep	= 0;
	info->fix.ywrapstep	= 0;
	info->fix.mmio_start	= p->mmio.base;
	info->fix.mmio_len	= p->mmio.len;
	info->fix.accel		= 0;

	info->pseudo_palette = p->pseudo_palette; /* The pseudopalette is an
						   * 16-member array
						   */
	/* Set up flags to indicate what sort of acceleration driver can provide */

	info->flags = FBINFO_DEFAULT
		| FBINFO_HWACCEL_YPAN
#ifdef CONFIG_MGA_HWCOPYAREA
		| FBINFO_HWACCEL_COPYAREA
#endif
#ifdef CONFIG_MGA_HWIMAGEBLIT
		| FBINFO_HWACCEL_IMAGEBLIT
#endif
		;
	
	retval = fb_find_mode(&info->var, info, mgam83fb_default_mode,
				NULL, 0, NULL, 8);
	if (!retval || retval == 4) {
		ERROR_MSG( "fb_find_mode() failed\n");
		return -EINVAL;
	}
	INFO_MSG("default mode %dx%d-%d\n", info->var.xres, info->var.yres,
		  info->var.bits_per_pixel);

	/* Здесь инициализируется структура cmap и заполняется цветами по default
	   На регистры раскладка ложится ф-ей fb_set_cmap -> fb_setcolreg или по default
	   или пользовательская используя FBIOPUTCMAP */
	retval = fb_alloc_cmap(&info->cmap, 256, 0);
	if (retval) {
		ERROR_MSG( "unable to allocate colormap\n" );
		return -ENOMEM;
	}

	/*
	 * For drivers that can...
	 */
	/* здесь инициализируется массив fb_bitfield для цветов */
	DEBUG_MSG("__fb_init: fb_bitfield initialization\n");
	if (mgam83fb_check_var(&info->var, info)) {
		ERROR_MSG( "unable to validate variable\n" );
		return -EINVAL;
	}

	if (register_framebuffer(info) < 0) {
		ERROR_MSG( "register_framebuffer() failed\n" );
		fb_dealloc_cmap(&info->cmap);
		return -EINVAL;
	}
	INFO_MSG("fb%d: %s frame buffer device\n", info->node, info->fix.id);
	p->index = next_index++;	
#ifdef MGA_DEBUG
	__proc_init( p );
#endif

	return 0;
}

static int mgam83fb_probe(struct pci_dev *dev,
				  const struct pci_device_id *ent)
{
#ifdef CONFIG_E90
	static struct mfgid mfg;
#endif
	struct fb_info* info;
	struct mgam83fb_par* p;	
	int ret = -EINVAL;
	char revision;
	
	DEBUG_MSG("mgam83fb: pci driver_init\n");
	if ( (ret = pci_enable_device(dev)) ) {
		printk( KERN_ERR "%s: cannot enable pci device\n", pci_name(dev));
		return ret;
	}

	pci_set_master(dev);

	/*
	 * Dynamically allocate info and par
	 */
	info = framebuffer_alloc(sizeof(struct mgam83fb_par), &dev->dev );
	if (!info) {
		ERROR_MSG( "failed to allocate fb_info instance!\n");
		ret = -ENOMEM;
		goto fail;
	}
	p = info->par;
	p->vers.bus = BUS_TYPE_PCI;
	p->pdev = dev;
	p->info = info;
#ifdef CONFIG_E90
	// TODO what to do if it is sparc, but not E90?
	p->mem.iospace = PCI_IOSPACE;
#endif
	p->mem.base = pci_resource_start(dev, PCI_MEM_BAR);
	if ((ret = pci_read_config_byte(dev,  PCI_REVISION_ID, &revision))) {
		printk( KERN_ERR "%s: cannot read revision id\n", pci_name(dev));
		return ret;
	}
	if (revision == 0) {
		// This card has wrong size in bar
		p->mem.len = MGA_MEM_SIZE;
	} else {
		p->mem.len = pci_resource_len( dev, PCI_MEM_BAR );
	}

	if ( (ret = pci_request_region(dev, PCI_MEM_BAR, "mgam83 FB")) ) 
		goto fail_mem;

	p->mem.vbase = ioremap(p->mem.base, p->mem.len);

	if ( !p->mem.vbase)
	{
		ERROR_MSG( "cannot ioremap MEM (%lx, 0x%x)\n", p->mem.base, p->mem.len);
		ret = -ENOMEM;
		goto fail_ioremap_mem;
	}

	// Video card registers
	p->mmio.base	= pci_resource_start( dev, PCI_MMIO_BAR );
	p->mmio.len	= pci_resource_len( dev, PCI_MMIO_BAR );

	if ( (ret = pci_request_region(dev, PCI_MMIO_BAR, "mgam83 MMIO")) )
		goto fail_mmio;

	p->mmio.vbase = ioremap( p->mmio.base, p->mmio.len );
	if ( !p->mmio.vbase )
	{
		ERROR_MSG( "cannot ioremap MMIO (0x%08lx:0x%x)\n", p->mmio.base, p->mmio.len );
		ret = -ENOMEM;		
		goto fail_mmio_ioremap;
	}

	// I2C bus registers
	p->i2c.base	= pci_resource_start( dev, PCI_I2C_BAR );
	p->i2c.len	= pci_resource_len( dev, PCI_I2C_BAR );
	if ( (ret = pci_request_region(dev, PCI_I2C_BAR, "mgam83 I2C")) )
		goto fail_i2c;
	p->i2c.vbase = ioremap( p->i2c.base, p->i2c.len );
	if ( !p->i2c.vbase )
	{
		ERROR_MSG( "cannot ioremap I2C (0x%08lx:0x%x)\n", p->i2c.base, p->i2c.len );
		ret = -ENOMEM;
		goto fail_i2c_ioremap;
	}

	/* Debug handler (bug62291) */
	if (use_irq) {
		ret = request_irq(dev->irq, mga_debug_handler, IRQF_SHARED,
				 "mgam83", p);
		if (ret)
			goto fail_irq;
	}

	/* Mga driver version on all other machines depends on RevID 
	* in pci configuration space */
	pci_read_config_byte(dev, PCI_REVISION_ID, &p->vers.revision);
	INFO_MSG("MGA version driver from pci config space = 0x%x\n",
			p->vers.revision);
#ifdef CONFIG_E90
#ifdef  CONFIG_E90_FASTBOOT
	if (!bootblock) // OpenPROM boot
#endif
	if(p->vers.revision != MGA_MODEL_PMUP2_0
		    && p->vers.revision != MGA_MODEL_PMUP2_1) {
		get_mcst_mfgid(&mfg);
		p->vers.revision = mfg.tty1Mbit;
		printk(KERN_NOTICE "mgam83fb: MGA version driver from mfgid = 0x%x\n", 
						p->vers.revision);
	}
#endif

	set_up_colors_bounds(p);
	/* Turning of display */
	MMIO_WRITE(p, REG_CTRL, MMIO_READ(p, REG_CTRL) & ~CTRL_VEN);

	p->dma_not_supported = (MMIO_READ(p, BBR0) & DMA_SUPPORT) == 0;

	// Filling info, selecting mode and initializating framebuffer
	DEBUG_MSG("mgam83fb: framebuffer init ...\n");
	if ( (ret = __fb_init( info )) )
		goto fail_register_fb;

	pci_set_drvdata(dev, info);
	return 0;

fail_register_fb:
	if (use_irq)
		free_irq(dev->irq, p);
fail_irq:
	iounmap(p->i2c.vbase);
fail_i2c_ioremap:
	pci_release_region(dev, PCI_I2C_BAR);
fail_i2c:
	iounmap(p->mmio.vbase);
fail_mmio_ioremap:
	pci_release_region(dev, PCI_MMIO_BAR);
fail_mmio:
	iounmap(p->mem.vbase);
fail_ioremap_mem:
	pci_release_region(dev, PCI_MEM_BAR);
fail_mem:
	framebuffer_release(info);
fail:
	return ret;
}

static void mgam83fb_remove(struct pci_dev *dev)
{
	struct fb_info *info = pci_get_drvdata(dev);
	struct page *map, *mapend;
	struct mgam83fb_par* p;

	if (info == NULL) {
		return;
	}

	p = (struct mgam83fb_par*)info->par;

	if (use_irq)
		free_irq(dev->irq, p);

	if (p->video_buf.ioaddr) {
		struct page *map, *mapend;
		pci_unmap_single(p->pdev, p->video_buf.ioaddr,
			p->video_buf.size, PCI_DMA_FROMDEVICE);
		mapend = virt_to_page(p->video_buf.kvaddr + p->video_buf.size -1);
		for (map = virt_to_page(p->video_buf.kvaddr); map <= mapend; map++) {
			ClearPageReserved(map);
		}
		free_pages((unsigned long)p->video_buf.kvaddr, get_order(p->video_buf.size));
		p->video_buf.ioaddr = 0;
		p->video_buf.kvaddr = 0;
		p->video_buf.size = 0;
	}
	for (rnum = 0; rnum != 2; rnum++) {
		if (d_image[rnum].size != 0){
		        mapend = virt_to_page((d_image[rnum].virt_addr) + 
					(PAGE_SIZE << get_order(d_image[rnum].size)) - 1);
		        for (map = virt_to_page((d_image[rnum].virt_addr)); map <= mapend; map++) {
		                ClearPageReserved(map);
		        }
			pci_unmap_single(p->pdev, d_image[rnum].dma_addr, 
					d_image[rnum].size, PCI_DMA_FROMDEVICE);
			free_pages(d_image[rnum].virt_addr, get_order(d_image[rnum].size));
			d_image[rnum].size = 0;
			d_image[rnum].virt_addr = 0;
			d_image[rnum].dma_addr = 0;
		}		
	}
	/* Turning of display */
	MMIO_WRITE(p, REG_CTRL, MMIO_READ(p, REG_CTRL) & ~CTRL_VEN);

	unregister_framebuffer(info);
	fb_dealloc_cmap(&info->cmap);
	iounmap(p->i2c.vbase);
	pci_release_region(dev, PCI_I2C_BAR);
	iounmap(p->mmio.vbase);
	pci_release_region(dev, PCI_MMIO_BAR);
	iounmap(p->mem.vbase);
	pci_release_region(dev, PCI_MEM_BAR);
	framebuffer_release(info);

	/* First time when we load driver drvdata is NULL, but if we reload it,
 	 * we get garbage here, because drvdata is not cleared after driver unload
 	 */
	pci_set_drvdata(dev, NULL);	
}

static int mgam83fb_suspend(struct pci_dev *dev, pm_message_t state)
{
	return pci_save_state(dev);
}

static int mgam83fb_resume(struct pci_dev *dev)
{
	struct fb_info *info = pci_get_drvdata(dev);
	pci_restore_state(dev);
	mgam83fb_set_par(info);
	return 0;
}

static struct pci_device_id mgam83fb_devices[] = {
	{ PCI_DEVICE(PCI_VENDOR_ID_MGAM83, PCI_DEVICE_ID_MGAM83) },
	{ 0, }
};

static struct pci_driver mgam83fb_driver = {
	.name		= "mgam83fb",
	.id_table	= mgam83fb_devices,
	.probe		= mgam83fb_probe,
	.remove         = mgam83fb_remove,
	.suspend	= mgam83fb_suspend,
	.resume         = mgam83fb_resume,
};


#ifndef MODULE
static int __init mgam83fb_setup(char *options)
{
	if (!options || !*options)
		return 0;
	mgam83fb_default_mode = options;
	return 0;
}
#endif  /*  MODULE  */

static int __init mgam83fb_init(void)
{
	int pci_ret = 0;
#ifndef MODULE
	char *option = NULL;
	if (fb_get_options("mgam83fb", &option))
		return -ENODEV;
	mgam83fb_setup(option);
#endif
	DEBUG_MSG("Module initialization\n");

	pci_ret = pci_register_driver(&mgam83fb_driver);

	return 0;
}



static void mgam83fb_cleanup(void)
{
	pci_unregister_driver(&mgam83fb_driver);
}

////////////////////////////////////////////////////////////////////////////////
// Modularization
////////////////////////////////////////////////////////////////////////////////

module_init(mgam83fb_init);
module_exit(mgam83fb_cleanup);

module_param(use_irq, bool, S_IRUGO);
MODULE_PARM_DESC(use_irq, "Register interrupt handler");
MODULE_LICENSE("GPL");

#ifdef MGA_DEBUG
/*******************************************************************************
 * Debug
 *******************************************************************************
 */

void __dump_mmio( struct mgam83fb_par* p )
{

	DEBUG_MSG( "CTRL:  0x%08x\n", MMIO_READ( p, REG_CTRL) );
	DEBUG_MSG( "STAT:  0x%08x\n", MMIO_READ( p, REG_STAT) );
	DEBUG_MSG( "HTIM:  0x%08x\n", MMIO_READ( p, REG_HTIM) );
	DEBUG_MSG( "VTIM:  0x%08x\n", MMIO_READ( p, REG_VTIM) );
	DEBUG_MSG( "HVLEN: 0x%08x\n", MMIO_READ( p, REG_HVLEN) );
	DEBUG_MSG( "VBARa: 0x%08x\n", MMIO_READ( p, REG_VBARa) );
	DEBUG_MSG( "VBARb: 0x%08x\n", MMIO_READ( p, REG_VBARb) );
	DEBUG_MSG( "C0XY:  0x%08x\n", MMIO_READ( p, REG_C0XY) );
	DEBUG_MSG( "C0BAR: 0x%08x\n", MMIO_READ( p, REG_C0BAR) );
	DEBUG_MSG( "C0CR:  0x%08x\n", MMIO_READ( p, REG_C0CR) );
	DEBUG_MSG( "C1XY:  0x%08x\n", MMIO_READ( p, REG_C1XY) );
	DEBUG_MSG( "C1BAR: 0x%08x\n", MMIO_READ( p, REG_C1BAR) );
	DEBUG_MSG( "C1CR:  0x%08x\n", MMIO_READ( p, REG_C1CR) );

	if ( 8 == p->bits_per_pixel ) {
		unsigned long col_regno;
		DEBUG_MSG( "CLUT0 ==================================DUMP BEGIN\n" );
		for( col_regno = 0; col_regno < 256; col_regno++ ) {
			int val = MMIO_READ( p, 0x800 + col_regno * 4 );
			DEBUG_MSG( "%03ld: r %02x g %02x b %02x\n", col_regno, (val & 0x00FF0000) >> 16, (val & 0x0000FF00), (val & 0x000000FF) );
		}
		DEBUG_MSG( "CLUT0 ====================================DUMP END\n" );
	}
}

void __dump_par( const struct mgam83fb_par* p )
{
	char buf[256] = { 0, };
	
	int pos = 0;
	if ( p->sync & FB_SYNC_HOR_HIGH_ACT ) 
		pos += sprintf( buf + pos, "FB_SYNC_HOR_HIGH_ACT " );
	if ( p->sync & FB_SYNC_VERT_HIGH_ACT ) 
		pos += sprintf( buf + pos, "FB_SYNC_VERT_HIGH_ACT " );
	if ( p->sync & FB_SYNC_COMP_HIGH_ACT ) 
		pos += sprintf( buf + pos, "FB_SYNC_COMP_HIGH_ACT " );

	DEBUG_MSG( "mgafb_par ==============================DUMP BEGIN\n" );
	DEBUG_MSG( "Resolution: %dx%d\n", p->xres, p->yres );
	DEBUG_MSG( "Virtual resolution: %dx%d\n", p->xres_virtual, p->yres_virtual );
	DEBUG_MSG( "Offset: x %d y %d\n", p->xoffset, p->yoffset );
	DEBUG_MSG( "Bpp: %d\n", p->bits_per_pixel );
	DEBUG_MSG( "Pixclock: %d\n", p->pixclock );
	DEBUG_MSG( "Margins: left %d right %d upper %d lower %d\n", 
		p->left_margin, p->right_margin, p->upper_margin, p->lower_margin );
	DEBUG_MSG( "Sync length: horizontal %d vertical %d\n", 
		p->hsync_len, p->vsync_len );
	DEBUG_MSG( "%s\n", buf );
	DEBUG_MSG( "mgafb_par ================================DUMP END\n" );
}


void __dump_var( const struct fb_var_screeninfo* var )
{
	char buf[256] = { 0, };
	int pos = 0;
	if ( var->sync & FB_SYNC_HOR_HIGH_ACT ) 
		pos += sprintf( buf + pos, "FB_SYNC_HOR_HIGH_ACT " );
	if ( var->sync & FB_SYNC_VERT_HIGH_ACT ) 
		pos += sprintf( buf + pos, "FB_SYNC_VERT_HIGH_ACT " );
	if ( var->sync & FB_SYNC_COMP_HIGH_ACT ) 
		pos += sprintf( buf + pos, "FB_SYNC_COMP_HIGH_ACT " );

	DEBUG_MSG( "fb_var_screeninfo ======================DUMP BEGIN\n" );
	DEBUG_MSG( "Resolution: %dx%d\n", var->xres, var->yres );
	DEBUG_MSG( "Virtual resolution: %dx%d\n", var->xres_virtual, var->yres_virtual );
	DEBUG_MSG( "Offset: x %d y %d\n", var->xoffset, var->yoffset );
	DEBUG_MSG( "Bpp: %d, Grayscale: %d\n", var->bits_per_pixel, var->grayscale );
	DEBUG_MSG( "Bitfields: \n" );
	DEBUG_MSG( "     color  | offset  | length | msb_right\n" );
	DEBUG_MSG( "     red    |   %2d   |   %2d   |     %1d    \n", var->red.offset, var->red.length, var->red.msb_right ); 
	DEBUG_MSG( "     green  |   %2d   |   %2d   |     %1d    \n", var->green.offset, var->green.length, var->green.msb_right );
	DEBUG_MSG( "     blue   |   %2d   |   %2d   |     %1d    \n", var->blue.offset, var->blue.length, var->blue.msb_right );
	DEBUG_MSG( "     transp |   %2d   |   %2d   |     %1d    \n", var->transp.offset, var->transp.length, var->transp.msb_right );
	DEBUG_MSG( "Pixclock: %d\n", var->pixclock );
	DEBUG_MSG( "Margins: left %d right %d upper %d lower %d\n", 
		var->left_margin, var->right_margin, var->upper_margin, var->lower_margin );
	DEBUG_MSG( "Sync length: horizontal %d vertical %d\n", 
		var->hsync_len, var->vsync_len );
	DEBUG_MSG( "%s\n", buf );
	DEBUG_MSG( "fb_var_screeninfo ========================DUMP END\n" );
}

/*******************************************************************************
 * Proc
 *******************************************************************************
 */

#define PROC_FILENAME "mgam83_"
#define PROC_INPUT_MAX_LEN 32
#define CTRL_VBL_MASK   (~(CTRL_VBL_1 | CTRL_VBL_2 | CTRL_VBL_4 | CTRL_VBL_8 | CTRL_VBL1024))

char regs_buf[4096];

void spill_regs(struct mgam83fb_par* p){
	int len = 0;
	int i = 0;
	for (i = 0; i != 4096; i++){
		regs_buf[i] = 0;	
	}
	len += sprintf( regs_buf + len, "CTRL:  0x%08x\n", MMIO_READ( p, REG_CTRL) 	);
	len += sprintf( regs_buf + len, "STAT:  0x%08x\n", MMIO_READ( p, REG_STAT) 	);
	len += sprintf( regs_buf + len, "HTIM:  0x%08x\n", MMIO_READ( p, REG_HTIM) 	);
	len += sprintf( regs_buf + len, "VTIM:  0x%08x\n", MMIO_READ( p, REG_VTIM) 	);
	len += sprintf( regs_buf + len, "HVLEN: 0x%08x\n", MMIO_READ( p, REG_HVLEN) 	);
	len += sprintf( regs_buf + len, "VBARa: 0x%08x\n", MMIO_READ( p, REG_VBARa) 	);
	len += sprintf( regs_buf + len, "VBARb: 0x%08x\n", MMIO_READ( p, REG_VBARb) 	);
	len += sprintf( regs_buf + len, "C0XY:  0x%08x\n", MMIO_READ( p, REG_C0XY) 	);
	len += sprintf( regs_buf + len, "C0BAR: 0x%08x\n", MMIO_READ( p, REG_C0BAR) 	);
	len += sprintf( regs_buf + len, "C0CR:  0x%08x\n", MMIO_READ( p, REG_C0CR) 	);
	len += sprintf( regs_buf + len, "C1XY:  0x%08x\n", MMIO_READ( p, REG_C1XY) 	);
	len += sprintf( regs_buf + len, "C1BAR: 0x%08x\n", MMIO_READ( p, REG_C1BAR) 	);
	len += sprintf( regs_buf + len, "C1CR:  0x%08x\n", MMIO_READ( p, REG_C1CR)	);
	len += sprintf( regs_buf + len, "TST_D: 0x%08x\n", MMIO_READ( p, REG_TST_D)	);
	len += sprintf( regs_buf + len, "BBR0: 0x%08x\n", MMIO_READ( p, BBR0)           );
	len += sprintf( regs_buf + len, "BBR1: 0x%08x\n", MMIO_READ( p, BBR1)    	);
	len += sprintf( regs_buf + len, "BBR2: 0x%08x\n", MMIO_READ( p, BBR2)           );
	len += sprintf( regs_buf + len, "BBR3: 0x%08x\n", MMIO_READ( p, BBR3)           );
	len += sprintf( regs_buf + len, "BBR4: 0x%08x\n", MMIO_READ( p, BBR4)           );
	len += sprintf( regs_buf + len, "BBR5: 0x%08x\n", MMIO_READ( p, BBR5)           );
	sprintf( regs_buf + len, "BBR6: 0x%08x\n", MMIO_READ( p, BBR6)          	);
}

int mgafb_proc_read(char *buf, char **start, off_t off, int count, int *eof, void *data)
{
 	struct mgam83fb_par* p = (struct mgam83fb_par* )data;
	int len = 0;
	int i = 0;
	u32 bpp = p->info->var.bits_per_pixel;	
	size_t screen_length;
	u8 *s;
	int rgval;
	

	if ( p ) {
#if 0
		uint32_t vbl = MMIO_READ( p, REG_CTRL ) & ~CTRL_VBL_MASK;
;
		len += sprintf( buf + len, "CTRL:  0x%08x\n", MMIO_READ( p, REG_CTRL) );
		len += sprintf( buf + len, "STAT:  0x%08x\n", MMIO_READ( p, REG_STAT) );
		len += sprintf( buf + len, "HTIM:  0x%08x\n", MMIO_READ( p, REG_HTIM) );
		len += sprintf( buf + len, "VTIM:  0x%08x\n", MMIO_READ( p, REG_VTIM) );
		len += sprintf( buf + len, "HVLEN: 0x%08x\n", MMIO_READ( p, REG_HVLEN) );
		len += sprintf( buf + len, "VBARa: 0x%08x\n", MMIO_READ( p, REG_VBARa) );
		len += sprintf( buf + len, "VBARb: 0x%08x\n", MMIO_READ( p, REG_VBARb) );
		len += sprintf( buf + len, "C0XY:  0x%08x\n", MMIO_READ( p, REG_C0XY) );
		len += sprintf( buf + len, "C0BAR: 0x%08x\n", MMIO_READ( p, REG_C0BAR) );
		len += sprintf( buf + len, "C0CR:  0x%08x\n", MMIO_READ( p, REG_C0CR) );
		len += sprintf( buf + len, "C1XY:  0x%08x\n", MMIO_READ( p, REG_C1XY) );
		len += sprintf( buf + len, "C1BAR: 0x%08x\n", MMIO_READ( p, REG_C1BAR) );
		len += sprintf( buf + len, "C1CR:  0x%08x\n", MMIO_READ( p, REG_C1CR) );
		len += sprintf( buf + len, "TST_D: 0x%08x\n", MMIO_READ( p, REG_TST_D) );

		len += sprintf( buf + len, "\n" );

		switch( vbl ) {
		case CTRL_VBL_1 :
			len += sprintf( buf + len, "VBL: 1\n" );
			break;
		case CTRL_VBL_2 :
			len += sprintf( buf + len, "VBL: 2\n" );
			break;
		case CTRL_VBL_4 :
			len += sprintf( buf + len, "VBL: 4\n" );
			break;
		case CTRL_VBL_8 :
			len += sprintf( buf + len, "VBL: 8\n" );
			break;
		case CTRL_VBL1024 :
			len += sprintf( buf + len, "VBL: 1024\n" );
			break;
		default :
			len += sprintf( buf + len, "VBL: N/A\n" );
		}

		{
			clk_t clk = __calc( p->pixclock );
			len += sprintf( buf + len, "div: %d\n", clk.div );
			len += sprintf( buf + len, "q: %d\n", clk.q );
			len += sprintf( buf + len, "p: %d\n", clk.p );
			len += sprintf( buf + len, "po: %d\n", clk.po );
		}

#endif
#if 0
		if (last_info != NULL)
			cfb_copyarea(last_info, &last_area);

		if (last_info != NULL)
			mgam83fb_copyarea(last_info, &last_area);
#endif
#if 0		
		for (i = area_count; i != 10; i++){
			len += sprintf( buf + len, "dx = %d\n", 	last_area[i].dx);
			len += sprintf( buf + len, "dy = %d\n", 	last_area[i].dy);
			len += sprintf( buf + len, "sx = %d\n", 	last_area[i].sx);
			len += sprintf( buf + len, "sy = %d\n", 	last_area[i].sy);
			len += sprintf( buf + len, "width = %d\n", 	last_area[i].width);
			len += sprintf( buf + len, "height = %d\n", 	last_area[i].height);
		}
		for (i = 0; i != area_count; i++){
			len += sprintf( buf + len, "dx = %d\n", 	last_area[i].dx);
			len += sprintf( buf + len, "dy = %d\n", 	last_area[i].dy);
			len += sprintf( buf + len, "sx = %d\n", 	last_area[i].sx);
			len += sprintf( buf + len, "sy = %d\n", 	last_area[i].sy);
			len += sprintf( buf + len, "width = %d\n", 	last_area[i].width);
			len += sprintf( buf + len, "height = %d\n", 	last_area[i].height);
		}
#endif
#if 0		/* getting framebuffer into file */
		screen_length = ((p->info->var.yres_virtual) * 
			(p->info->var.xres_virtual) * 
					(bpp >> 3)); /* in bytes */
		s = (u8 *)p->info->screen_base;
		for (i = 0; i != screen_length; i++)
		{
			*buf = *s;
			buf++;
			s++;
			len++;
		}
#endif
#if 1
		/* getting reg */
		if (start == 0x100){
			if (count == 1) {rgval =  MMIO_READ(p, REG_STAT);}
			if (count == 2) {rgval =  MMIO_READ(p, REG_HTIM);}
			if (count == 3) {rgval =  MMIO_READ(p, REG_VTIM);}
			if (count == 4) {rgval =  MMIO_READ(p, REG_HVLEN);}
			if (count == 5) {rgval =  MMIO_READ(p, REG_VBARa);}
			if (count == 6) {rgval =  MMIO_READ(p, REG_VBARb);}
			if (count == 7) {rgval =  MMIO_READ(p, REG_C0XY);}
			if (count == 8) {rgval =  MMIO_READ(p, REG_C0BAR);}
			if (count == 9) {rgval =  MMIO_READ(p, REG_C0CR);}
			if (count == 10) {rgval = MMIO_READ(p, REG_C1XY);}
			if (count == 11) {rgval = MMIO_READ(p, REG_C1BAR);}
			if (count == 12) {rgval = MMIO_READ(p, REG_C1CR);}
			if (count == 13) {rgval = MMIO_READ(p, REG_TST_D);}
			if (count == 14) {rgval = MMIO_READ(p, BBR0);}	 
			if (count == 15) {rgval = MMIO_READ(p, BBR1);}	 
			if (count == 16) {rgval = MMIO_READ(p, BBR2);}	 
			if (count == 17) {rgval = MMIO_READ(p, BBR3);}	 
			if (count == 18) {rgval = MMIO_READ(p, BBR4);}	 
			if (count == 19) {rgval = MMIO_READ(p, BBR5);}
			if (count == 20) {rgval = MMIO_READ(p, BBR6);}
			
			if (count >= 32)
				return 0; 
			
			*(u32 *)buf = rgval;			
			return 4;
		}

		/* getting all regs (last values before write) */
#if 0
		if (start == 0x1000){
			s = regs_buf;
			for (i = 0; i != PAGE_SIZE; i++){
				*buf = *s;
				buf++;
				s++;
				len++;
			}
			return len;
		}
#endif
		 /* getting all regs  */
#if 1
		spill_regs(p);
                if (start == 0x1000){
                        s = regs_buf;
                        for (i = 0; i != PAGE_SIZE; i++){
                                *buf = *s;
                                buf++;
                                s++;
                                len++;
                        }
                        return len;
                }
#endif

		/* getting framebuffer */
		screen_length = ((p->info->var.yres_virtual) *
                        (p->info->var.xres_virtual) *
                                        (bpp >> 3)); /* in bytes */
		if (off >= screen_length)
				return 0;
		if (count > (screen_length - off))
			count = (screen_length - off);
		s = (u8 *)((u8 *)p->info->screen_base + off);
		for (i = 0; i != count; i++)
		{
			*buf = *s;
			buf++;
			s++;
			len++;
		}
#endif		
	}

	return len;
}


int mgafb_proc_write(struct file *file, const char *buffer, unsigned long count, void *data)
{
 	struct mgam83fb_par* p = (struct mgam83fb_par*)data;
	char kern_buf[PROC_INPUT_MAX_LEN] = { 0, };
	char *new_buf;
	unsigned int reg;
	int vbl = 0;
	int command;
	struct page *map, *mapend;
	int dpitch, spitch;

	int i = 0;
	u32 bpp = p->info->var.bits_per_pixel;	
	size_t screen_length, len;
	char *s;
	char *buf;
	char *st, *sf;
	int rgval;

#if 1 /* (writing register) */
	if (count <= 32){
		if (copy_from_user(&rgval, buffer, 4)) {
                	ERROR_MSG( "Failed to copy from user\n" );
                	return -EFAULT;
                }
	}

	if (count == 1){ 	MMIO_WRITE(p, REG_STAT, rgval);   return 4;}
	if (count == 2){ 	MMIO_WRITE( p, REG_HTIM, rgval ); return 4;}
	if (count == 3){ 	MMIO_WRITE( p, REG_VTIM, rgval ); return 4;}
	if (count == 4){ 	MMIO_WRITE( p, REG_HVLEN, rgval );return 4;}
	if (count == 5){ 	MMIO_WRITE( p, REG_VBARa, rgval );return 4;}
	if (count == 6){	MMIO_WRITE( p, REG_VBARb, rgval );return 4;}
	if (count == 7){ 	MMIO_WRITE( p, REG_C0XY, rgval ); return 4;}
	if (count == 8){ 	MMIO_WRITE( p, REG_C0BAR, rgval );return 4;}
	if (count == 9){ 	MMIO_WRITE( p, REG_C0CR, rgval ); return 4;}
	if (count == 10){ 	MMIO_WRITE( p, REG_C1XY, rgval ); return 4;}
	if (count == 11){	MMIO_WRITE( p, REG_C1BAR, rgval );return 4;}
	if (count == 12){	MMIO_WRITE( p, REG_C1CR, rgval ); return 4;}
	if (count == 13){	MMIO_WRITE( p, REG_TST_D, rgval );return 4;}
	if (count == 14){	MMIO_WRITE( p, BBR0, rgval );	  return 4;}
	if (count == 15){	MMIO_WRITE( p, BBR1, rgval );	  return 4;}
	if (count == 16){	MMIO_WRITE( p, BBR2, rgval );	  return 4;}
	if (count == 17){	MMIO_WRITE( p, BBR3, rgval );	  return 4;}
	if (count == 18){	MMIO_WRITE( p, BBR4, rgval );	  return 4;}
	if (count == 19){	MMIO_WRITE( p, BBR5, rgval );	  return 4;}
	if (count == 20){	MMIO_WRITE( p, BBR6, rgval );	  return 4;}
	if (count == 21){       MMIO_WRITE(p, REG_CTRL, rgval);
				mdelay(1);			  return 4;}
	
	if (count <= 32)
		return 0;
#endif
#if 0
        if ( !count || count > PROC_INPUT_MAX_LEN ) {
		ERROR_MSG( "Command length is too big\n" );
		return -EINVAL;
	}
        if ( copy_from_user( &kern_buf, buffer, count ) ) {
		ERROR_MSG( "Failed to copy from user\n" );
                return -EFAULT;
	}

	if ( sscanf( kern_buf, "CTRL=0x%x", &reg ) == 1 || sscanf( kern_buf, "CTRL=0x%x", &reg ) == 1 ) {
		DEBUG_MSG( "CTRL <= 0x%x\n", reg );	
		MMIO_WRITE( p, REG_CTRL, reg );
//	} else if ( sscanf( kern_buf, "FB=%d", &fb_cmd ) == 1 ) {
//		DEBUG_MSG( "Unregistering FB..." );
//		if ( unregister_framebuffer( &p->gen.info ) ) {
//		    printk( "Failed\n" );
//		} else {
//		    printk( "Ok\n" );
//		    p->fb_registered = 0;
//		}
	} else {
		int enabled = MMIO_READ( p, REG_CTRL ) & CTRL_VEN;
		unsigned int offset;
//		int index, time;
		MMIO_WRITE( p, REG_CTRL, MMIO_READ( p, REG_CTRL ) & ~CTRL_VEN );

		if ( sscanf( kern_buf, "STAT=0x%x", &reg ) == 1  || sscanf( kern_buf, "STAT=%x", &reg ) == 1 ) {
			DEBUG_MSG( "STAT <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_STAT, reg );
		} else if ( sscanf( kern_buf, "HTIM=0x%x", &reg ) == 1  || sscanf( kern_buf, "HTIM=%x", &reg ) == 1 ) {
			DEBUG_MSG( "HTIM <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_HTIM, reg );
		} else if ( sscanf( kern_buf, "VTIM=0x%x", &reg ) == 1  || sscanf( kern_buf, "VTIM=%x", &reg ) == 1 ) {
			DEBUG_MSG( "VTIM <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_VTIM, reg );
		} else if ( sscanf( kern_buf, "HVLEN=0x%x", &reg ) == 1 || sscanf( kern_buf, "HVLEN=%x", &reg ) == 1 ) {
			DEBUG_MSG( "HVLEN <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_HVLEN, reg );
		} else if ( sscanf( kern_buf, "VBARa=0x%x", &reg ) == 1 || sscanf( kern_buf, "VBARa=%x", &reg ) == 1 ) {
			DEBUG_MSG( "VBARa <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_VBARa, reg );
		} else if ( sscanf( kern_buf, "VBARb=0x%x", &reg ) == 1 || sscanf( kern_buf, "VBARb=%x", &reg ) == 1 ) {
			DEBUG_MSG( "VBARb <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_VBARb, reg );
		} else if ( sscanf( kern_buf, "C0XY=0x%x", &reg ) == 1  || sscanf( kern_buf, "C0XY=%x", &reg ) == 1 ) {
			DEBUG_MSG( "C0XY <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_C0XY, reg );
		} else if ( sscanf( kern_buf, "C0BAR=0x%x", &reg ) == 1 || sscanf( kern_buf, "C0BAR=%x", &reg ) == 1 ) {
			DEBUG_MSG( "C0BAR <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_C0BAR, reg );
		} else if ( sscanf( kern_buf, "C0CR=0x%x", &reg ) == 1  || sscanf( kern_buf, "C0CR=%x", &reg ) == 1 ) {
			DEBUG_MSG( "C0CR <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_C0CR, reg );
		} else if ( sscanf( kern_buf, "C1XY=0x%x", &reg ) == 1  || sscanf( kern_buf, "C1XY=%x", &reg ) == 1 ) {
			DEBUG_MSG( "C1XY <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_C1XY, reg );
		} else if ( sscanf( kern_buf, "C1BAR=0x%x", &reg ) == 1 || sscanf( kern_buf, "C1BAR=%x", &reg ) == 1 ) {
			DEBUG_MSG( "C1BAR <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_C1BAR, reg );
		} else if ( sscanf( kern_buf, "C1CR=0x%x", &reg ) == 1  || sscanf( kern_buf, "C1CR=%x", &reg ) == 1 ) {
			DEBUG_MSG( "C1CR <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_C1CR, reg );
		} else if ( sscanf( kern_buf, "TST_D=0x%x", &reg ) == 1 || sscanf( kern_buf, "TST_D=%x", &reg ) == 1 ) {
			DEBUG_MSG( "TST_D <= 0x%x\n", reg );	
			MMIO_WRITE( p, REG_TST_D, reg );
		} else if ( sscanf( kern_buf, "VBL=%d", &vbl ) == 1 ) {
			switch( vbl ) {
			case 1 : 
				DEBUG_MSG( "VBL: 1\n" );
				vbl = CTRL_VBL_1;
				break;
			case 2 :
				DEBUG_MSG( "VBL: 2\n" );
				vbl = CTRL_VBL_2;
				break;
			case 4 :
				DEBUG_MSG( "VBL: 4\n" );
				vbl = CTRL_VBL_4;
				break;
			case 8 :
				DEBUG_MSG( "VBL: 8\n" );
				vbl = CTRL_VBL_8;
				break;
			case 1024 :
				DEBUG_MSG( "VBL: 1024\n" );
				vbl = CTRL_VBL1024;
				break;
			default :
				DEBUG_MSG( "Unknown VBL value. Using VBL1024\n" );
				vbl = CTRL_VBL1024;
			}
			MMIO_WRITE( p, REG_CTRL, ( MMIO_READ( p, REG_CTRL ) & CTRL_VBL_MASK ) | vbl );
		} else if ( sscanf( kern_buf, "RS 0x%x=0x%x", &offset, &reg ) == 2  ) {
			DEBUG_MSG( "REG(0x%x) <= 0x%x\n", offset, reg );
			MMIO_WRITE( p, offset, reg );
		} else if ( sscanf( kern_buf, "RG 0x%x", &offset ) == 1  ) {
			DEBUG_MSG( "REG(0x%x) => 0x%x\n", offset, MMIO_READ( p, offset ) );
		} else {
			ERROR_MSG( "Unknown command line: %s\n", kern_buf );	
		}
		
		MMIO_WRITE( p, REG_CTRL, MMIO_READ( p, REG_CTRL ) | enabled );
	}
#endif

#if 0 /* no dma mode (buffer like in dma) (source is file) */
                screen_length = (p->info->var.yres_virtual) *
                                (p->info->var.xres_virtual)*(bpp >> 3); /* in bytes */
		d_image.size = screen_length;
		d_image.virt_addr = __get_free_pages(GFP_KERNEL | GFP_DMA,
                                                get_order(d_image.size));

		st = (u8 *)d_image.virt_addr;
                sf = (u8 *)buffer;

		if ( copy_from_user( st, sf, d_image.size ) ) {
                	ERROR_MSG( "Failed to copy from user\n" );
                	return -EFAULT;
                }
                st = (u8 *)p->info->screen_base;
                sf = (u8 *)d_image.virt_addr;
		
                for (i = 0; i != d_image.size; i++)
                {
                	*st = *sf;
                	st++;
                	sf++;
                	vbl++;
                }
                free_pages(d_image.virt_addr, get_order(d_image.size));
#endif
#if 0  /* dma mode (source is file) */
		d_image.size = (p->info->var.yres_virtual) * 
				(p->info->var.xres_virtual)*(bpp >> 3); /* in bytes */		
		d_image.virt_addr = __get_free_pages(GFP_KERNEL | GFP_DMA, 
						get_order(d_image.size));
		mapend = virt_to_page ((d_image.virt_addr) + 
					(PAGE_SIZE << get_order(d_image.size)) - 1);
		for (map = virt_to_page((d_image.virt_addr)); map <= mapend; map++)
			SetPageReserved(map);
		d_image.dma_addr = pci_map_single(p->pdev, 
				(void *)d_image.virt_addr, d_image.size, 
							PCI_DMA_FROMDEVICE);

		st = (u8 *)d_image.virt_addr;
		sf = (u8 *)buffer;

		if ( copy_from_user( st, sf, d_image.size ) ) {
				ERROR_MSG( "Failed to copy from user\n" );
		                return -EFAULT;
			}

		vbl = d_image.size;

		while (MMIO_READ(p, BBR0) & PROCESS){
		}
		dpitch = (p->info->var.xres_virtual) * (bpp >> 3);
                spitch = dpitch;
	
		MMIO_WRITE(p, BBR1, ((p->info->var.yres_virtual << 16) | 
					((p->info->var.xres_virtual) * (bpp >> 3))));
		MMIO_WRITE(p, BBR2, d_image.dma_addr);
		MMIO_WRITE(p, BBR3, 0);
		MMIO_WRITE(p, BBR4, (dpitch << 16) | spitch);
		command |= ( ROP_05 | SDMA_EN | START);

		spill_regs(p);
		MMIO_WRITE(p, BBR0, command);		

		while ( MMIO_READ(p, BBR0) & PROCESS) {
		}
		pci_unmap_single(p->pdev, d_image.dma_addr, 
				d_image.size, PCI_DMA_FROMDEVICE);
		free_pages(d_image.virt_addr, get_order(d_image.size));
#endif
#if 0  /* dma mode (source is framebuffer) */
                while (MMIO_READ(p, BBR0) & PROCESS){
                }
                dpitch = (p->info->var.xres_virtual) * (bpp >> 3);
                spitch = dpitch;

                MMIO_WRITE(p, BBR1, ((p->info->var.yres_virtual << 16) |
                                        ((p->info->var.xres_virtual) * (bpp >> 3))));
                MMIO_WRITE(p, BBR2, p->mem.base);
                MMIO_WRITE(p, BBR3, 0);
                MMIO_WRITE(p, BBR4, (dpitch << 16) | spitch);
                command |= ( ROP_05 | SDMA_EN | START);

                MMIO_WRITE(p, BBR0, command);

		spill_regs(p);

                while ( MMIO_READ(p, BBR0) & PROCESS) {
                }
                pci_unmap_single(p->pdev, d_image.dma_addr,
                                d_image.size, PCI_DMA_FROMDEVICE);
                free_pages(d_image.virt_addr, get_order(d_image.size));
#endif
#if 0  /* dma - dma mode (source is file) */
                d_image.size = (p->info->var.yres_virtual) *
                                (p->info->var.xres_virtual)*(bpp >> 3); /* in bytes */
                d_image.virt_addr = __get_free_pages(GFP_KERNEL | GFP_DMA,
                                                get_order(d_image.size));
                mapend = virt_to_page ((d_image.virt_addr) +
                                        (PAGE_SIZE << get_order(d_image.size)) - 1);
                for (map = virt_to_page((d_image.virt_addr)); map <= mapend; map++)
                        SetPageReserved(map);
                d_image.dma_addr = pci_map_single(p->pdev,
                                (void *)d_image.virt_addr, d_image.size,
                                                        PCI_DMA_FROMDEVICE);

                st = (u8 *)d_image.virt_addr;
                sf = (u8 *)buffer;

                if ( copy_from_user( st, sf, d_image.size ) ) {
                                ERROR_MSG( "Failed to copy from user\n" );
                                return -EFAULT;
                        }

                vbl = d_image.size;

                while (MMIO_READ(p, BBR0) & PROCESS){
                }

		dpitch = (p->info->var.xres_virtual) * (bpp >> 3);
		spitch = dpitch;

                MMIO_WRITE(p, BBR1, ((p->info->var.yres_virtual << 16) |
                                        ((p->info->var.xres_virtual) * (bpp >> 3))));
                MMIO_WRITE(p, BBR2, d_image.dma_addr);
                MMIO_WRITE(p, BBR3, p->mem.base);
                MMIO_WRITE(p, BBR4, (dpitch << 16) | spitch);
                command |= ( ROP_05 | SDMA_EN | DDMA_EN | START);
		
		spill_regs(p);
                MMIO_WRITE(p, BBR0, command);

                while ( MMIO_READ(p, BBR0) & PROCESS) {
                }
                pci_unmap_single(p->pdev, d_image.dma_addr,
                                d_image.size, PCI_DMA_FROMDEVICE);
                free_pages(d_image.virt_addr, get_order(d_image.size));
#endif
	return vbl;
}

void __proc_init( struct mgam83fb_par* p )
{
	char buf[256] = { 0, };	
	struct proc_dir_entry* entry;

	// TODO not index but pci slot id
	sprintf( buf, PROC_FILENAME "%d", p->index );
	
        entry = create_proc_entry( buf, 0, &proc_root );

	if ( entry ) {
		entry->data = (void*)p;
		entry->read_proc = mgafb_proc_read;
		entry->write_proc = mgafb_proc_write;
	}
}

#endif	/* End of MGA_DEBUG */

