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
 *	1.1	SBUS model support added
 *	2.0	Linux-2.6 version
 */

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
#include <asm/uaccess.h>
#include <linux/dma-mapping.h>
#include <linux/of_device.h>

#if defined(CONFIG_SBUS)
#define mga_ioremap of_ioremap
#elif defined(CONFIG_PCI2SBUS_MODULE)
#include <linux/mcst/p2ssbus.h>
#endif

#include "sbus_mgam83fb.h"

static char* mode_option  = NULL;
static int next_index = 0;

/*******************************************************************************
 * Structures
 *******************************************************************************
 */
struct mgam83fb_par {
	int			bus_type;	// 0 - PCI, 1 - SBUS
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
                unsigned long   kvaddr;
                unsigned long   ioaddr;
                unsigned int    size;
        } video_buf;

	struct of_device *mgaop;
	struct fb_info* info;

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
static int mgam83fb_mmap(struct fb_info *info, struct vm_area_struct *vma);
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
/*******************************************************************************
 * MMIO Registers
 *******************************************************************************
 */
static void MMIO_WRITE( struct mgam83fb_par* p, unsigned long reg, uint32_t val )
{
	TRACE_MSG( "MMIO[0x%03lx] <= 0x%08x\n", reg, val );

	switch( p->bus_type ) {
#if defined(CONFIG_SBUS) || defined(CONFIG_PCI2SBUS_MODULE)
	case BUS_TYPE_SBUS :
		// registers are little-endian like in PCI model
		writel( val, (void*)((unsigned long)p->mmio.vbase + reg) );
		break;
#endif /* CONFIG_SBUS || CONFIG_PCI2SBUS_MODULE */
	default :
		printk( KERN_WARNING "Cannot write to mmio: unsupported MGA/M video card model!\n" );
	}
		
	TRACE_MSG( "Sleeping 10 msecs...\n" );
}

static uint32_t MMIO_READ( struct mgam83fb_par* p, unsigned long reg )
{
	uint32_t result;

	switch( p->bus_type ) {
#if defined(CONFIG_SBUS) || defined(CONFIG_PCI2SBUS_MODULE)
	case BUS_TYPE_SBUS :
		// registers are little-endian like in PCI model
		result = readl( (void*)((unsigned long) p->mmio.vbase + reg) );

		
		break;
#endif /* CONFIG_SBUS || CONFIG_PCI2SBUS_MODULE */
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
static struct { struct fb_bitfield transp, red, green, blue; } colors[] = {
	{ {  0, 0, 0}, {  0, 8, 0}, { 0, 8, 0}, { 0, 8, 0} },	// 8bpp
	{ {  0, 0, 0}, { 11, 5, 0}, { 5, 6, 0}, { 0, 5, 0} },	// 16bpp
	{ {  0, 0, 0}, {  0, 8, 0}, { 8, 8, 0}, {16, 8, 0} },	// 24bpp
	{ { 24, 8, 0}, { 16, 8, 0}, { 8, 8, 0}, { 0, 8, 0} },	// 32bpp
};

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

	var->red = colors[colors_index].red;
	var->green = colors[colors_index].green;
	var->blue = colors[colors_index].blue;
	var->transp = colors[colors_index].transp;
	DEBUG_MSG("mgam83fb: mgam83fb_check_var finish\n");

	return 0;
}


static int __set_mode( struct mgam83fb_par* p )
{
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

	switch( p->bits_per_pixel ) {
	case 8 :
		ctrl |= CTRL_CD_8BPP | CTRL_PC_PSEUDO;
		break;
	case 16 :
		ctrl |= CTRL_CD_16BPP;
		break;
	case 24 :
		ctrl |= CTRL_CD_24BPP;
		break;
	case 32 :
		ctrl |= CTRL_CD_32BPP;
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
	trace_func(19);
	MMIO_WRITE( p, REG_HTIM, hsync << 24 | hgdel << 16 | hgate );
	trace_func(20);
	MMIO_WRITE( p, REG_VTIM, vsync << 24 | vgdel << 16 | vgate );
	trace_func(21);
	MMIO_WRITE( p, REG_HVLEN, hlen << 16 | vlen );
	trace_func(22);
	MMIO_WRITE( p, REG_VBARa, 0x0 );
	MMIO_WRITE(p, REG_BUGFIX, 0);

	DEBUG_MSG( "hsync: %d hgdel: %d hgate %d\n", hsync, hgdel, hgate );
	DEBUG_MSG( "vsync: %d vgdel: %d vgate %d\n", vsync, vgdel, vgate );
	DEBUG_MSG( "hlen: %d vlen: %d\n", hlen, vlen );
	trace_func(23);
	MMIO_WRITE( p, REG_CTRL, MMIO_READ( p, REG_CTRL ) | CTRL_VEN );
//	MMIO_WRITE( p, REG_CTRL, ctrl | CTRL_VEN );	

	CHECKPOINT_LEAVE;
	return 0;
}

#define DEBUG_MSG_SET_PAR_MODE				0
#define DEBUG_MSG_SET_PAR if (DEBUG_MSG_SET_PAR_MODE) printk
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

	trace_func(3);	
	__sbus_set_pixclock( p->bus_type, (unsigned long)p->i2c.vbase, p->pixclock );
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
		// using CLUT0
		trace_func(26);
		MMIO_WRITE( p, 0x800 + regno * 4, val );
	}

	/* Truecolor has hardware independent palette */
	if (info->fix.visual == FB_VISUAL_TRUECOLOR) {
		u32 v;

		if (regno >= 16){
			printk("mgam83fb: mgam83fb_setcolreg finish with error, regno = 0x%x\n", regno);
			return -EINVAL;
		}

		v = 	(red << info->var.red.offset) |
			(green << info->var.green.offset) |
			(blue << info->var.blue.offset) |
			(transp << info->var.transp.offset);

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

struct ker_dma_mem {
	unsigned long phys_addr;	/* dma addr */
	unsigned long kvaddr;
	size_t size;
	struct ker_dma_mem *next;
};

static struct ker_dma_mem *dma_mem_list = NULL;

#define FBIOALLOC_DMA_MEM	0x4631
#define FBIOFREE_ALL_DMA_MEMS	0x4632

#define	DEBUG_IOCTL_MSG_ON	0
#define DEBUG_IOCTL_MSG		if (DEBUG_IOCTL_MSG_ON)	printk

static int 
mgam83fb_ioctl(struct fb_info *info, unsigned int cmd,
         unsigned long arg)
{
        unsigned long kvaddr;
        struct dma_mem          dmem;
        int     order;
        struct page *map, *mapend;
        struct mgam83fb_par* par = (struct mgam83fb_par*)info->par;
        void __user *argp = (void __user *)arg;

        switch (cmd) {
           case FBIOALLOC_DMA_MEM:
                if (!par->video_buf.ioaddr) {
                        if (copy_from_user(&dmem, argp, sizeof(dmem))) {
                                return -EFAULT;
                        }
                        DEBUG_IOCTL_MSG("mgam83fb_ioctl: Ask to alloc 0x%lx bytes\n",
							(unsigned long)dmem.size);
                        order = get_order(dmem.size);
                        kvaddr = __get_free_pages(GFP_KERNEL | GFP_DMA, order);

                        if (!kvaddr){
                                DEBUG_IOCTL_MSG("mgam83fb_ioctl: failed to alloc dma buffer\n");
                                return -ENOMEM;
                        }
                        mapend = virt_to_page (kvaddr + (PAGE_SIZE << order) - 1);
                        for (map = virt_to_page(kvaddr); map <= mapend; map++) {
                                SetPageReserved(map);
                        }
                        par->video_buf.ioaddr = dma_map_single(&par->mgaop->dev, (void *)kvaddr, dmem.size,
                                                               DMA_BIDIRECTIONAL);
                        par->video_buf.kvaddr = kvaddr;
                        par->video_buf.size = dmem.size;
                }
                dmem.phys_addr = par->video_buf.ioaddr;
                DEBUG_IOCTL_MSG("FBIOALLOC_DMA_MEM: kvaddr = 0x%08lx; dmem.phys_addr = 0x%08lx\n", kvaddr, dmem.phys_addr);

                if (copy_to_user(argp, &dmem, sizeof(dmem))){
                        DEBUG_IOCTL_MSG("mgam83fb_ioctl: failed to copy_to_user\n");
                        return -EFAULT;
                }
                return 0;
           default:
                return -EINVAL;
        }
}

#define	DEBUG_MMAP_MSG_ON	0
#define DEBUG_MMAP_MSG		if (DEBUG_MMAP_MSG_ON)	printk

static struct ker_dma_mem *lookup_trough_dma_list(unsigned long off)
{
	struct ker_dma_mem 	*tmp_list = dma_mem_list;
	while (tmp_list){
		if ((off >= tmp_list->phys_addr) &&
			(off < (tmp_list->phys_addr + tmp_list->size)))
				return tmp_list;
		tmp_list = dma_mem_list->next;
	}
	return NULL;
}

static int mgam83fb_mmap(struct fb_info *info, struct vm_area_struct *vma)
{
	unsigned long off;
	unsigned long start;
	struct ker_dma_mem 	*tmp_list = NULL;
	u32 len;
	struct mgam83fb_par* p = (struct mgam83fb_par*)info->par;

	off = vma->vm_pgoff << PAGE_SHIFT;

	/* frame buffer memory */
	start = info->fix.smem_start;
	len = PAGE_ALIGN((start & ~PAGE_MASK) + info->fix.smem_len);
	DEBUG_MMAP_MSG("mgam83fb_mmap: start = 0x%lx, off = 0x%lx, len = 0x%x\n", 
							start, off, len);
	/* off that's in range of 0..."fb len" corresponds to framebuffer  */
	/* off that's in range of "fb len"..."io len" corresponds to mmio */
	if (off < len){
		DEBUG_MMAP_MSG("mgam83fb_mmap: given off corresponds to fbmem\n");
#ifdef CONFIG_E2K
		vma->vm_page_prot = (cpu_has(CPU_HAS_WC_PCI_PREFETCH)) ?
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

	/* off that's more then 0x80000000 corresponds to allocated dma buffers */
	if (off >= 0x80000000){
		DEBUG_MMAP_MSG("mgam83fb_mmap: given off corresponds to dma mem\n");
		off = off - 0x80000000;
		DEBUG_MMAP_MSG("mgam83fb_mmap: corrected off: 0x%lx\n", off);
		tmp_list = lookup_trough_dma_list(off);
		if (!tmp_list){
			DEBUG_MMAP_MSG("mgam83fb_mmap: relevant dma buffer isn't found\n");
			return -EINVAL;
		}
		DEBUG_MMAP_MSG("mgam83fb_mmap: found dma buffer, the \"off\" corresponds to\n");
		DEBUG_MMAP_MSG("mgam83fb_mmap: dma buf parms: paddr 0x%lx, size 0x%x\n", 
						tmp_list->phys_addr, tmp_list->size);
		DEBUG_MMAP_MSG("mgam83fb_mmap: We desire to map the range from 0x%lx to 0x%lx\n",
			off, (off + vma->vm_end - vma->vm_start));
		if (((off - tmp_list->phys_addr) + 
				(vma->vm_end - vma->vm_start)) > tmp_list->size){
			DEBUG_MMAP_MSG("mgam83fb_mmap: too much size was given to map in:\n");
			DEBUG_MMAP_MSG("mgam83fb_mmap: off: 0x%lx given size: 0x%lx, "
			       "found dma buffer size: 0x%x\n", (off - tmp_list->phys_addr), 
				(vma->vm_end - vma->vm_start), tmp_list->size);
			return -EINVAL;
		}
		
		vma->vm_pgoff = off >> PAGE_SHIFT;
		vma->vm_flags |= VM_IO | VM_RESERVED;
#if defined(__e2k__)
		if (vma->vm_flags & VM_WRITECOMBINED)
			vma->vm_page_prot =
				pgprot_writecombine(vma->vm_page_prot);
#endif

#if defined (__sparc__)
		if (remap_pfn_range(vma, vma->vm_start, 
				MK_IOSPACE_PFN(p->mem.iospace, (off >> PAGE_SHIFT)),
			     	vma->vm_end - vma->vm_start, vma->vm_page_prot))
			return -EAGAIN;
#else
		if (remap_pfn_range(vma, vma->vm_start, off >> PAGE_SHIFT,
			     	vma->vm_end - vma->vm_start, vma->vm_page_prot))
			return -EAGAIN;
#endif
		DEBUG_MMAP_MSG("mgam83fb_mmap: mapping done successfully\n");		
		return 0;	
	}

	start &= PAGE_MASK;
	if ((off + vma->vm_end - vma->vm_start) > len)
		return -EINVAL;

	off += start;
	vma->vm_pgoff = off >> PAGE_SHIFT;
	/* This is an IO map - tell maydump to skip this VMA */
	vma->vm_flags |= VM_IO | VM_RESERVED;

#if !defined(__e2k__) 
	vma->vm_page_prot = pgprot_noncached(vma->vm_page_prot);
#endif

#if defined (__sparc__)
	if (io_remap_pfn_range(vma, vma->vm_start, 
				MK_IOSPACE_PFN(p->mem.iospace, (off >> PAGE_SHIFT)),
				vma->vm_end - vma->vm_start, vma->vm_page_prot)) {
		return -EAGAIN;
	}
#else
	if (io_remap_pfn_range(vma, vma->vm_start, off >> PAGE_SHIFT,
			     vma->vm_end - vma->vm_start, vma->vm_page_prot))
		return -EAGAIN;
#endif

	return 0;
}

#if 0
extern int soft_cursor(struct fb_info *info, struct fb_cursor *cursor);
extern void cfb_fillrect(struct fb_info *p, const struct fb_fillrect *rect);
#endif

#ifdef MGA_DEBUG
static struct fb_copyarea last_area[10];
static int area_count = 0;
static struct fb_copyarea *curr_area = NULL;
static struct fb_info *last_info[10];
#endif

static inline u32 flip_32 (u32 l)
{
	return ((l&0xff)<<24) | (((l>>8)&0xff)<<16) | 
			(((l>>16)&0xff)<<8)| ((l>>24)&0xff);
}

static inline u32 bitflip_32 (u32 l)
{
        return ((l&0x1)<<31)      | (((l>>1)&0x1)<<30) |
               (((l>>2)&0x1)<<29) | (((l>>3)&0x1)<<28) |
	       (((l>>4)&0x1)<<27) | (((l>>5)&0x1)<<26) |
	       (((l>>6)&0x1)<<25) | (((l>>7)&0x1)<<24) |
	       (((l>>8)&0x1)<<23) | (((l>>9)&0x1)<<22) |
	       (((l>>10)&0x1)<<21)| (((l>>11)&0x1)<<20)|
	       (((l>>12)&0x1)<<19)| (((l>>13)&0x1)<<18)|
	       (((l>>14)&0x1)<<17)| (((l>>15)&0x1)<<16)|
	       (((l>>16)&0x1)<<15)| (((l>>17)&0x1)<<14)|
	       (((l>>18)&0x1)<<13)| (((l>>19)&0x1)<<12)|
	       (((l>>20)&0x1)<<11)| (((l>>21)&0x1)<<10)|
	       (((l>>22)&0x1)<<9) | (((l>>23)&0x1)<<8) |
	       (((l>>24)&0x1)<<7) | (((l>>25)&0x1)<<6) |
	       (((l>>26)&0x1)<<5) | (((l>>27)&0x1)<<4) |
	       (((l>>28)&0x1)<<3) | (((l>>29)&0x1)<<2) |
	       (((l>>30)&0x1)<<1) | ((l>>31)&0x1);
}

#if 0
struct dma_image {
	unsigned long 	virt_addr;
	dma_addr_t	dma_addr;
	size_t		size;
};

static struct dma_image d_image;
#endif

#define FB_WRITEL fb_writel
#define FB_READL  fb_readl

#undef DMA_DEBUG

#ifdef CONFIG_SBUS_MGA_HWCOPYAREA
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
	
#ifdef MGA_DEBUG
#if 1
	if (area_count == 10)
		area_count = 0;
	last_area[area_count].width = modded.width;
	last_area[area_count].height = modded.height;
	last_area[area_count].dx = dx;
	last_area[area_count].dy = dy;
	last_area[area_count].sx = sx;
	last_area[area_count].sy = sy;
	last_info[area_count] = info;
	area_count++;
#endif
#endif

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

	// Waiting for BitBLT is not full

	while (MMIO_READ(p, BBR0) & PROCESS){
	}

	/* FIXME: should be investigated */
	if (info->fbops->fb_sync)
		info->fbops->fb_sync(info);

	if (sy < dy){
		sy = sy + height;
		dy = dy + height;
	}
	dst_idx = dy*line_length + dx*(info->var.bits_per_pixel >> 3); /* Bytes */
	src_idx = sy*line_length + sx*(info->var.bits_per_pixel >> 3); /* Bytes */
#ifdef MGA_DEBUG
#if 1
	if (area_count == 10)
		area_count = 0;
	last_area[area_count].width = modded.width;
	last_area[area_count].height = modded.height;
	last_area[area_count].dx = dx;
	last_area[area_count].dy = dy;
	last_area[area_count].sx = sx;
	last_area[area_count].sy = sy;
	last_info[area_count] = info;
	area_count++;
#endif
#endif
	MMIO_WRITE(p, BBR1, ((height << 16) | width));
	MMIO_WRITE(p, BBR2, src_idx);
	MMIO_WRITE(p, BBR3, dst_idx);
	MMIO_WRITE(p, BBR4, ((dpitch << 16) | spitch));

	command |= (ROP_05 | START);
	if (sy < dy){
		command |= VDIR;
	}

	MMIO_WRITE(p, BBR0, command);		

	while ( MMIO_READ(p, BBR0) & PROCESS) {
	}
}
#endif

/*
 * Driver initialization
 */

extern int soft_cursor(struct fb_info *info, struct fb_cursor *cursor);
 
static struct fb_ops mgam83fb_ops = {
	.owner          = THIS_MODULE,

	.fb_check_var   = mgam83fb_check_var,
	.fb_set_par	= mgam83fb_set_par,
	.fb_setcolreg	= mgam83fb_setcolreg,
	.fb_ioctl	= mgam83fb_ioctl,
	.fb_mmap	= mgam83fb_mmap,
	.fb_fillrect    = cfb_fillrect,		// Generic function
#ifdef CONFIG_SBUS_MGA_HWCOPYAREA
	.fb_copyarea    = mgam83fb_copyarea,	// HW function		
#else
	.fb_copyarea    = cfb_copyarea,		// Generic function
#endif
	.fb_imageblit   = cfb_imageblit,	

	.fb_cursor      = soft_cursor
};

static int __fb_init( struct fb_info* info )
{
	struct mgam83fb_par* p = (struct mgam83fb_par*)info->par;
#if 0
	int regno = 0;
#endif
	int retval;

	printk( KERN_INFO "MEM : base 0x%08lx vbase 0x%08lx len 0x%lx\n", 
		(unsigned long)p->mem.base, (unsigned long)p->mem.vbase,
		(unsigned long)p->mem.len );
	printk( KERN_INFO "MMIO: base 0x%08lx vbase 0x%08lx len 0x%lx\n", 
		(unsigned long)p->mmio.base, (unsigned long)p->mmio.vbase,
		(unsigned long)p->mmio.len );
	printk( KERN_INFO "I2C : base 0x%08lx vbase 0x%08lx len 0x%lx\n", 
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
#ifdef CONFIG_SBUS_MGA_HWCOPYAREA
		     | FBINFO_HWACCEL_COPYAREA 
#endif
		     ;
	/*
	 * This should give a reasonable default video mode. The following is
	 * done when we can set a video mode. 
	 */
	 if (!mode_option)
		mode_option = "640x480@60";
//		mode_option = "1024x768@60";
	
	retval = fb_find_mode(&info->var, info, mode_option, NULL, 0, NULL, 8);
	if (!retval || retval == 4) {
		ERROR_MSG( "fb_find_mode() failed\n");
		return -EINVAL;
	}
	printk(KERN_INFO "MGA/M-83: default bits_per_pixel: %d\n", info->var.bits_per_pixel);

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

	if (p->bus_type == BUS_TYPE_SBUS){
		DEBUG_MSG("mgam83fb: __init_pixclock - only SBUS\n");
		__sbus_init_pixclock(p->bus_type, (unsigned long)p->i2c.vbase);

		/* здесь инициализируется высота, ширина, разрешение и т.д */
		mgam83fb_set_par(info);
	}

	if (register_framebuffer(info) < 0) {
		ERROR_MSG( "register_framebuffer() failed\n" );
		fb_dealloc_cmap(&info->cmap);
		return -EINVAL;
	}
	printk(KERN_INFO "fb%d: %s frame buffer device\n", info->node, info->fix.id);
	p->index = next_index++;	
#ifdef MGA_DEBUG
	__proc_init( p );
#endif

	return 0;
}

#if defined(CONFIG_SBUS) || defined(CONFIG_PCI2SBUS_MODULE)
static int mga_sbus_probe(struct of_device* op, const struct of_device_id *match)
{
	struct fb_info* info;
	struct mgam83fb_par* p;	
	int ret = -EINVAL;
	unsigned long length = 0;
	
	/*
	 * Dynamically allocate info and par
	 */
	DEBUG_MSG("mgam83fb: sbus driver init\n");
	info = framebuffer_alloc(sizeof(struct mgam83fb_par), NULL );
	if (!info) {
		printk( KERN_ERR "mgam83: failed to allocate fb_info instance!\n");
		ret = -ENOMEM;
		goto fail;
	}
	p = info->par;
	p->bus_type = BUS_TYPE_SBUS;
	p->mgaop = op;
	p->info = info;
	dev_set_drvdata(&op->dev, p);
	// Framebuffer memory
#ifdef __sparc__
	p->mem.iospace = op->resource[SBUS_MEM_BAR].flags & IORESOURCE_BITS;
#endif
	p->mem.base = op->resource[SBUS_MEM_BAR].start;
	p->mem.len = op->resource[SBUS_MEM_BAR].end - op->resource[SBUS_MEM_BAR].start + 1;
	p->mem.vbase = (uint8_t*)of_ioremap(&op->resource[SBUS_MEM_BAR], 0, p->mem.len, "mga_mem");
	if (!p->mem.vbase) {
		ERROR_MSG( "Cannot ioremap MEM (0x%08lx:0x%x)\n", p->mem.base, p->mem.len );
		ret = -ENOMEM;
		goto fail_mem_ioremap;
	}

	// Video card registers
	p->mmio.base	= op->resource[SBUS_MMIO_BAR].start;
	p->mmio.len	= op->resource[SBUS_MMIO_BAR].end - op->resource[SBUS_MMIO_BAR].start + 1;
	p->mmio.vbase	= (uint8_t*)of_ioremap(&op->resource[SBUS_MMIO_BAR], 0, p->mmio.len, "mga_mmio");
	if ( !p->mmio.vbase )
	{
		ERROR_MSG( "Cannot ioremap MMIO (0x%08lx:0x%x)\n", p->mmio.base, p->mmio.len );
		ret = -ENOMEM;		
		goto fail_mmio_ioremap;
	}
	
	// I2C bus registers
	p->i2c.base	= op->resource[SBUS_I2C_BAR].start;
	p->i2c.len	= op->resource[SBUS_I2C_BAR].end - op->resource[SBUS_I2C_BAR].start + 1;
	p->i2c.vbase	= (uint8_t*)of_ioremap(&op->resource[SBUS_I2C_BAR], 0, p->i2c.len, "mga_i2c");
	if ( !p->i2c.vbase )
	{
		ERROR_MSG("Cannot ioremap I2C (0x%08lx:0x%x)\n", p->i2c.base, p->i2c.len);
		ret = -ENOMEM;
		goto fail_i2c_ioremap;
	}


	// Filling info, selecting mode and initializating framebuffer
	DEBUG_MSG("mgam83fb: framerbuffer init...\n");
	if ( (ret = __fb_init( info )) ) 
		goto fail_register_fb;

	printk("SBUS MGA video card  %d:%d\n", op->slot, op->portid);
	return 0;

fail_register_fb:
	length = p->i2c.len;
#ifdef CONFIG_SBUS
	of_iounmap(&op->resource[SBUS_I2C_BAR], p->i2c.vbase, length);
#else
	sbus_iounmap((unsigned long)p->i2c.vbase, length );
#endif
fail_i2c_ioremap:
	length = p->mmio.len;
#ifdef CONFIG_SBUS
	of_iounmap(&op->resource[SBUS_MMIO_BAR], p->mmio.vbase, length);
#else
	sbus_iounmap((unsigned long)p->mmio.vbase, length );
#endif
fail_mmio_ioremap:
	length = p->mem.len;
#ifdef CONFIG_SBUS
	of_iounmap(&op->resource[SBUS_MEM_BAR], p->mem.vbase, length);
#else
	sbus_iounmap((unsigned long)p->mem.vbase, length );
#endif
fail_mem_ioremap:
	framebuffer_release(info);
fail:
	return ret;
}


static int mga_sbus_remove(struct of_device *op)
{
	struct mgam83fb_par* p = dev_get_drvdata(&op->dev);
	struct fb_info* info = p->info;
	/* or dev_get_drv_data(device); */
	unsigned long length = 0;

         if (p->video_buf.ioaddr) {
                 struct page *map, *mapend;
                 dma_unmap_single(&p->mgaop->dev, p->video_buf.ioaddr,
                         p->video_buf.size, DMA_BIDIRECTIONAL);
                 mapend = virt_to_page(p->video_buf.kvaddr + p->video_buf.size -1);
                 for (map = virt_to_page(p->video_buf.kvaddr); map <= mapend; map++) {
                         ClearPageReserved(map);
                 }
                 free_pages(p->video_buf.kvaddr, get_order(p->video_buf.size));
                 p->video_buf.ioaddr = 0;
                 p->video_buf.kvaddr = 0;
                 p->video_buf.size = 0;
         }

	if (info) {
		// Turn of display
		MMIO_WRITE(p, REG_CTRL, MMIO_READ( p, REG_CTRL) & ~CTRL_VEN);

		unregister_framebuffer(info);
		fb_dealloc_cmap(&info->cmap);
		length = p->i2c.len;
#ifdef CONFIG_SBUS
		of_iounmap(&op->resource[SBUS_I2C_BAR], p->i2c.vbase, length);
#else
		sbus_iounmap((unsigned long)p->i2c.vbase, length );
#endif
		length = p->mmio.len;
#ifdef CONFIG_SBUS
		of_iounmap(&op->resource[SBUS_MMIO_BAR], p->mmio.vbase, length);
#else
		sbus_iounmap((unsigned long)p->mmio.vbase, length);
#endif
		length = p->mem.len;
#ifdef CONFIG_SBUS
		of_iounmap(&op->resource[SBUS_MEM_BAR], p->mem.vbase, length);
#else
		sbus_iounmap((unsigned long)p->mem.vbase, length);
#endif
		framebuffer_release(info);
	}
	return 0;
}
#endif




static const struct of_device_id mgam_sbus_match[] = {
        {
                .name = "mgam",
        },
        {
                .name = "mga",
        },
        {
                .name = " MGA/M",
        },
        {},
};

MODULE_DEVICE_TABLE(of, mgam_sbus_match);

static struct of_platform_driver mga_sbus_driver = {
        .name           = "mgam83fb",
        .match_table    = mgam_sbus_match,
        .probe          = mga_sbus_probe,
        .remove         = mga_sbus_remove,
};




////////////////////////////////////////////////////////////////////////////////
// Modularization
////////////////////////////////////////////////////////////////////////////////
static int __init mga_sbus_init(void)
{
	printk("SBUS MGA video card driver loaded\n");
#ifndef MODULE
        char *option = NULL;
        if (fb_get_options("mgam83fb", &option)) {
                return -ENODEV;
	}
	mode_option = option;
#endif
        return of_register_driver(&mga_sbus_driver, &of_bus_type);
}

static void __exit mga_sbus_exit(void)
{
        of_unregister_driver(&mga_sbus_driver);
}

module_init(mga_sbus_init);
module_exit(mga_sbus_exit);

MODULE_LICENSE("GPL");


