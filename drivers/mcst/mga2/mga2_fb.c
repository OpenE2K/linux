//#define DEBUG
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/tty.h>
#include <linux/sysrq.h>
#include <linux/delay.h>
#include <linux/fb.h>
#include <linux/init.h>
#include <linux/circ_buf.h>

#include "mga2_drv.h"

#define	 MGA2_BB_R0		0x01000
#define	 MGA2_BB_R7		0x0101C	/* базовые регистры MGA-совместимого блиттера */
#define	 MGA2_BB_FMTCFG		0x01020	/* управление форматами пикселей для alpha-опера */
#define	 MGA2_BB_ASRC		0x01024	/* вычисление Fs */
#define	 MGA2_BB_ADST		0x01028	/* вычисление Fd */
#define	 MGA2_BB_PALADDR		0x0102C	/* установка адреса LUT (палитры) для форматов 1bpp 4bpp 8bpp. */
#define	 MGA2_BB_PALDATA		0x01030	/* запись данных в элемент LUT (палитры) для форматов 1bpp 4bpp 8bpp. */
#define	 MGA2_BB_SRC64		0x01034	/* старшая часть 64-битного адреса DMA системной памяти для канала источника */
#define	 MGA2_BB_DST64		0x01038	/* старшая часть 64-битного адреса DMA системной памяти для канала приёмника */
#define	 MGA2_BCTRL_LBASEPTR		0x01800	/* указатель на базу (четыре 32-битных слова) в системной памяти младшая часть. */
#define	 MGA2_BCTRL_HBASEPTR		0x01804	/* старшая часть указателя на базу (R/W) */
#define	 MGA2_BCTRL_START		0x01808	/* управление контроллером */
#define	 MGA2_BCTRL_CURLPTR		0x0180C	/* дублирует содержимое младшей части указателя на дескриптор в базе (R/O) записываемое контроллером. */
#define	 MGA2_BCTRL_STATUS		0x01810	/* статусное слово (R/O) */
#define	 MGA2_BCTRL_DUMMY		0x01814	/* регистр-пустышка */

#define	 MGA2_VIDMUX_BITS	0x03404
#define	 MGA2_VIDMUX_BLT_WR_BUSY	(1 << 5)

#define	 MGA2_SYSMUX_BITS	0x03804
#define	 MGA2_SYSMUX_BLT_WR_BUSY	(1 << 1)

MODULE_PARM_DESC(nofbaccel, "Disable fbcon acceleration");
static int __initdata mga2_nofbaccel = 1;
module_param_named(nofbaccel, mga2_nofbaccel, int, 0400);

#define MGA2_BCTRL_OFF	(1 << 31)

MODULE_PARM_DESC(nohwcursor, "Disable hardware cursor");
static int __initdata mga2_nohwcursor = 0;
module_param_named(nohwcursor, mga2_nohwcursor, int, 0400);

/*
 *******************************************************************************
 * MMIO BitBlt Module Registers
 *******************************************************************************
 */
#define REG_BB_CTRL	0x1000	/* BitBlt module control register (write only) */
#define REG_BB_STAT	0x1000	/* BitBlt module status register (read only) */

#define REG_BB_WINDOW	0x1004	/* Operation geometry */
#define REG_BB_SADDR	0x1008	/* Source start address */
#define REG_BB_DADDR	0x100c	/* Destination start address */
#define REG_BB_PITCH	0x1010	/* */
#define REG_BB_BG	0x1014	/* Background color */
#define REG_BB_FG	0x1018	/* Foreground color */

/* BitBlt status register bits */
#define BB_STAT_PROCESS	(0x1<<31)	/* 1 - processing operation, 0 - idle */
#define BB_STAT_FULL	(0x1<<30)	/* 1 - pipeline full */
#define BB_STAT_DMA	(0x1<<26)	/* DMA support */

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
#elif defined(__LITTLE_ENDIAN)
#define BB_CTRL_BPP_CD_8	BB_CTRL_BPP_8
#define BB_CTRL_BPP_CD_16	BB_CTRL_BPP_16
#define BB_CTRL_BPP_CD_24	BB_CTRL_BPP_24
#define BB_CTRL_BPP_CD_32	BB_CTRL_BPP_32
#else
#error byte order not defined
#endif

#define	 MGA2_BB_FMTCFG		0x01020	/* управление форматами пикселей для alpha-опера */
#define	 MGA2_BB_ASRC		0x01024	/* вычисление Fs */
#define	 MGA2_BB_ADST		0x01028	/* вычисление Fd */
#define	 MGA2_BB_PALADDR		0x0102C	/* установка адреса LUT (палитры) для форматов 1bpp 4bpp 8bpp. */
#define	 MGA2_BB_PALDATA		0x01030	/* запись данных в элемент LUT (палитры) для форматов 1bpp 4bpp 8bpp. */
#define	 MGA2_BB_SRC64		0x01034	/* старшая часть 64-битного адреса DMA системной памяти для канала источника */
#define	 MGA2_BB_DST64		0x01038	/* старшая часть 64-битного адреса DMA системной памяти для канала приёмника */

#define	 MGA2_BCTRL_LBASEPTR		0x01800	/* указатель на базу (четыре 32-битных слова) в системной памяти младшая часть. */
#define	 MGA2_BCTRL_HBASEPTR		0x01804	/* старшая часть указателя на базу (R/W) */
#define	 MGA2_BCTRL_START		0x01808	/* управление контроллером */
# define MGA2_BCTRL_B_START		(1 << 0)

#define	 MGA2_BCTRL_CURLPTR		0x0180C	/* дублирует содержимое младшей части указателя на дескриптор в базе (R/O) записываемое контроллером. */
#define	 MGA2_BCTRL_STATUS		0x01810	/* статусное слово (R/O) */
# define MGA2_BCTRL_B_BUSY		(1 << 0)

#define	 MGA2_BCTRL_DUMMY		0x01814	/* регистр-пустышка */

#define	 MGA2_INTENA		0x02000	/* разрешение генерации прерывания */
#define	 MGA2_INTREQ		0x02004	/* состояние запросов прерывания */
#define	 MGA2_INTLEVEL		0x02008	/* указывает активный уровень входного сигнала */
#define	 MGA2_INTMODE		0x0200C	/* указывает режим обработки входных сигналов */

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

#define MGA2_TIMEOUT_MSEC	1000

static int mga2fb_bctrl_init(struct mga2 *mga2)
{
	int ret = 0;
	struct bctrl *b;
	mga2->bctrl = dma_alloc_coherent(mga2->drm->dev,
					 sizeof(*mga2->bctrl),
					 &mga2->bctrl_dma, GFP_KERNEL);
	b = mga2->bctrl;
	if (!b) {
		ret = -ENOMEM;
		goto out;
	}

	wfb((u32) mga2->bctrl_dma, MGA2_BCTRL_LBASEPTR);
	wfb((u32) ((u64) mga2->bctrl_dma >> 32), MGA2_BCTRL_HBASEPTR);
      out:
	return ret;
}

static int mga2fb_bctrl_fini(struct mga2 *mga2)
{
	dma_free_coherent(mga2->drm->dev, sizeof(*mga2->bctrl), mga2->bctrl,
			  mga2->bctrl_dma);
	return 0;
}

static int __mga2_sync(struct mga2 *mga2)
{
	int ret = 0, i;
	int timeout_usec = MGA2_TIMEOUT_MSEC * 1000;
	if (mga2->subdevice == MGA2_P2_PROTO)
		timeout_usec *= 10;

	for (i = 0; i < timeout_usec; i++) {
		u32 busy = (rfb(REG_BB_CTRL) & BB_STAT_PROCESS) |
		    (rfb(MGA2_BCTRL_STATUS) & MGA2_BCTRL_B_BUSY) |
		    (rfb(MGA2_SYSMUX_BITS) & MGA2_SYSMUX_BLT_WR_BUSY) |
		    (rfb(MGA2_VIDMUX_BITS) & MGA2_VIDMUX_BLT_WR_BUSY);

		if (!busy)
			break;
		udelay(1);
	}

	if (i == timeout_usec) {
		DRM_ERROR("sync timeout\n");
		ret = -ETIME;
	}
	return ret;
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

static int mga2_sync(struct fb_info *info)
{
	struct mga2_fbdev *fb = info->par;
	struct mga2 *mga2 = fb->helper.dev->dev_private;

	return __mga2_sync(mga2);
}

static inline void write_desc(void *p, dma_addr_t addr)
{
	volatile dma_addr_t *d = p;
	if (sizeof(dma_addr_t) == 32)
		*d = cpu_to_le32(addr);
	else
		*d = cpu_to_le64(addr);
}

static inline dma_addr_t read_desc(void *p)
{
	dma_addr_t ret;
	volatile dma_addr_t *d = p;
	if (sizeof(dma_addr_t) == 32)
		ret = cpu_to_le32(*d);
	else
		ret = le64_to_cpu(*d);
	return ret;
}

#define CIRC_SIZE BCTRL_DESC_NR
#define CIRC_MASK (CIRC_SIZE - 1)
#define circ_empty(circ)     ((circ)->head == (circ)->tail)
#define circ_free(circ)      CIRC_SPACE((circ)->head, (circ)->tail, CIRC_SIZE)
#define circ_cnt(circ)       CIRC_CNT((circ)->head, (circ)->tail, CIRC_SIZE)
#define circ_desc(circ, idx) ((circ)->bctrl->desc[(idx) & CIRC_MASK])
#define circ_clear(circ)	((circ)->tail = (circ)->head)
#define circ_add(__v, __i)	(((__v) + (__i)) & CIRC_MASK)
#define circ_inc(__v)	circ_add(__v, 1)
#define circ_dec(__v)	circ_add(__v, -1)

static int addr_to_idx(struct mga2 *mga2, dma_addr_t d)
{
	dma_addr_t base = mga2->bctrl_dma + offsetof(struct bctrl, desc);
	return (d - base) / sizeof(struct bctrl_desc);
}

static dma_addr_t idx_to_addr(struct mga2 *mga2, int i)
{
	dma_addr_t base = mga2->bctrl_dma + offsetof(struct bctrl, desc);
	return base + i * sizeof(struct bctrl_desc);
}

static int wait_for_bctrl(struct mga2 *mga2)
{
	int ret = 0, i;

	for (i = 0; i < MGA2_TIMEOUT_MSEC; i++) {
		int last = circ_dec(mga2->head);
		int tail = mga2->tail;
		int busy = rfb(MGA2_BCTRL_STATUS) & MGA2_BCTRL_B_BUSY;

		struct bctrl_desc *desc = mga2->bctrl->desc;
		struct bctrl_base *base = &mga2->bctrl->base;

		dma_addr_t cur = read_desc(base);
		dma_addr_t t = read_desc(&desc[tail]);

		if (!cur) {	/* last desc is processing */
			if (busy)
				last = circ_dec(last);
			cur = read_desc(&desc[last]);
		}

		if (!busy || cur != t) {
			mga2->tail = addr_to_idx(mga2, t);
			break;
		}
		msleep(1);
	}
	if (i == MGA2_TIMEOUT_MSEC) {
		DRM_ERROR("bctrl timeout\n");
		ret = -ETIME;
	}
	return ret;
}

static int __get_free_desc(struct mga2 *mga2)
{
	if (!circ_free(mga2)) {
		if (wait_for_bctrl(mga2))
			return -1;
	}
	return mga2->head;
}

static int get_free_desc(struct mga2 *mga2)
{
	if (mga2->flags & MGA2_BCTRL_OFF) {
		__mga2_sync(mga2);
		return 0;
	}
	return __get_free_desc(mga2);
}

static int __append_desc(struct mga2 *mga2)
{
	int ret = 0, i;
	struct bctrl_desc *desc = &mga2->bctrl->desc[mga2->head];
	struct bctrl_base *base = &mga2->bctrl->base;
	dma_addr_t addr = idx_to_addr(mga2, mga2->head);
	write_desc(desc, 0);
	for (i = 0; i < MGA2_TIMEOUT_MSEC; i++) {
		int busy = rfb(MGA2_BCTRL_STATUS) & MGA2_BCTRL_B_BUSY;
		dma_addr_t cur = read_desc(base);
		if (!busy) {
			write_desc(base, addr);
			wfb(MGA2_BCTRL_B_START, MGA2_BCTRL_START);
			circ_clear(mga2);
			break;
		}

		if (cur)
			break;
		/* last desc is processing */
		msleep(1);
	}

	if (i == MGA2_TIMEOUT_MSEC) {
		DRM_ERROR("append bctrl timeout\n");
		ret = -ETIME;
	}
	mga2->head = circ_inc(mga2->head);
	return ret;
}

#ifdef __DEBUG
static void dump_bctrl(struct mga2 *mga2)
{
	int i;
	u32 *p = (u32 *) mga2->bctrl;

	__mga2_sync(mga2);
	printk("bctrl dump:\n");
	for (i = 0; i < sizeof(*mga2->bctrl) / 4; i++)
		printk(" %p: %08x\n", __pa(p + i), p[i]);
	mga2->tail = mga2->head = 0;

	printk("bitblt regs dump:\n");
	for (i = 0; i < 0x20; i += 4)
		printk(" %x: %08x\n", REG_BB_CTRL + i, rfb(REG_BB_CTRL + i));
}
#endif

static int append_desc(struct mga2 *mga2)
{
	if (mga2->flags & MGA2_BCTRL_OFF) {
		return 0;
	}
	__append_desc(mga2);
#ifdef __DEBUG
	dump_bctrl(info);
#endif
	return 0;
}

static inline void __wdesc(struct bctrl_cmd *c, u32 data, u32 reg,
			   bool first, bool last)
{
	c->ctrl = cpu_to_le32((last << 15) | first);
	c->data = cpu_to_le32(data);
	c->reg = cpu_to_le32(reg / 4);
}

#define wdesc(__cmd, __data, __reg, __first, __last)	do {		\
	if (mga2->flags & MGA2_BCTRL_OFF) {		\
		wfb(__data, __reg);				\
		break;						\
	}							\
	__wdesc(__cmd, __data, __reg, __first, __last);			\
} while(0)

static void mga2_color_blit(int width, int height, int pitch, int dest,
			    int rop, int color, int Bpp, struct mga2 *mga2)
{
	struct bctrl_cmd *c;
	int head = get_free_desc(mga2);
	u32 ctrl = rop | BB_CTRL_CE_EN | BB_CTRL_SFILL_EN | BB_CTRL_CMD_START
	    | (((Bpp - 1) & 0x3) << 10);
	if (head < 0)
		return;

	c = mga2->bctrl->desc[head].cmd;

	wdesc(&c[0], color, REG_BB_FG, 1, 0);
	wdesc(&c[1], (height << 16) | (width * Bpp), REG_BB_WINDOW, 0, 0);
	wdesc(&c[2], dest, REG_BB_DADDR, 0, 0);
	wdesc(&c[3], pitch << 16 | 0, REG_BB_PITCH, 0, 0);
	wdesc(&c[4], ctrl, REG_BB_CTRL, 0, 1);

	append_desc(mga2);
}

void mga2_fillrect(struct fb_info *info, const struct fb_fillrect *rect)
{
	struct mga2_fbdev *fb = info->par;
	struct mga2 *mga2 = fb->helper.dev->dev_private;
	u32 dx, dy, width, height, dest, rop = 0, color = 0;
	u32 Bpp = info->var.bits_per_pixel >> 3;

	if (info->flags & FBINFO_HWACCEL_DISABLED) {
		cfb_fillrect(info, rect);
		return;
	}

	if (Bpp == 1)
		color = rect->color;
	else
		color = ((u32 *) (info->pseudo_palette))[rect->color];

	rop = (rect->rop != ROP_COPY) ? BB_CTRL_ROP_XOR : BB_CTRL_ROP_SRC;

	dx = rect->dx * Bpp;
	width = rect->width;
	dy = rect->dy;
	height = rect->height;

	dest = info->fix.smem_start - mga2->vram_paddr +
			(dy * info->fix.line_length) + dx;
	mga2_color_blit(width, height, info->fix.line_length, dest, rop, color,
			Bpp, mga2);
}

static void mga2_hw_copyarea(struct mga2 *mga2, unsigned sBase,	/* Address of source: offset in frame buffer */
			     unsigned sPitch,	/* Pitch value of source surface in BYTE */
			     unsigned sx, unsigned sy,	/* Starting coordinate of source surface */
			     unsigned dBase,	/* Address of destination: offset in frame buffer */
			     unsigned dPitch,	/* Pitch value of destination surface in BYTE */
			     unsigned Bpp,	/* Color depth of destination surface */
			     unsigned dx, unsigned dy,	/* Starting coordinate of destination surface */
			     unsigned width, unsigned height	/* width and height of rectangle in pixel value */
    )
{
	struct bctrl_cmd *c;
	int head = get_free_desc(mga2);
	unsigned saddr, daddr;
	unsigned ctrl = BB_CTRL_ROP_SRC | BB_CTRL_CMD_START;

	if (head < 0)
		return;
	c = mga2->bctrl->desc[head].cmd;

	saddr = sBase + sy * dPitch + sx * Bpp;
	daddr = dBase + dy * dPitch + dx * Bpp;

	wdesc(&c[0], (height << 16) | (width * Bpp), REG_BB_WINDOW, 1, 0);
	wdesc(&c[1], saddr, REG_BB_SADDR, 0, 0);
	wdesc(&c[2], daddr, REG_BB_DADDR, 0, 0);
	wdesc(&c[3], sPitch << 16 | sPitch, REG_BB_PITCH, 0, 0);
	wdesc(&c[4], ctrl, REG_BB_CTRL, 0, 1);

	append_desc(mga2);
}

static void mga2_copyarea(struct fb_info *info, const struct fb_copyarea *area)
{
	unsigned base, pitch, Bpp;
	struct mga2_fbdev *fb = info->par;
	struct mga2 *mga2 = fb->helper.dev->dev_private;
	if (info->flags & FBINFO_HWACCEL_DISABLED) {
		cfb_copyarea(info, area);
		return;
	}

	base = info->fix.smem_start - mga2->vram_paddr;
	pitch = info->fix.line_length;
	Bpp = info->var.bits_per_pixel >> 3;

	mga2_hw_copyarea(mga2, base, pitch, area->sx, area->sy,
			 base, pitch, Bpp, area->dx, area->dy,
			 area->width, area->height);
}

static void mga2_hw_imageblit(struct mga2 *mga2, dma_addr_t pSrcbuf,	/* pointer to start of source buffer in system memory */
			      unsigned dBase,	/* Address of destination: offset in frame buffer */
			      unsigned dPitch,	/* Pitch value of destination surface in BYTE */
			      unsigned Bpp,	/* Color depth of destination surface */
			      unsigned dx, unsigned dy,	/* Starting coordinate of destination surface */
			      unsigned width, unsigned height,	/* width and height of rectange in pixel value */
			      unsigned fColor,	/* Foreground color (corresponding to a 1 in the monochrome data */
			      unsigned bColor	/* Background color (corresponding to a 0 in the monochrome data */
	) {
	unsigned cbpp;
	unsigned ctrl = BB_CTRL_CE_EN | BB_CTRL_SDMA_EN |
	    BB_CTRL_CMD_START | BB_CTRL_ROP_SRC |
	    BB_CTRL_SRC_MODE | BB_CTRL_BITS_IN_BYTE_TWISTER;
	unsigned daddr;
	struct bctrl_cmd *c;
	int head = get_free_desc(mga2);
	if (head < 0)
		return;
	c = mga2->bctrl->desc[head].cmd;

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
	}

	daddr = dBase + dy * dPitch + dx * Bpp;

	ctrl |= cbpp;

	wdesc(&c[0], (height << 16) | (width * Bpp), REG_BB_WINDOW, 1, 0);
	wdesc(&c[1], pSrcbuf, REG_BB_SADDR, 0, 0);
	wdesc(&c[2], daddr, REG_BB_DADDR, 0, 0);
	wdesc(&c[3], dPitch << 16 | 0, REG_BB_PITCH, 0, 0);
	wdesc(&c[4], bColor, REG_BB_BG, 0, 0);
	wdesc(&c[5], fColor, REG_BB_FG, 0, 0);
	wdesc(&c[6], ctrl, REG_BB_CTRL, 0, 1);

	append_desc(mga2);
}

static int mga2_map_addr(struct mga2 *mga2, const void *addr, u32 size,
			 dma_addr_t * dma)
{

	if (mga2->subdevice == MGA2_P2 || mga2->subdevice == MGA2_P2_PROTO) {
		*dma = __pa(addr);
		return 0;
	}
	*dma =
	    dma_map_single(mga2->drm->dev, (void *)addr, size, DMA_TO_DEVICE);
	if (dma_mapping_error(mga2->drm->dev, *dma))
		return -EAGAIN;
	return 0;
}

static void mga2_unmap_addr(struct mga2 *mga2, dma_addr_t dma_addr, u32 size)
{

	if (mga2->subdevice == MGA2_P2 || mga2->subdevice == MGA2_P2_PROTO) {
		return;
	}
	dma_unmap_single(mga2->drm->dev, dma_addr, size, DMA_TO_DEVICE);

}

#if 0
static int mga2_map_page(struct mga2 *mga2, struct page *page,
			 size_t size, dma_addr_t * dma)
{

	if (mga2->subdevice == MGA2_P2 || mga2->subdevice == MGA2_P2_PROTO) {
		*dma = page_to_phys(page);
		return 0;
	}
	*dma = dma_map_page(mga2->drm->dev, page, 0, size, DMA_TO_DEVICE);
	if (dma_mapping_error(mga2->drm->dev, *dma))
		return -EAGAIN;
	return 0;
}
#endif

static void mga2_imageblit(struct fb_info *info, const struct fb_image *image)
{
	struct mga2_fbdev *fb = info->par;
	struct mga2 *mga2 = fb->helper.dev->dev_private;
	unsigned base, pitch, Bpp;
	unsigned fgcol, bgcol;
	int offset = (void *)image->data - (void *)info->pixmap.addr;
	BUG_ON(offset > info->pixmap.size || offset < 0);

	if (info->flags & FBINFO_HWACCEL_DISABLED ||
	    mga2->subdevice == MGA2_PCI_PROTO || !fb->pixmap_dma) {
		cfb_imageblit(info, image);
		return;
	}

	base = info->fix.smem_start - mga2->vram_paddr;
	pitch = info->fix.line_length;
	Bpp = info->var.bits_per_pixel >> 3;

	if (info->fix.visual == FB_VISUAL_TRUECOLOR ||
	    info->fix.visual == FB_VISUAL_DIRECTCOLOR) {
		fgcol = ((u32 *) info->pseudo_palette)[image->fg_color];
		bgcol = ((u32 *) info->pseudo_palette)[image->bg_color];
	} else {
		fgcol = image->fg_color;
		bgcol = image->bg_color;
	}

	mga2_hw_imageblit(mga2, fb->pixmap_dma + offset, base, pitch, Bpp,
			  image->dx, image->dy,
			  image->width, image->height, fgcol, bgcol);
}

static void mga2_load_mono_to_argb_cursor(u32 __iomem * dst1, const void *data8,
					  u32 bg, u32 fg, u32 w, u32 h)
{
	int i, j;
	const int spitch = DIV_ROUND_UP(w, 8), dpitch = MGA2_MAX_HWC_WIDTH;
	const u8 *s = data8, *src;

	for (i = 0; i < h; i++, dst1 += dpitch, s += spitch) {
		u32 __iomem *dst = dst1;
		int shift;

		for (j = 0, shift = 7, src = s; j < w; j++, dst++, shift--) {
			u32 p = *src & (1 << shift) ? fg : bg;
			writel(p, dst);
			if (!shift) {
				shift = 7;
				src++;
			}
		}
	}
}

static int mga2_load_cursor(struct drm_crtc *crtc, struct fb_info *info,
			    struct fb_cursor *c)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	struct fb_image *image = &c->image;
	u32 s_pitch = (c->image.width + 7) >> 3;
	unsigned i, dsize;
	u8 *src;
	u32 bg_idx = image->bg_color;
	u32 fg_idx = image->fg_color;
	u32 fg, bg;
	void __iomem *dst = mga2_crtc->cursor_addr;
	s_pitch = (c->image.width + 7) >> 3;
	dsize = s_pitch * image->height;

	src = kmalloc(dsize, GFP_ATOMIC);
	if (!src) {
		return -ENOMEM;
	}

	switch (c->rop) {
	case ROP_XOR:
		for (i = 0; i < dsize; i++) {
			src[i] = image->data[i] ^ c->mask[i];
		}
		break;
	case ROP_COPY:
	default:
		for (i = 0; i < dsize; i++) {
			src[i] = image->data[i] & c->mask[i];
		}
		break;
	}

	fg = ((info->cmap.red[fg_idx] & 0xff) << 0) |
	    ((info->cmap.green[fg_idx] & 0xff) << 8) |
	    ((info->cmap.blue[fg_idx] & 0xff) << 16) | (0xff << 24);

	bg = ((info->cmap.red[bg_idx] & 0xff) << 0) |
	    ((info->cmap.green[bg_idx] & 0xff) << 8) |
	    ((info->cmap.blue[bg_idx] & 0xff) << 16);

	mga2_load_mono_to_argb_cursor(dst, c->mask, bg, fg, image->width,
				      image->height);
	kfree(src);
	return 0;
}

static int __mga2_fb_cursor(struct drm_crtc *crtc, struct fb_info *info,
			    struct fb_cursor *cursor)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	mga2_hide_cursor(crtc);

	if (cursor->set & FB_CUR_SETPOS) {
		mga2_cursor_move(crtc, cursor->image.dx - info->var.xoffset,
				 cursor->image.dy - info->var.yoffset);
	}

	if (cursor->set & FB_CUR_SETSIZE) {
		memset_io(mga2_crtc->cursor_addr, 0, MGA2_HWC_SIZE);
	}
	if (cursor->set & FB_CUR_SETCMAP)	/* Nothing to do */
		;

	if (cursor->set & (FB_CUR_SETSHAPE))
		mga2_load_cursor(crtc, info, cursor);

	if (cursor->enable)
		mga2_show_cursor(crtc, mga2_crtc->cursor_offset);

	return 0;
}

static int mga2_fb_cursor(struct fb_info *info, struct fb_cursor *cursor)
{
	struct mga2_fbdev *fb = info->par;
	int i;

	if (cursor->image.width > MGA2_MAX_HWC_WIDTH
	    || cursor->image.height > MGA2_MAX_HWC_HEIGHT)
		return -EINVAL;

	for (i = 0; i < fb->helper.crtc_count; i++) {
		struct drm_crtc *crtc = fb->helper.crtc_info[i].mode_set.crtc;
		__mga2_fb_cursor(crtc, info, cursor);
	}

	return 0;
}

static struct fb_ops mga2fb_ops = {
	.owner = THIS_MODULE,
	.fb_check_var = drm_fb_helper_check_var,
	.fb_set_par = drm_fb_helper_set_par,
	.fb_fillrect = mga2_fillrect,
	.fb_copyarea = mga2_copyarea,
	.fb_imageblit = mga2_imageblit,
	.fb_cursor = mga2_fb_cursor,
	.fb_sync = mga2_sync,
	.fb_pan_display = drm_fb_helper_pan_display,
	.fb_blank = drm_fb_helper_blank,
	.fb_setcmap = drm_fb_helper_setcmap,
};

static int mga2fb_create_object(struct mga2_fbdev *fb,
				struct drm_mode_fb_cmd2 *mode_cmd,
				struct drm_gem_object **gobj_p)
{
	struct drm_device *drm = fb->helper.dev;
	u32 bpp, depth;
	u32 size;
	struct drm_gem_object *gobj;
	drm_fb_get_bpp_depth(mode_cmd->pixel_format, &depth, &bpp);

	size = mode_cmd->pitches[0] * mode_cmd->height;
	gobj = mga2_gem_create(drm, size, MGA2_GEM_DOMAIN_VRAM);

	if (IS_ERR(gobj))
		return PTR_ERR(gobj);

	*gobj_p = gobj;
	return 0;
}

static int mga2fb_create(struct mga2_fbdev *fb,
			 struct drm_fb_helper_surface_size *sizes)
{
	struct drm_device *drm = fb->helper.dev;
	struct mga2 *mga2 = drm->dev_private;
	struct drm_mode_fb_cmd2 mode_cmd;
	struct drm_framebuffer *dfb;
	struct fb_info *info;
	int size, ret;
	struct device *device = &drm->pdev->dev;
	struct drm_gem_object *gobj = NULL;
	struct drm_mm_node *node;
	mode_cmd.width = sizes->surface_width;
	mode_cmd.height = sizes->surface_height;
	mode_cmd.pitches[0] = mode_cmd.width * ((sizes->surface_bpp + 7) / 8);

	mode_cmd.pixel_format = drm_mode_legacy_fb_format(sizes->surface_bpp,
							  sizes->surface_depth);

	size = mode_cmd.pitches[0] * mode_cmd.height;

	ret = mga2fb_create_object(fb, &mode_cmd, &gobj);
	if (ret) {
		DRM_ERROR("failed to create fbcon backing object %d\n", ret);
		return ret;
	}

	info = framebuffer_alloc(0, device);
	if (!info) {
		ret = -ENOMEM;
		goto out;
	}
	info->par = fb;

	ret = mga2_framebuffer_init(drm, &fb->afb, &mode_cmd, gobj);
	if (ret)
		goto out;
	node = gobj->driver_private;

	dfb = &fb->afb.base;
	fb->helper.fb = dfb;
	fb->helper.fbdev = info;

	strcpy(info->fix.id, "mga2");

	info->flags = FBINFO_DEFAULT /*| FBINFO_CAN_FORCE_OUTPUT */ ;

	info->flags = FBINFO_DEFAULT | FBINFO_HWACCEL_COPYAREA |
	    FBINFO_HWACCEL_FILLRECT | FBINFO_HWACCEL_IMAGEBLIT;
	if (mga2_nofbaccel == 1)
		info->flags = FBINFO_DEFAULT | FBINFO_HWACCEL_DISABLED;
	else if (mga2_nofbaccel == 2)
		mga2->flags |= MGA2_BCTRL_OFF;

	if (mga2_nohwcursor)
		mga2fb_ops.fb_cursor = NULL;

	info->fbops = &mga2fb_ops;

	ret = fb_alloc_cmap(&info->cmap, 256, 0);
	if (ret) {
		ret = -ENOMEM;
		goto out;
	}

	drm_fb_helper_fill_fix(info, dfb->pitches[0], dfb->depth);
	drm_fb_helper_fill_var(info, &fb->helper, sizes->fb_width,
			       sizes->fb_height);
	info->apertures = alloc_apertures(1);
	if (!info->apertures) {
		ret = -ENOMEM;
		goto out;
	}
	info->apertures->ranges[0].base = pci_resource_start(drm->pdev, 0);
	info->apertures->ranges[0].size = pci_resource_len(drm->pdev, 0);

	info->screen_base = ioremap_wc(node->start, size);
	info->screen_size = size;

	info->fix.smem_start = node->start;
	info->fix.smem_len = size;
	info->pixmap.flags = FB_PIXMAP_SYSTEM;

	DRM_DEBUG_KMS("allocated %dx%d\n", dfb->width, dfb->height);
	DRM_INFO("fb mappable at 0x%lX\n", info->fix.smem_start);
	DRM_INFO("fb is %dx%d-%d\n", sizes->fb_width,
		 sizes->fb_height, dfb->depth);
	DRM_INFO("   pitch is %d\n", dfb->pitches[0]);

	return 0;
      out:
	return ret;
}

static void mga2_fb_gamma_set(struct drm_crtc *crtc, u16 red, u16 green,
			      u16 blue, int regno)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	mga2_crtc->lut_r[regno] = red >> 8;
	mga2_crtc->lut_g[regno] = green >> 8;
	mga2_crtc->lut_b[regno] = blue >> 8;
}

static void mga2_fb_gamma_get(struct drm_crtc *crtc, u16 * red, u16 * green,
			      u16 * blue, int regno)
{
	struct mga2_crtc *mga2_crtc = to_mga2_crtc(crtc);
	*red = mga2_crtc->lut_r[regno] << 8;
	*green = mga2_crtc->lut_g[regno] << 8;
	*blue = mga2_crtc->lut_b[regno] << 8;
}

static int mga2_find_or_create_single(struct drm_fb_helper *helper,
				      struct drm_fb_helper_surface_size *sizes)
{
	struct mga2_fbdev *fb = (struct mga2_fbdev *)helper;
	int new_fb = 0;
	int ret;

	if (!helper->fb) {
		ret = mga2fb_create(fb, sizes);
		if (ret)
			return ret;
		new_fb = 1;
	}
	return new_fb;
}

static struct drm_fb_helper_funcs mga2_fb_helper_funcs = {
	.gamma_set = mga2_fb_gamma_set,
	.gamma_get = mga2_fb_gamma_get,
	.fb_probe = mga2_find_or_create_single,
};

static void mga2_fbdev_destroy(struct drm_device *drm, struct mga2_fbdev *fb)
{
	struct fb_info *info;
	struct mga2_framebuffer *afb = &fb->afb;
	if (fb->helper.fbdev) {
		struct mga2 *mga2 = drm->dev_private;
		info = fb->helper.fbdev;
		mga2_unmap_addr(mga2, fb->pixmap_dma, info->pixmap.size);

		unregister_framebuffer(info);
		if (info->cmap.len)
			fb_dealloc_cmap(&info->cmap);
		framebuffer_release(info);
	}

	if (afb->gobj) {
		drm_gem_object_unreference_unlocked(afb->gobj);
		afb->gobj = NULL;
	}
	drm_fb_helper_fini(&fb->helper);
	drm_framebuffer_cleanup(&afb->base);
}

int mga2_fbdev_init(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;
	struct mga2_fbdev *fb;
	int ret;

	fb = kzalloc(sizeof(struct mga2_fbdev), GFP_KERNEL);
	if (!fb)
		return -ENOMEM;

	mga2->fbdev = fb;
	fb->helper.funcs = &mga2_fb_helper_funcs;

	ret = mga2fb_bctrl_init(mga2);
	if (ret)
		goto fail;

	ret = drm_fb_helper_init(drm, &fb->helper, 1, 1);
	if (ret)
		goto fail;

	drm_fb_helper_single_add_all_connectors(&fb->helper);
	drm_fb_helper_initial_config(&fb->helper, 32);

	if (mga2_map_addr(mga2, fb->helper.fbdev->pixmap.addr,
			  fb->helper.fbdev->pixmap.size, &fb->pixmap_dma))
		goto fail;

	return 0;
      fail:
	kfree(fb);
	return ret;
}

void mga2_fbdev_fini(struct drm_device *drm)
{
	struct mga2 *mga2 = drm->dev_private;

	if (!mga2->fbdev)
		return;

	mga2fb_bctrl_fini(mga2);
	mga2_fbdev_destroy(drm, mga2->fbdev);
	kfree(mga2->fbdev);
	mga2->fbdev = NULL;
}

void mga2_fbdev_set_suspend(struct drm_device *drm, int state)
{
	struct mga2 *mga2 = drm->dev_private;

	if (!mga2->fbdev)
		return;

	fb_set_suspend(mga2->fbdev->helper.fbdev, state);
}

int mga2_bctrl_ioctl(struct drm_device *drm, void *data, struct drm_file *file)
{
	int ret = 0;
	struct drm_mga2_bctrl *udesc = data;
	struct mga2 *mga2 = drm->dev_private;
	struct bctrl_base *base = &mga2->bctrl->base;
	struct drm_mga2_buffers __user *b = (void *)((long)udesc->buffers_ptr);
	struct drm_gem_object *gobj;
	struct drm_mm_node *node;

	u32 *desc, nr, handle;
	mutex_lock(&mga2->bctrl_mu);

	if (!access_ok(VERIFY_READ, b, PAGE_SIZE)) {
		ret = -EFAULT;
		goto out;

	}

	if (!(gobj = drm_gem_object_lookup(drm, file, udesc->desc_handle))) {
		ret = -ENOENT;
		goto out;
	}
	node = gobj->driver_private;

	desc = __va(node->start);
	for (ret = __get_user(nr, &b->nr); nr && !ret;) {
		struct drm_gem_object *o;
		struct drm_mm_node *n;
		unsigned long a = -1;
		int i;
		if (__get_user(handle, &b->handle)) {
			ret = -EFAULT;
			goto out;
		}
		if (!(o = drm_gem_object_lookup(drm, file, handle))) {
			ret = -ENOENT;
			goto out_free;
		}
		n = o->driver_private;
		switch (o->write_domain) {
		case MGA2_GEM_DOMAIN_VRAM:
			a = n->start - mga2->vram_paddr;
			break;
		case MGA2_GEM_DOMAIN_CPU:
			a = n->size;
			break;
		default:
			BUG();
		}
		for (i = 0; i < nr; i++) {
			u32 offset;
			if (__get_user(offset, &b->offset[i])) {
				ret = -EFAULT;
				drm_gem_object_unreference(o);
				goto out_free;
			}
			desc[offset / sizeof(*desc)] = a;
		}
		drm_gem_object_unreference(o);
	}

	if ((ret = __mga2_sync(mga2))) {
		goto out_free;
	}

	write_desc(base, node->start);
	wfb(MGA2_BCTRL_B_START, MGA2_BCTRL_START);

      out_free:
	drm_gem_object_unreference(gobj);
      out:
	mutex_unlock(&mga2->bctrl_mu);
	return ret;
}

int mga2_gem_sync_ioctl(struct drm_device *drm, void *data,
			struct drm_file *filp)
{
	struct mga2 *mga2 = drm->dev_private;
	return __mga2_sync(mga2);
}
