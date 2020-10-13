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
#include <linux/module.h>
#include <linux/kernel.h>
#include <linux/errno.h>
#include <linux/string.h>
#include <linux/mm.h>
#include <linux/slab.h>
#include <linux/delay.h>
#include <linux/fb.h>
#include <linux/ioport.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/vmalloc.h>
#include <linux/pagemap.h>
#include <linux/console.h>
#if LINUX_VERSION_CODE >= KERNEL_VERSION(2, 6, 10)
/* no below two header files in 2.6.9 */
#include <linux/platform_device.h>
#include <linux/screen_info.h>
#else
/* nothing by far */
#endif

#include "lynx_drv.h"
#include "lynx_accel.h"
#include "lynx_help.h"
static inline void write_dpr(struct lynx_accel *accel, int offset,
			     u32 regValue)
{
	writel(regValue, accel->dprBase + offset);
}

static inline u32 read_dpr(struct lynx_accel *accel, int offset)
{
	return readl(accel->dprBase + offset);
}

#define	writedp_rep	iowrite32_rep

void hw_de_init(struct lynx_accel *accel)
{
	/* setup 2d engine registers */
	u32 reg, clr;
	ENTER();
	write_dpr(accel, DE_MASKS, 0xFFFFFFFF);

	/* dpr1c */
	reg = 3 << DE_STRETCH_FORMAT_SOURCE_HEIGHT_LSB;

	clr = (~(1 << DE_STRETCH_FORMAT_PATTERN_XY_LSB)) &
	    (~(7 << DE_STRETCH_FORMAT_PATTERN_Y_LSB)) &
	    (~(7 << DE_STRETCH_FORMAT_PATTERN_X_LSB)) &
	    (~(15 << DE_STRETCH_FORMAT_ADDRESSING_LSB)) &
	    (~(0xFFF << DE_STRETCH_FORMAT_SOURCE_HEIGHT_LSB));

	/* DE_STRETCH bpp format need be initilized in setMode routine */
	write_dpr(accel, DE_STRETCH_FORMAT,
		  (read_dpr(accel, DE_STRETCH_FORMAT) & clr) | reg);

	/* disable clipping and transparent */
	write_dpr(accel, DE_CLIP_TL, 0);
	write_dpr(accel, DE_CLIP_BR, 0);

	write_dpr(accel, DE_COLOR_COMPARE_MASK, 0);
	write_dpr(accel, DE_COLOR_COMPARE, 0);

	reg = (~(1 << DE_CONTROL_TRANSPARENCY_LSB)) &
	    (~(1 << DE_CONTROL_TRANSPARENCY_MATCH_LSB)) &
	    (~(1 << DE_CONTROL_TRANSPARENCY_SELECT_LSB));

	clr = (~(1 << DE_CONTROL_TRANSPARENCY_LSB)) &
	    (~(1 << DE_CONTROL_TRANSPARENCY_MATCH_LSB)) &
	    (~(1 << DE_CONTROL_TRANSPARENCY_SELECT_LSB));

	/* dpr0c */
	write_dpr(accel, DE_CONTROL,
		  (read_dpr(accel, DE_CONTROL) & clr) | reg);
	LEAVE();
}

/* set2dformat only be called from setmode functions
 * but if you need dual framebuffer driver, need call set2dformat
 * every time you use 2d function */

void hw_set2dformat(struct lynx_accel *accel, int fmt)
{
	u32 reg;
	ENTER();
	/* fmt=0, 1, 2 for 8, 16, 32, bpp on sm718/750/502 */
	reg = read_dpr(accel, DE_STRETCH_FORMAT);
	reg &= (~(3 << DE_STRETCH_FORMAT_PIXEL_FORMAT_LSB));
	reg |= fmt << DE_STRETCH_FORMAT_PIXEL_FORMAT_LSB;
	write_dpr(accel, DE_STRETCH_FORMAT, reg);
	LEAVE();
}

int hw_fillrect(struct lynx_accel *accel,
		u32 base, u32 pitch, u32 Bpp,
		u32 x, u32 y, u32 width, u32 height, u32 color, u32 rop)
{
	u32 deCtrl;

#ifdef CONFIG_FB_LYNXFB_DOMAINS
	if (accel->de_wait(accel->domain) != 0)
#else
	if (accel->de_wait() != 0)
#endif
	{

		/* int time wait and always busy, seems hardware
		 * got something error */
		dbg_msg("%s:De engine always bussy\n", __func__);
		return -1;
	}

	write_dpr(accel, DE_WINDOW_DESTINATION_BASE, base);
	write_dpr(accel, DE_PITCH,
		  (pitch / Bpp << DE_PITCH_DESTINATION_LSB) |
		  (pitch / Bpp << DE_PITCH_SOURCE_LSB));

	write_dpr(accel, DE_WINDOW_WIDTH,
		  (pitch / Bpp << DE_WINDOW_WIDTH_DESTINATION_LSB) |
		  (pitch / Bpp << DE_WINDOW_WIDTH_SOURCE_LSB));
	write_dpr(accel, DE_FOREGROUND, color);

	write_dpr(accel, DE_DESTINATION, (x << DE_DESTINATION_X_LSB) |
		  (y << DE_DESTINATION_Y_LSB));

	write_dpr(accel, DE_DIMENSION,
		  (width << DE_DIMENSION_X_LSB) |
		  (height << DE_DIMENSION_Y_ET_LSB));

	deCtrl =
	    ((1 << DE_CONTROL_STATUS_LSB) &
	    (~(1 << DE_CONTROL_DIRECTION_LSB))) |
	    (1 << DE_CONTROL_LAST_PIXEL_LSB) |
	    (1 << DE_CONTROL_COMMAND_LSB) |
	    (1 << DE_CONTROL_ROP_SELECT_LSB) | (rop << DE_CONTROL_ROP_LSB);
	write_dpr(accel, DE_CONTROL, deCtrl);
	return 0;
}

int hw_copyarea(struct lynx_accel *accel, unsigned int sBase,	/* Address of source: offset in frame buffer */
		unsigned int sPitch,	/* Pitch value of source surface in BYTE */
		unsigned int sx, unsigned int sy,	/* Starting coordinate of source surface */
		unsigned int dBase,	/* Address of destination: offset in frame buffer */
		unsigned int dPitch,	/* Pitch value of destination surface in BYTE */
		unsigned int Bpp,	/* Color depth of destination surface */
		unsigned int dx, unsigned int dy,	/* Starting coordinate of destination surface */
		unsigned int width, unsigned int height,	/* width and height of rectangle in pixel value */
		unsigned int rop2)
{				/* ROP value */
	unsigned int nDirection, de_ctrl;
	int opSign;
	nDirection = LEFT_TO_RIGHT;
	/* Direction of ROP2 operation: 1 = Left to Right, (-1) = Right to Left */
	opSign = 1;
	de_ctrl = 0;

	/* If source and destination are the same surface, need to check for overlay cases */
	if (sBase == dBase && sPitch == dPitch) {

		/* Determine direction of operation */
		if (sy < dy) {

			/* +----------+
			   |S         |
			   |   +----------+
			   |   |      |   |
			   |   |      |   |
			   +---|------+   |
			   |         D|
			   +----------+ */

			nDirection = BOTTOM_TO_TOP;
		} else if (sy > dy) {

			/* +----------+
			   |D         |
			   |   +----------+
			   |   |      |   |
			   |   |      |   |
			   +---|------+   |
			   |         S|
			   +----------+ */

			nDirection = TOP_TO_BOTTOM;
		} else {

			/* sy == dy */

			if (sx <= dx) {

				/* +------+---+------+
				   |S     |   |     D|
				   |      |   |      |
				   |      |   |      |
				   |      |   |      |
				   +------+---+------+ */

				nDirection = RIGHT_TO_LEFT;
			} else {

				/* sx > dx */

				/* +------+---+------+
				   |D     |   |     S|
				   |      |   |      |
				   |      |   |      |
				   |      |   |      |
				   +------+---+------+ */

				nDirection = LEFT_TO_RIGHT;
			}
		}
	}

	if ((nDirection == BOTTOM_TO_TOP) || (nDirection == RIGHT_TO_LEFT)) {

		sx += width - 1;
		sy += height - 1;
		dx += width - 1;
		dy += height - 1;
		opSign = (-1);
	}

	/* Note:
	   DE_FOREGROUND are DE_BACKGROUND are don't care.
	   DE_COLOR_COMPARE and DE_COLOR_COMPARE_MAKS are set by set deSetTransparency().
	 */

	/* 2D Source Base.
	   It is an address offset (128 bit aligned) from the beginning of frame buffer.
	 */
	write_dpr(accel, DE_WINDOW_SOURCE_BASE, sBase);

	/* 2D Destination Base.
	   It is an address offset (128 bit aligned) from the beginning of frame buffer.
	 */
	write_dpr(accel, DE_WINDOW_DESTINATION_BASE, dBase);


	{
		write_dpr(accel, DE_PITCH,
			  ((dPitch / Bpp) << DE_PITCH_DESTINATION_LSB) |
			  ((sPitch / Bpp) << DE_PITCH_SOURCE_LSB));
	}

	/* Screen Window width in Pixels.
	   2D engine uses this value to calculate the linear address in frame buffer for a given point.
	 */
	write_dpr(accel, DE_WINDOW_WIDTH,
		  ((dPitch / Bpp) << DE_WINDOW_WIDTH_DESTINATION_LSB) |
		  ((sPitch / Bpp) << DE_WINDOW_WIDTH_SOURCE_LSB));

#ifdef CONFIG_FB_LYNXFB_DOMAINS
	if (accel->de_wait(accel->domain) != 0)
#else
	if (accel->de_wait() != 0)
#endif
	{
		return -1;
	}

	{
		write_dpr(accel, DE_SOURCE, (~(1 << DE_SOURCE_WRAP_LSB)) &
			  ((sx << DE_SOURCE_X_K1_LSB) |
			  (sy << DE_SOURCE_Y_K2_LSB)));

		write_dpr(accel, DE_DESTINATION,
			  (dx << DE_DESTINATION_X_LSB) | (dy <<
							  DE_DESTINATION_Y_LSB));

		write_dpr(accel, DE_DIMENSION,
			  (width << DE_DIMENSION_X_LSB) |
			  (height << DE_DIMENSION_Y_ET_LSB));

		de_ctrl = (rop2 << DE_CONTROL_ROP_LSB) |
		    ((1 << DE_CONTROL_ROP_SELECT_LSB) &
		    (~(0x1f << DE_CONTROL_COMMAND_LSB))) |
		    (1 << DE_CONTROL_STATUS_LSB);

		if (nDirection == RIGHT_TO_LEFT)
			de_ctrl |= 1 << DE_CONTROL_DIRECTION_LSB;
		else
			de_ctrl &= ~(1 << DE_CONTROL_DIRECTION_LSB);

		write_dpr(accel, DE_CONTROL, de_ctrl);
	}

	return 0;
}

static unsigned int deGetTransparency(struct lynx_accel *accel)
{
	unsigned int de_ctrl;

	de_ctrl = read_dpr(accel, DE_CONTROL);
	de_ctrl &=
	    (1 << DE_CONTROL_TRANSPARENCY_MATCH_LSB) |
	    (1 << DE_CONTROL_TRANSPARENCY_SELECT_LSB) |
	    (1 << DE_CONTROL_TRANSPARENCY_LSB);
	return de_ctrl;
}

int hw_imageblit(struct lynx_accel *accel, const char *pSrcbuf,	/* pointer to start of source buffer in system memory */
		 unsigned int  srcDelta,	/* Pitch value (in bytes) of the source buffer, +ive means top down and -ive mean button up */
		 unsigned int startBit,	/* Mono data can start at any bit in a byte, this value should be 0 to 7 */
		 unsigned int dBase,	/* Address of destination: offset in frame buffer */
		 unsigned int dPitch,	/* Pitch value of destination surface in BYTE */
		 unsigned int bytePerPixel,	/* Color depth of destination surface */
		 unsigned int dx, unsigned int dy,	/* Starting coordinate of destination surface */
		 unsigned int width, unsigned int height,	/* width and height of rectange in pixel value */
		 unsigned int fColor,	/* Foreground color (corresponding to a 1 in the monochrome data */
		 unsigned int bColor,	/* Background color (corresponding to a 0 in the monochrome data */
		 unsigned int rop2) {	/* ROP value */
	unsigned int ulBytesPerScan;
	unsigned int de_ctrl = 0;
	int i;

	startBit &= 7;		/* Just make sure the start bit is within legal range */
	ulBytesPerScan = (width + startBit + 7) / 8;

#ifdef CONFIG_FB_LYNXFB_DOMAINS
	if (accel->de_wait(accel->domain) != 0)
#else
	if (accel->de_wait() != 0)
#endif
	{
		/* inf_msg("*** ImageBlit return -1 ***\n"); */
		return -1;
	}

	/* 2D Source Base.
	   Use 0 for HOST Blt.
	 */
	write_dpr(accel, DE_WINDOW_SOURCE_BASE, 0);

	/* 2D Destination Base.
	   It is an address offset (128 bit aligned) from the beginning of frame buffer.
	 */
	write_dpr(accel, DE_WINDOW_DESTINATION_BASE, dBase);
	{
		write_dpr(accel, DE_PITCH,
			  (dPitch /
			   bytePerPixel << DE_PITCH_DESTINATION_LSB) |
			  (dPitch / bytePerPixel << DE_PITCH_SOURCE_LSB));
	}

	/* Screen Window width in Pixels.
	   2D engine uses this value to calculate the linear address in frame buffer for a given point.
	 */
	write_dpr(accel, DE_WINDOW_WIDTH,
		  ((dPitch /
		    bytePerPixel) << DE_WINDOW_WIDTH_DESTINATION_LSB) |
		  ((dPitch / bytePerPixel) << DE_WINDOW_WIDTH_SOURCE_LSB));

	/* Note: For 2D Source in Host Write, only X_K1_MONO field is needed, and Y_K2 field is not used.
	   For mono bitmap, use startBit for X_K1. */
	write_dpr(accel, DE_SOURCE, startBit << DE_SOURCE_X_K1_MONO);
	write_dpr(accel, DE_DESTINATION, (dx << DE_DESTINATION_X_LSB) |
		  (dy << DE_DESTINATION_Y_LSB));

	write_dpr(accel, DE_DIMENSION,
		  (width << DE_DIMENSION_X_LSB) |
		  (height << DE_DIMENSION_Y_ET_LSB));
	write_dpr(accel, DE_FOREGROUND, fColor);
	write_dpr(accel, DE_BACKGROUND, bColor);

	de_ctrl = (rop2 << DE_CONTROL_ROP_LSB) |
	    (1 << DE_CONTROL_ROP_SELECT_LSB) |
	    (8 << DE_CONTROL_COMMAND_LSB) |
	    (1 << DE_CONTROL_HOST_LSB) | (1 << DE_CONTROL_STATUS_LSB);
	write_dpr(accel, DE_CONTROL, de_ctrl | deGetTransparency(accel));

	/* Write MONO data (line by line) to 2D Engine data port */
	for (i = 0; i < height; i++) {
		writedp_rep(accel->dpPortBase, pSrcbuf,
			ulBytesPerScan / 4 + (ulBytesPerScan % 4 ? 1 : 0));
		pSrcbuf += srcDelta;
	}
	return 0;
}
