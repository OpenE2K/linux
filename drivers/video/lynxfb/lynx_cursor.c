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
#include "lynx_help.h"
#include "lynx_cursor.h"

#define PEEK32(addr) \
readl(cursor->mmio + (addr))

#define POKE32(addr, data) \
writel((data), cursor->mmio + (addr))

/* cursor control for voyager and 718/750*/

#define HWC_ADDRESS                         0x0
#define HWC_ADDRESS_ENABLE_LSB              31
#define HWC_ADDRESS_EXT_LSB                 27
#define HWC_ADDRESS_CS                      26
#define HWC_ADDRESS_ADDRESS_LSB             0
#define HWC_LOCATION                        0x4
#define HWC_LOCATION_TOP_LSB                27
#define HWC_LOCATION_Y_LSB                  16
#define HWC_LOCATION_LEFT                   11
#define HWC_LOCATION_X_LSB                  0
#define HWC_COLOR_12                        0x8
#define HWC_COLOR_3                         0xC

/* hw_cursor_xxx works for voyager, 718 and 750 */
void hw_cursor_enable(struct lynx_cursor *cursor)
{
	u32 reg;
	reg = ((cursor->offset << HWC_ADDRESS_ADDRESS_LSB) &
	    (~(1 << HWC_ADDRESS_EXT_LSB))) | (1 << HWC_ADDRESS_ENABLE_LSB);
	POKE32(HWC_ADDRESS, reg);
}

void hw_cursor_disable(struct lynx_cursor *cursor)
{
	POKE32(HWC_ADDRESS, 0);
}

void hw_cursor_setSize(struct lynx_cursor *cursor, int w, int h)
{
	cursor->w = w;
	cursor->h = h;
}

void hw_cursor_setPos(struct lynx_cursor *cursor, int x, int y)
{
	u32 reg;
	reg = (y << HWC_LOCATION_Y_LSB) | (x << HWC_LOCATION_X_LSB);
	POKE32(HWC_LOCATION, reg);
}

void hw_cursor_setColor(struct lynx_cursor *cursor, u32 fg, u32 bg)
{
	POKE32(HWC_COLOR_12, (fg << 16) | (bg & 0xffff));
	POKE32(HWC_COLOR_3, 0xffe0);
}

void hw_cursor_setData(struct lynx_cursor *cursor,
		       u16 rop, const u8 * pcol, const u8 * pmsk)
{
	int i, j, count, pitch, offset;
	u8 color, mask, opr;
	u16 data;
	u16 *pbuffer, *pstart;

	/*  in byte */
	pitch = cursor->w >> 3;

	/* in byte      */
	count = pitch * cursor->h;

	/* in ushort */
	offset = cursor->maxW * 2 / 8 / 2;

	data = 0;
	pstart = (u16 *) cursor->vstart;
	pbuffer = pstart;

/*
	if (odd &1) {
		hw_cursor_setData2(cursor, rop, pcol, pmsk);
	}
	odd++;
	if (odd > 0xfffffff0)
		odd=0;
*/

	for (i = 0; i < count; i++) {

		color = *pcol++;
		mask = *pmsk++;
		data = 0;

		/* either method below works well,
		 * but method 2 shows no lag
		 * and method 1 seems a bit wrong*/

		for (j = 0; j < 8; j++) {
			if (mask & (0x80 >> j)) {
				if (rop == ROP_XOR)
					opr = mask ^ color;
				else
					opr = mask & color;

				/* 2 stands for forecolor and 1 for backcolor */
				data |=
				    ((opr & (0x80 >> j)) ? 2 : 1) << (j *
								      2);
			}
		}

		writew(data, pbuffer);

		/* assume pitch is 1, 2, 4, 8, ... */
		if ((i + 1) % pitch == 0) {
			/* need a return */
			pstart += offset;
			pbuffer = pstart;
		} else {
			pbuffer++;
		}

	}


}

void hw_cursor_setData2(struct lynx_cursor *cursor,
			u16 rop, const u8 * pcol, const u8 * pmsk)
{
	int i, j, count, pitch, offset;
	u8 color, mask;
	u16 data;
	u16 *pbuffer, *pstart;

	/*  in byte */
	pitch = cursor->w >> 3;

	/* in byte      */
	count = pitch * cursor->h;

	/* in ushort */
	offset = cursor->maxW * 2 / 8 / 2;

	data = 0;
	pstart = (u16 *) cursor->vstart;
	pbuffer = pstart;

	for (i = 0; i < count; i++) {

		color = *pcol++;
		mask = *pmsk++;
		data = 0;

		/* either method below works well,  but method 2 shows no lag */

		for (j = 0; j < 8; j++) {
			if (mask & (1 << j))
				data |=
				    ((color & (1 << j)) ? 1 : 2) << (j *
								     2);
		}

		writew(data, pbuffer);

		/* assume pitch is 1, 2, 4, 8, ... */
		if (!(i & (pitch - 1))) {


			/* need a return */
			pstart += offset;
			pbuffer = pstart;
		} else {
			pbuffer++;
		}

	}
}
