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
#ifndef DDK750_MODE_H__
#define DDK750_MODE_H__

#include "ddk750_chip.h"

typedef enum _spolarity_t {
	POS = 0,		/* positive */
	NEG,			/* negative */
} spolarity_t;


typedef struct _mode_parameter_t {
	/* Horizontal timing. */
	unsigned long horizontal_total;
	unsigned long horizontal_display_end;
	unsigned long horizontal_sync_start;
	unsigned long horizontal_sync_width;
	spolarity_t horizontal_sync_polarity;

	/* Vertical timing. */
	unsigned long vertical_total;
	unsigned long vertical_display_end;
	unsigned long vertical_sync_start;
	unsigned long vertical_sync_height;
	spolarity_t vertical_sync_polarity;

	/* Refresh timing. */
	unsigned long pixel_clock;
	unsigned long horizontal_frequency;
	unsigned long vertical_frequency;

	/* Clock Phase. This clock phase only applies to Panel. */
	spolarity_t clock_phase_polarity;
} mode_parameter_t;

#ifdef CONFIG_FB_LYNXFB_DOMAINS
int ddk750_setModeTiming(mode_parameter_t *, clock_type_t, int);
#else
int ddk750_setModeTiming(mode_parameter_t *, clock_type_t);
#endif /* CONFIG_FB_LYNXFB_DOMAINS */ 

#endif
