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
#ifndef LYNX_CURSOR_H__
#define LYNX_CURSOR_H__

/* hw_cursor_xxx works for voyager, 718 and 750 */
void hw_cursor_enable(struct lynx_cursor *cursor);
void hw_cursor_disable(struct lynx_cursor *cursor);
void hw_cursor_setSize(struct lynx_cursor *cursor, int w, int h);
void hw_cursor_setPos(struct lynx_cursor *cursor, int x, int y);
void hw_cursor_setColor(struct lynx_cursor *cursor, u32 fg, u32 bg);
void hw_cursor_setData(struct lynx_cursor *cursor,
		       u16 rop, const u8 * data, const u8 * mask);
void hw_cursor_setData2(struct lynx_cursor *cursor,
			u16 rop, const u8 * data, const u8 * mask);

#endif
