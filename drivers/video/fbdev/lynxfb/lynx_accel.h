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
#ifndef ACCEL_H__
#define ACCEL_H__

#define HW_ROP2_COPY 0xc
#define HW_ROP2_XOR 0x6

/* notes: below address are the offset value from de_base_address (0x100000)*/

/* for sm718/750/502 de_base is at mmreg_1mb*/
#define DE_BASE_ADDR_TYPE1	0x100000
/* for sm712, de_base is at mmreg_32kb */
#define DE_BASE_ADDR_TYPE2	0x8000
/* for sm722, de_base is at mmreg_0 */
#define DE_BASE_ADDR_TYPE3 0

/* type1 data port address is at mmreg_0x110000*/
#define DE_PORT_ADDR_TYPE1 0x110000
/* for sm712, data port address is at mmreg_0 */
#define DE_PORT_ADDR_TYPE2 0x100000
/* for sm722, data port address is at mmreg_1mb */
#define DE_PORT_ADDR_TYPE3 0x100000

#define DE_SOURCE 0
#define DE_SOURCE_WRAP_LSB	31
#define DE_SOURCE_X_K1_LSB	16
#define DE_SOURCE_Y_K2_LSB	0
#define DE_SOURCE_X_K1_MONO 0

#define DE_DESTINATION		0x4
#define DE_DESTINATION_WRAP_LSB 31
#define DE_DESTINATION_X_LSB 16
#define DE_DESTINATION_Y_LSB 0

#define DE_DIMENSION                                    0x8
#define DE_DIMENSION_X_LSB                              16
#define DE_DIMENSION_Y_ET_LSB                           0

#define DE_CONTROL                                      0xC
#define DE_CONTROL_STATUS_LSB                           31
#define DE_CONTROL_DIRECTION_LSB                            27
#define DE_CONTROL_HOST_LSB                                 22
#define DE_CONTROL_LAST_PIXEL_LSB                           21
#define DE_CONTROL_COMMAND_LSB                          16
#define DE_CONTROL_ROP_SELECT_LSB                       15
#define DE_CONTROL_ROP2_SOURCE_LSB                      14
#define DE_CONTROL_TRANSPARENCY_MATCH_LSB               10
#define DE_CONTROL_TRANSPARENCY_SELECT_LSB              9
#define DE_CONTROL_TRANSPARENCY_LSB 					8
#define DE_CONTROL_ROP_LSB                              0
#define DE_MASKS                                        0x000028
#define DE_CLIP_TL                                      0x00002C
#define DE_CLIP_BR                                      0x000030
#define DE_COLOR_COMPARE                                0x000020
#define DE_COLOR_COMPARE_MASK                           0x000024
#define DE_MONO_PATTERN_LOW                             0x000034
#define DE_MONO_PATTERN_HIGH                            0x000038
#define DE_WINDOW_SOURCE_BASE                           0x000040
#define DE_WINDOW_DESTINATION_BASE                      0x000044

#define DE_PITCH                                        0x000010
#define DE_PITCH_DESTINATION_LSB                        16
#define DE_PITCH_SOURCE_LSB                             0


#define DE_FOREGROUND                                   0x000014
#define DE_BACKGROUND                                   0x000018

#define DE_STRETCH_FORMAT                               0x00001C
#define DE_STRETCH_FORMAT_PATTERN_XY_LSB                30
#define DE_STRETCH_FORMAT_PATTERN_Y_LSB                 27
#define DE_STRETCH_FORMAT_PATTERN_X_LSB                 23
#define DE_STRETCH_FORMAT_PIXEL_FORMAT_LSB              20
#define DE_STRETCH_FORMAT_ADDRESSING_LSB                16
#define DE_STRETCH_FORMAT_SOURCE_HEIGHT_LSB             0
#define DE_MASKS                                        0x000028
#define DE_CLIP_TL                                      0x00002C
#define DE_CLIP_BR                                      0x000030
#define DE_COLOR_COMPARE                                0x000020
#define DE_COLOR_COMPARE_MASK                           0x000024
#define DE_MONO_PATTERN_LOW                             0x000034
#define DE_MONO_PATTERN_HIGH                            0x000038
#define DE_WINDOW_SOURCE_BASE                           0x000040
#define DE_WINDOW_DESTINATION_BASE                      0x000044



#define DE_WINDOW_WIDTH                                 0x00003C
#define DE_WINDOW_WIDTH_DESTINATION_LSB                     16
#define DE_WINDOW_WIDTH_SOURCE_LSB                          0



/* blt direction */
#define TOP_TO_BOTTOM 0
#define LEFT_TO_RIGHT 0
#define BOTTOM_TO_TOP 1
#define RIGHT_TO_LEFT 1

void hw_set2dformat(struct lynx_accel *accel, int fmt);

void hw_de_init(struct lynx_accel *accel);

int hw_fillrect(struct lynx_accel *accel,
		u32 base, u32 pitch, u32 Bpp,
		u32 x, u32 y, u32 width, u32 height, u32 color, u32 rop);

int hw712_fillrect(struct lynx_accel *accel,
		   u32 base, u32 pitch, u32 Bpp,
		   u32 x, u32 y, u32 width, u32 height,
		   u32 color, u32 rop);

int hw_copyarea(struct lynx_accel *accel, unsigned int sBase,	/* Address of source: offset in frame buffer */
		unsigned int sPitch,	/* Pitch value of source surface in BYTE */
		unsigned int sx, unsigned int sy,	/* Starting coordinate of source surface */
		unsigned int dBase,	/* Address of destination: offset in frame buffer */
		unsigned int dPitch,	/* Pitch value of destination surface in BYTE */
		unsigned int bpp,	/* Color depth of destination surface */
		unsigned int dx, unsigned int dy,	/* Starting coordinate of destination surface */
		unsigned int width, unsigned int height,	/* width and height of rectangle in pixel value */
		unsigned int rop2);

int hw_imageblit(struct lynx_accel *accel, const char *pSrcbuf,	/* pointer to start of source buffer in system memory */
		 unsigned int srcDelta,	/* Pitch value (in bytes) of the source buffer, +ive means top down and -ive mean button up */
		 unsigned int startBit,	/* Mono data can start at any bit in a byte, this value should be 0 to 7 */
		 unsigned int dBase,	/* Address of destination: offset in frame buffer */
		 unsigned int dPitch,	/* Pitch value of destination surface in BYTE */
		 unsigned int bytePerPixel,	/* Color depth of destination surface */
		 unsigned int dx, unsigned int dy,	/* Starting coordinate of destination surface */
		 unsigned int width, unsigned int height,	/* width and height of rectange in pixel value */
		 unsigned int fColor,	/* Foreground color (corresponding to a 1 in the monochrome data */
		 unsigned int bColor,	/* Background color (corresponding to a 0 in the monochrome data */
		 unsigned int rop2);
#endif
