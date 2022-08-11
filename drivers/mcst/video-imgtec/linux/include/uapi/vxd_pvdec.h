/*!
 *****************************************************************************
 *
 * @File       vxd_pvdec.h
 * @Description    This is a configurable header file which sets up the memory
 *  spaces for a fixed device.
 * ---------------------------------------------------------------------------
 *
 * Copyright (c) Imagination Technologies Ltd.
 *
 * The contents of this file are subject to the MIT license as set out below.
 *
 * Permission is hereby granted, free of charge, to any person obtaining a
 * copy of this software and associated documentation files (the "Software"),
 * to deal in the Software without restriction, including without limitation
 * the rights to use, copy, modify, merge, publish, distribute, sublicense,
 * and/or sell copies of the Software, and to permit persons to whom the
 * Software is furnished to do so, subject to the following conditions:
 *
 * The above copyright notice and this permission notice shall be included in
 * all copies or substantial portions of the Software.
 *
 * THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 * IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 * FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 * AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 * LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 * OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN
 * THE SOFTWARE.
 *
 * Alternatively, the contents of this file may be used under the terms of the
 * GNU General Public License Version 2 ("GPL")in which case the provisions of
 * GPL are applicable instead of those above.
 *
 * If you wish to allow use of your version of this file only under the terms
 * of GPL, and not to allow others to use your version of this file under the
 * terms of the MIT license, indicate your decision by deleting the provisions
 * above and replace them with the notice and other provisions required by GPL
 * as set out in the file called "GPLHEADER" included in this distribution. If
 * you do not delete the provisions above, a recipient may use your version of
 * this file under the terms of either the MIT license or GPL.
 *
 * This License is also included in this distribution in the file called
 * "MIT_COPYING".
 *
 *****************************************************************************/


#ifndef VXD_PVDEC_H
#define VXD_PVDEC_H

#define PVDEC_COMMS_RAM_OFFSET      0x00002000
#define PVDEC_COMMS_RAM_SIZE        0x00001000
#define PVDEC_ENTROPY_OFFSET        0x00003000
#define PVDEC_ENTROPY_SIZE          0x1FF
#define PVDEC_VEC_BE_OFFSET         0x00005000
#define PVDEC_VEC_BE_SIZE           0x3FF
#define PVDEC_VEC_BE_CODEC_OFFSET   0x00005400
#define MSVDX_VEC_OFFSET            0x00006000
#define MSVDX_VEC_SIZE              0x7FF
#define MSVDX_CMD_OFFSET            0x00007000

/* Defines virtual memory area separation space size.
 * It's used to avoid memory overwriting in case of neighbouring areas. */
#define PVDEC_GUARD_BAND            0x00001000ul

/* Virtual memory address ranges for hardware
 * related buffers allocated in the kernel driver.
 */
#define PVDEC_BUF_FW_START          0x00042000ul
#define PVDEC_BUF_RENDEC_START      0x00400000ul
#define PVDEC_BUF_RENDEC_SIZE       (0x02000000ul - PVDEC_GUARD_BAND)
#define PVDEC_BUF_END  (PVDEC_BUF_RENDEC_START + \
                        PVDEC_BUF_RENDEC_SIZE + \
                        PVDEC_GUARD_BAND)

/* Use of tiled heaps. */
/* Define to 1 if 512-byte stride tiled heap is to be used.
 * Otherwise define to 0.
 */
#define PVDEC_USE_HEAP_TILE512  0

/* Virtual memory heap address ranges for tiled
 * and non-tiled buffers. Addresses within each
 * range should be assigned to the appropriate
 * buffers by the UM driver and mapped into the
 * device using the corresponding KM driver ioctl.
 */
#define PVDEC_HEAP_UNTILED_START    (PVDEC_BUF_END)
#define PVDEC_HEAP_UNTILED_SIZE     (0x3DC00000ul)
#define PVDEC_HEAP_TILE512_START    (PVDEC_HEAP_UNTILED_START + \
                                     PVDEC_HEAP_UNTILED_SIZE)
#define PVDEC_HEAP_TILE512_SIZE     (0x10000000ul * PVDEC_USE_HEAP_TILE512)
#define PVDEC_HEAP_TILE1024_START   (PVDEC_HEAP_TILE512_START + \
                                     PVDEC_HEAP_TILE512_SIZE)
#define PVDEC_HEAP_TILE1024_SIZE    (0x20000000ul)
#define PVDEC_HEAP_TILE2048_START   (PVDEC_HEAP_TILE1024_START + \
                                     PVDEC_HEAP_TILE1024_SIZE)
#define PVDEC_HEAP_TILE2048_SIZE    (0x30000000ul)
#define PVDEC_HEAP_TILE4096_START   (PVDEC_HEAP_TILE2048_START + \
                                     PVDEC_HEAP_TILE2048_SIZE)
#define PVDEC_HEAP_TILE4096_SIZE    (0x40000000ul)
#define PVDEC_HEAP_BITSTREAM_START  (PVDEC_HEAP_TILE4096_START + \
                                     PVDEC_HEAP_TILE4096_SIZE)
#define PVDEC_HEAP_BITSTREAM_SIZE   (0x02000000ul)
#define PVDEC_HEAP_STREAM_START     (PVDEC_HEAP_BITSTREAM_START + \
                                     PVDEC_HEAP_BITSTREAM_SIZE)
#define PVDEC_HEAP_STREAM_SIZE      (0x100000000 - PVDEC_HEAP_STREAM_START)
#if ((PVDEC_HEAP_STREAM_START) >= 0x100000000)
    #error "PVDEC MMU heap definitions exceed 4GB!"
#endif

#endif /* VXD_PVDEC_H */
