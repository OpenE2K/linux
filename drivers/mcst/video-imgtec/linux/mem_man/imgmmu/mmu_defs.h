/*!
 *****************************************************************************
 *
 * @File       mmu_defs.h
 * @Description    Internal MMU library header used to define MMU information at compilation time and have access to the error printing functions
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

#ifndef MMU_DEFS_H
#define MMU_DEFS_H

#include <stdarg.h>

#ifdef __cplusplus
extern "C" {
#endif

/**
 * @addtogroup IMGMMU_lib
 * @{
 */
/*-------------------------------------------------------------------------
 * Following elements are in the IMGMMU_int documentation module
 *------------------------------------------------------------------------*/

#ifndef IMGMMU_PHYS_SIZE
/** @brief MMU physical address size in bits */
#define IMGMMU_PHYS_SIZE 40
#endif

#ifndef IMGMMU_VIRT_SIZE
/** @brief MMU virtual address size in bits */
#define IMGMMU_VIRT_SIZE 32
#endif

#ifndef IMGMMU_PAGE_SIZE

/** @brief Page size in bytes */
#define IMGMMU_PAGE_SIZE 4096u
/** should be log2(IMGMMU_PAGE_SIZE) */
#define IMGMMU_PAGE_SHIFT 12
/** should be log2(IMGMMU_PAGE_SIZE)*2-2 */
#define IMGMMU_DIR_SHIFT 22

#endif

static const IMG_SIZE MMU_PAGE_SIZE = IMGMMU_PAGE_SIZE;
static const unsigned int MMU_PAGE_SHIFT = IMGMMU_PAGE_SHIFT;
static const unsigned int MMU_DIR_SHIFT = IMGMMU_DIR_SHIFT;

/** @brief Page offset mask in virtual address - bottom bits */
static const IMG_SIZE VIRT_PAGE_OFF_MASK = ((1<<IMGMMU_PAGE_SHIFT)-1);

/** @brief Page table index mask in virtual address - middle bits */
static const IMG_SIZE VIRT_PAGE_TBL_MASK
	= (((1<<IMGMMU_DIR_SHIFT)-1) & ~(((1<<IMGMMU_PAGE_SHIFT)-1)));

/** @brief Directory index mask in virtual address - high bits */
static const IMG_SIZE VIRT_DIR_IDX_MASK = (~((1<<IMGMMU_DIR_SHIFT)-1));

#if IMGMMU_VIRT_SIZE == 32
/** @brief maximum number of pagetable that can be stored in the directory entry */
#define IMGMMU_N_TABLE (IMGMMU_PAGE_SIZE/4u)
/** @brief maximum number of page mapping in the pagetable */
#define IMGMMU_N_PAGE (IMGMMU_PAGE_SIZE/4u)
#else
/* it is unlikely to change anyway */
#error "need an update for the new virtual address size"
#endif

/** @brief Memory flag used to mark a page mapping as invalid */
#define MMU_FLAG_VALID 0x1
#define MMU_FLAG_INVALID 0x0

/*
 * internal printing functions
 */
__printf(4, 5)
void _MMU_Log(int err, const char *function, IMG_UINT32 line, const char *format, ...);

#define MMU_LogError(...) _MMU_Log(1, __FUNCTION__, __LINE__, __VA_ARGS__)

#define MMU_LogDebug(...)
/*#define MMU_LogDebug(...) _MMU_Log(0, __FUNCTION__, __LINE__, __VA_ARGS__)*/

/**
 * @}
 */
/*-------------------------------------------------------------------------
 * End of the IMGMMU_int documentation module
 *------------------------------------------------------------------------*/

#ifdef __cplusplus
}
#endif

#endif /* MMU_DEFS_H */
