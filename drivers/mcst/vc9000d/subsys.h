/*
 * Copyright (c) 2015, Verisilicon Inc. - All Rights Reserved
 *
 * This software is dual licensed, either GPL-2.0 or BSD-3-Clause, at your
 * option.
 *
 ********************************************************************************
 *
 * GPL-2.0
 *
 ********************************************************************************
 *
 * This program is free software; you can redistribute it and/or modify it under
 * the terms of the GNU General Public License as published by the Free Software
 * Foundation; version 2.
 *
 * This program is distributed in the hope that it will be useful, but WITHOUT
 * ANY WARRANTY; without even the implied warranty of MERCHANTABILITY or FITNESS
 * FOR A PARTICULAR PURPOSE. See the GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License along with
 * this program; if not, write to the Free Software Foundation, Inc., 51 Franklin
 * Street, Fifth Floor, Boston, MA 02110-1301, USA.
 *
 ********************************************************************************
 *
 * Alternatively, This software may be distributed under the terms of
 * BSD-3-Clause, in which case the following provisions apply instead of the ones
 * mentioned above :
 *
 ********************************************************************************
 *
 * Redistribution and use in source and binary forms, with or without
 * modification, are permitted provided that the following conditions are met:
 *
 * 1. Redistributions of source code must retain the above copyright notice, this
 * list of conditions and the following disclaimer.
 *
 * 2. Redistributions in binary form must reproduce the above copyright notice,
 * this list of conditions and the following disclaimer in the documentation
 * and/or other materials provided with the distribution.
 *
 * 3. Neither the name of the copyright holder nor the names of its contributors
 * may be used to endorse or promote products derived from this software without
 * specific prior written permission.
 *
 * THIS SOFTWARE IS PROVIDED BY THE COPYRIGHT HOLDERS AND CONTRIBUTORS "AS IS"
 * AND ANY EXPRESS OR IMPLIED WARRANTIES, INCLUDING, BUT NOT LIMITED TO, THE
 * IMPLIED WARRANTIES OF MERCHANTABILITY AND FITNESS FOR A PARTICULAR PURPOSE ARE
 * DISCLAIMED. IN NO EVENT SHALL THE COPYRIGHT HOLDER OR CONTRIBUTORS BE LIABLE
 * FOR ANY DIRECT, INDIRECT, INCIDENTAL, SPECIAL, EXEMPLARY, OR CONSEQUENTIAL
 * DAMAGES (INCLUDING, BUT NOT LIMITED TO, PROCUREMENT OF SUBSTITUTE GOODS OR
 * SERVICES; LOSS OF USE, DATA, OR PROFITS; OR BUSINESS INTERRUPTION) HOWEVER
 * CAUSED AND ON ANY THEORY OF LIABILITY, WHETHER IN CONTRACT, STRICT LIABILITY,
 * OR TORT (INCLUDING NEGLIGENCE OR OTHERWISE) ARISING IN ANY WAY OUT OF THE USE
 * OF THIS SOFTWARE, EVEN IF ADVISED OF THE POSSIBILITY OF SUCH DAMAGE.
 *
 */

#ifndef _SUBSYS_H_
#define _SUBSYS_H_

#include <linux/fs.h>
#include "hantrodec.h"

#ifndef NULL
#ifdef __cplusplus
#define NULL 0
#else
#define NULL ((void *)0)
#endif
#endif

/* Functions provided by all other subsystem IP - hantrodec_xxx.c */

/***********************************************/
/* subsys level */
/***********************************************/

#ifdef EMU
  #define VCMD_BUF_POOL_OFFSET      0x5000000

  #define PCI_VENDOR_ID_HANTRO      0x1d9b//0x16c3//0x1ae0
  #define PCI_DEVICE_ID_HANTRO      0xface//0x7011//0x001a

  /* Base address got control register */
  #define PCI_CONTROL_BAR              2

  /* Base address DDR register */
  #define PCI_DDR_BAR             4

#else //EMU

  #define VCMD_BUF_POOL_OFFSET      0x1000000

#if defined(CONFIG_MCST)
  #define PCI_VENDOR_ID_HANTRO      PCI_VENDOR_ID_MCST_TMP
  #define PCI_DEVICE_ID_HANTRO      PCI_DEVICE_ID_MCST_VC9000D

  /* Base address got control register */
  #define PCI_CONTROL_BAR           0

 /* Base address DDR register */
  #undef PCI_DDR_BAR
#else

#ifdef PLATFORM_GEN7
  #define PCI_VENDOR_ID_HANTRO      0x10ee//0x16c3
  #define PCI_DEVICE_ID_HANTRO      0x9014// 0x7011

  /* Base address got control register */
  #define PCI_CONTROL_BAR              2

  /* Base address DDR register */
  #define PCI_DDR_BAR             0
#else //PLATFORM_GEN7
  #define PCI_VENDOR_ID_HANTRO      0x10ee//0x16c3
  #define PCI_DEVICE_ID_HANTRO      0x8014// 0x7011

  /* Base address got control register */
  #define PCI_CONTROL_BAR              4

  /* Base address DDR register */
  #define PCI_DDR_BAR             0
#endif //PLATFORM_GEN7
#endif
#endif //EMU

#define MAX_SUBSYS_NUM 4 /* up to 4 subsystem (temporary) */
#define HXDEC_MAX_CORES MAX_SUBSYS_NUM /* used in hantro_dec_xxx.c */

#define PPU_REG_RANGE 128
#define PP0_START_REG 384
#define MAX_PPU_COUNT 2
#define DEC_MAX_PPU_COUNT MAX_PPU_COUNT
#define MAX_REG_COUNT (PP0_START_REG + PPU_REG_RANGE * DEC_MAX_PPU_COUNT)

enum SubsysType {
	ENCODER_TYPE = 0,
	CUTREE_TYPE,
	DECODER_TYPE,
	JPEG_ENCODER_TYPE,
	MAX_TYPE
};

/* SubsysDesc & CoreDesc are used for configuration */
struct SubsysDesc {
	int slice_index; /* slice this subsys belongs to */
	int index; /* subsystem index */
	long base;
};

struct CoreDesc {
	int slice;
	int subsys; /* subsys this core belongs to */
	enum CoreType core_type;
	int offset; /* offset to subsystem base */
	int iosize;
	int irq;
	int has_apb;
};

/* internal config struct (translated from SubsysDesc & CoreDesc) */
struct subsys_config {
	unsigned long base_addr;
	int irq;
	/* identifier for each subsys vc8000e=0,
	 * IM=1,vcd=2,jpege=3,jpegd=4
	 */
	u32 subsys_type;
	u32 submodule_offset[HW_CORE_MAX]; /* in bytes */
	u16 submodule_iosize[HW_CORE_MAX]; /* in bytes */

	void __iomem *submodule_hwregs[HW_CORE_MAX]; /* virtual address */
	int has_apbfilter[HW_CORE_MAX];
};

enum subsys_module_id {
	SUB_MOD_VCMD = 0,
	SUB_MOD_MAIN,
	SUB_MOD_MMU,
	SUB_MOD_MMU_WR,
	SUB_MOD_DEC400,
	SUB_MOD_AXIFE,
	SUB_MOD_UFBC,
	SUB_MOD_AXI2TO1,

	SUB_MOD_MAX
};

void CheckSubsysCoreArray(struct subsys_config *subsys, int *subsys_num, int *vcmd);

extern unsigned long ddr_offset;
extern char *dec_dev_n;

int hantrovcmd_open(struct inode *inode, struct file *filp);
int hantrovcmd_release(struct inode *inode, struct file *filp);
long hantrovcmd_ioctl(struct file *filp,
				  unsigned int cmd, unsigned long arg);
void *hantrovcmd_init(struct subsys_config *subsys, int subsys_num, void *platformdev);
void hantrovcmd_cleanup(void *_vcmd_mgr);
void vcmd_request_arbiter(void *_vcmd_mgr, u32 subsys_id);
void vcmd_release_arbiter(void *_vcmd_mgr, u32 subsys_id);
int vcmd_pm_suspend(void *_vcmd_mgr);
int vcmd_pm_resume(void *_vcmd_mgr);
u32 *get_submodule_regs_va(void *_vcmd_mgr, u32 subsys_id, u32 sub_mod_id);
int in_vcmd_memory_region(void *_vcmd_mgr, unsigned long start, unsigned long end);
#ifdef SUPPORT_48PA_MMU
int _vcmd_memory_map(void *_vcmd_mgr, struct file *filp);
#endif

/******************************************************************************/
/* MMU */
/******************************************************************************/
#ifdef SUPPORT_MMU
/* Init MMU, should be called in driver init function. */
enum MMUStatus MMUInit(volatile unsigned char *hwregs);
/* Clean up all data in MMU, should be called in driver cleanup function
 * when rmmod driver
 */
enum MMUStatus MMUCleanup(void *_platformdev);
/* The function should be called in driver realease function
 * when driver exit unnormally
 */
enum MMUStatus MMURelease(void *filp);

enum MMUStatus MMUSetup(volatile unsigned char *hwregs[MAX_SUBSYS_NUM][2]);
enum MMUStatus MMUEnable(volatile unsigned char *hwregs[MAX_SUBSYS_NUM][2], void *_platformdev);

/* Used in kernel to map buffer */
enum MMUStatus MMUKernelMemNodeMap(struct kernel_addr_desc *addr, struct file *flip);
/* Used in kernel to unmap buffer */
enum MMUStatus MMUKernelMemNodeUnmap(struct kernel_addr_desc *addr);
/* create page table for multi-process */
enum MMUStatus MMUCreatePageTable(struct file *filp);

long MMUIoctl(unsigned int cmd, void *filp, unsigned long arg,
	      volatile unsigned char *hwregs[MAX_SUBSYS_NUM][2]);

unsigned long long GetMMUAddress(void);
unsigned int GetMMUPageTableArraySize(void);
#endif
/******************************************************************************/
/* DEC400 */
/******************************************************************************/

/******************************************************************************/
/* AXI FE */
/******************************************************************************/

#endif
