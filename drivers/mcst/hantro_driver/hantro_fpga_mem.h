/* SPDX-License-Identifier: GPL-2.0 */
/*
 * header file for pcie hantro fpga.
 *
 * Copyright (c) 2020, VeriSilicon Inc.
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License, version 2, as
 * published by the Free Software Foundation.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License version 2 for more details.
 *
 * You may obtain a copy of the GNU General Public License
 * Version 2 at the following locations:
 * https://opensource.org/licenses/gpl-2.0.php
 */

#ifndef __HANTRO_FPGA_MEM__
#define __HANTRO_FPGA_MEM__

#include "hantro_priv.h"

/* Total DDR memory size */
#define DDR_SIZE    800
/* hantro linear memory chunk */
struct hlinc {
	unsigned long bus_address;
	u16 chunks_reserved;
	//const struct file *filp; /* Client that allocated this chunk */
	u16 filp; /* as a flag only */
};

struct hantro_fpga_t {
	/* PCI base register address of HW cores (Hardware address) */
	unsigned long reg_base;
	u32 reg_len; /* core registers address Length */

	/* PCI base register address of on board DDR (Hardware address) */
	unsigned long ddr_base;
	u32 ddr_len; /* on board DDR address Length */

	unsigned int alloc_size;
	unsigned long alloc_base;
	/* user space SW will subtract HLINA_TRANSL_OFFSET from the bus address
	 * and decoder HW will use the result as the address translated base
	 * address. The SW needs the original host memory bus address for memory
	 * mapping to virtual address.
	 */
	unsigned long addr_transl;

	/* memory part */
	spinlock_t mem_lock;
	struct hlinc *hlina_chunks;
	size_t chunks;
};

/* API */

#define hantro_fpga_memalloc hantro_dev_memalloc
#define hantro_fpga_memfree hantro_dev_memfree

int hantro_fpga_memalloc(struct hantro_mem_handle *phandle, unsigned int size);
int hantro_fpga_memfree(struct hantro_mem_handle *phandle);
int hantro_fpga_meminit(unsigned long ddr_base);
int hantro_fpga_memrelease(void);
void FreeHantroFpgaMem(struct drm_gem_hantro_object *cma_obj);
int AllocHantroFpgaMem(struct drm_gem_hantro_object *cma_obj, struct drm_mode_create_dumb *args);
#endif /* __HANTRO_FPGA_MEM__ */
