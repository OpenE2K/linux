/* SPDX-License-Identifier: GPL-2.0 */
/*
 *    Hantro mmu driver header file.
 *
 *    Copyright (c) 2017, VeriSilicon Inc.
 *
 *    This program is free software; you can redistribute it and/or modify
 *    it under the terms of the GNU General Public License, version 2, as
 *    published by the Free Software Foundation.
 *
 *    This program is distributed in the hope that it will be useful,
 *    but WITHOUT ANY WARRANTY; without even the implied warranty of
 *    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *    GNU General Public License version 2 for more details.
 *
 *    You may obtain a copy of the GNU General Public License
 *    Version 2 at the following locations:
 *    https://opensource.org/licenses/gpl-2.0.php
 */

#ifndef _HANTROMMU_H_
#define _HANTROMMU_H_

#include "hantro_priv.h"

#define REGION_IN_START 0x0
#define REGION_IN_END 0x40000000u
#define REGION_OUT_START 0x40000000u
#define REGION_OUT_END 0x80000000u
#define REGION_PRIVATE_START 0x80000000u
#define REGION_PRIVATE_END 0xc0000000u

#define REGION_IN_MMU_START 0x1000u
#define REGION_IN_MMU_END 0x40002000u
#define REGION_OUT_MMU_START 0x40002000u
#define REGION_OUT_MMU_END 0x80001000u
#define REGION_PRIVATE_MMU_START 0x80001000u
#define REGION_PRIVATE_MMU_END 0xc0000000u

enum MMUStatus {
	MMU_STATUS_OK = 0,

	MMU_STATUS_FALSE = -1,
	MMU_STATUS_INVALID_ARGUMENT = -2,
	MMU_STATUS_INVALID_OBJECT = -3,
	MMU_STATUS_OUT_OF_MEMORY = -4,
	MMU_STATUS_NOT_FOUND = -19,
};
enum MMUProbeStage {
	PGTBL_RESOURCE = 0,
	HWREG_RESOURCE = 1,
	ALL_RESOURCE = 2, /* probe page table and reserve hw reg both */
};
struct addr_desc {
	void *virtual_address; /* buffer virtual address */
	unsigned long bus_address; /* buffer physical address */
	unsigned long mmu_bus_address;
	unsigned long size; /* physical size */
	unsigned int id; /*SLICE, TYPE*/
};

/* Init MMU, should be called in driver init function. */
int hantroMMUprobe(dtbnode *pnode, enum MMUProbeStage loop, struct mmu_t *pmmu,
		   struct platform_device *pdev, unsigned long ddr_base, struct mmu_core_cfg *cfg);

/* Clean up all data in MMU */
void hantroMMUCleanup(void);
/* The function should be called in driver realease function */
void hantroMMURelease(void *filp);
/* Memmap the address to hantro mmu */
void hantro_mmu_map(struct addr_desc *addr, int valid_bus_addr);
long hantroMMUIoctl(unsigned int cmd, void *filp, unsigned long arg);

#endif //#ifndef _HANTROMMU_H_
