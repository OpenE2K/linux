// SPDX-License-Identifier: GPL-2.0
/*
 * Hantro driver on pcie fpga.
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

#include <asm/io.h>
#include <linux/uaccess.h>
#include <linux/errno.h>
#include <linux/fs.h>
#include <linux/init.h>
#include <linux/ioport.h>
#include <linux/kernel.h>
#include <linux/list.h>
#include <linux/mm.h>
#include <linux/module.h>
#include <linux/sched.h>
#include <linux/slab.h>
#include <linux/vmalloc.h>
#include "hantro_fpga_mem.h"

#ifndef HLINA_START_ADDRESS
#define HLINA_START_ADDRESS 0x02000000
#endif

#ifndef HLINA_SIZE
#define HLINA_SIZE 96
#endif

#ifndef HLINA_TRANSL_OFFSET
#define HLINA_TRANSL_OFFSET 0x0
#endif

#ifdef HAS_MMU
extern unsigned long get_total_mmu_pgtbl_buf_size(u32 slice_cnt);
#endif

#ifdef HAS_VCMD
extern unsigned long get_total_vcmd_pool_size(void);
#endif

static unsigned long get_hantro_fpgamem_offset(void);

/* the size of chunk in MEMALLOC_DYNAMIC */
#define CHUNK_SIZE (PAGE_SIZE * 4)

struct hantro_fpga_t g_fpga = {
	.alloc_size = HLINA_SIZE,
	.alloc_base = HLINA_START_ADDRESS,
	.addr_transl = 0,
};

int hantro_fpga_memrelease(void)
{
	struct hantro_fpga_t *fpga = &g_fpga;
	int i = 0;

	for (i = 0; i < fpga->chunks; i++) {
		spin_lock(&fpga->mem_lock);
		if (fpga->hlina_chunks[i].filp != 0) {
			pr_warn("memalloc: Found unfreed memory at release time!\n");

			fpga->hlina_chunks[i].filp = 0;
			fpga->hlina_chunks[i].chunks_reserved = 0;
		}
		spin_unlock(&fpga->mem_lock);
	}
	vfree(fpga->hlina_chunks);
	pr_info("dev closed\n");
	return 0;
}

/* Cycle through the buffers we have, give the first free one */
int hantro_fpga_memalloc(struct hantro_mem_handle *phandle, unsigned int size)
{
	struct hantro_fpga_t *fpga = &g_fpga;
	int i = 0;
	int j = 0;
	unsigned int skip_chunks = 0;
	unsigned long busaddr;

	/* calculate how many chunks we need; round up to chunk boundary */
	unsigned int alloc_chunks = (size + CHUNK_SIZE - 1) / CHUNK_SIZE;

	busaddr = 0;

	/* run through the chunk table */
	for (i = 0; i < fpga->chunks;) {
		skip_chunks = 0;
		/* if this chunk is available */
		if (!fpga->hlina_chunks[i].chunks_reserved) {
			/* check that there is enough memory left */
			if (i + alloc_chunks > fpga->chunks)
				break;

			/* check that there is enough consecutive chunks */
			for (j = i; j < i + alloc_chunks; j++) {
				if (fpga->hlina_chunks[j].chunks_reserved) {
					skip_chunks = 1;
					/* skip the used chunks */
					i = j + fpga->hlina_chunks[j]
							.chunks_reserved;
					break;
				}
			}

			/* if enough free memory found */
			if (!skip_chunks) {
				busaddr = fpga->hlina_chunks[i].bus_address;
				fpga->hlina_chunks[i].filp = 0x55aa;
				fpga->hlina_chunks[i].chunks_reserved =
					alloc_chunks;
				break;
			}
		} else {
			/* skip the used chunks */
			i += fpga->hlina_chunks[i].chunks_reserved;
		}
	}

	if (busaddr == 0) {
		pr_info("memalloc: Allocation FAILED: size = %d\n", size);
		return -EFAULT;
	}

	pr_info("MEMALLOC OK: size: %d, reserved: %ld\n", size,
		alloc_chunks * CHUNK_SIZE);

	phandle->sliceidx = 0; /* no slice in fpga now */
	phandle->size = alloc_chunks * (CHUNK_SIZE);
	phandle->paddr = busaddr;
	phandle->mem_base = fpga->ddr_base;

	/* FIXME: */
	//phandle->vaddr = phys_to_virt(busaddr);
	phandle->vaddr = ioremap(busaddr, alloc_chunks * CHUNK_SIZE);
	return 0;
}

/**
 * Free a buffer based on bus address
 */
int hantro_fpga_memfree(struct hantro_mem_handle *phandle)
{
	struct hantro_fpga_t *fpga = &g_fpga;
	int i = 0;

	for (i = 0; i < fpga->chunks; i++) {
		/* user space SW has stored the translated bus address, add
		 * addr_transl to translate back to our address space.
		 */
		if (fpga->hlina_chunks[i].bus_address == phandle->paddr) {
			fpga->hlina_chunks[i].filp = 0;
			fpga->hlina_chunks[i].chunks_reserved = 0;
			break;
		}
	}
	if (i == fpga->chunks) {
		pr_warn("memalloc: Owner mismatch while freeing memory!\n");
		return -1;
	}

	if (phandle->vaddr)
		iounmap(phandle->vaddr);

	return 0;
}

/**
 * Reset "used" status
 */
static int hantro_fpga_memreset(void)
{
	struct hantro_fpga_t *fpga = &g_fpga;
	int i = 0;
	int result;
	unsigned long ba = fpga->alloc_base;

	pr_info("memalloc: Linear Memory Allocator\n");
	pr_info("memalloc: Linear memory base = %p\n",
		(void *)fpga->alloc_base);

	fpga->chunks = (fpga->alloc_size * 1024 * 1024) / CHUNK_SIZE;
	pr_info("memalloc: Total size %d MB; %d chunks of size %lu\n",
		fpga->alloc_size, (int)fpga->chunks, CHUNK_SIZE);

	fpga->hlina_chunks = vmalloc(fpga->chunks * sizeof(struct hlinc));
	//if (!fpga->hlina_chunks) {
	//	pr_err("memalloc: cannot allocate hlina_chunks\n");
	//	result = -ENOMEM;
	//	goto err;
	//}

	for (i = 0; i < fpga->chunks; i++) {
		fpga->hlina_chunks[i].bus_address = ba;
		fpga->hlina_chunks[i].filp = 0;
		fpga->hlina_chunks[i].chunks_reserved = 0;
		ba += CHUNK_SIZE;
	}
	return 0;

	if (fpga->hlina_chunks)
		vfree(fpga->hlina_chunks);

	return result;
}

/**
 * init hantro fpga pcie board
 *
 * \return -1 fail;
 * \return  0 success;
 */
int hantro_fpga_meminit(unsigned long ddr_base)
{
	struct hantro_fpga_t *fpga = &g_fpga;
	int ret;
	unsigned long offset;

	offset = get_hantro_fpgamem_offset();
	fpga->ddr_base = ddr_base;
	fpga->alloc_base = fpga->ddr_base + offset;
	fpga->alloc_size = DDR_SIZE - offset / (0x100000);
	fpga->addr_transl = fpga->ddr_base;

	ret = hantro_fpga_memreset();
	if (ret != 0)
		goto out;

	return 0;

out:
	return -1;
}

//Reserve memory region for MMU and VCMD buffer pool
static unsigned long get_hantro_fpgamem_offset(void)
{
	unsigned long offset1 = 0, offset2 = 0;
	// make sure no 0x0 bus address, otherwise HW can't make sure valid address
#ifdef HAS_MMU
	offset1 = get_total_mmu_pgtbl_buf_size(1);
#endif

#ifdef HAS_VCMD
	offset2 = get_total_vcmd_pool_size();
#endif
	if ((offset1 + offset2) == 0)
		return 0x100000;
	return offset1 + offset2;
}

void FreeHantroFpgaMem(struct drm_gem_hantro_object *cma_obj)
{
	struct hantro_mem_handle fpga_phandle;

	fpga_phandle.vaddr = cma_obj->vaddr;
	fpga_phandle.paddr = cma_obj->paddr;
	hantro_fpga_memfree(&fpga_phandle);
}

int AllocHantroFpgaMem(struct drm_gem_hantro_object *cma_obj, struct drm_mode_create_dumb *args)
{
	struct hantro_mem_handle fpga_phandle;
	int ret;

	ret = hantro_fpga_memalloc(&fpga_phandle, args->size);
	if (ret != 0) {
		pr_err("hantro_fpga_memalloc ret error\n");
		return ret;
	}
	cma_obj->vaddr = fpga_phandle.vaddr;
	cma_obj->paddr = fpga_phandle.paddr;
	cma_obj->mem_base = fpga_phandle.mem_base;
	return 0;
}
