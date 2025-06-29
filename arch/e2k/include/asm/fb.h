/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_E2K_FB_H
#define _ASM_E2K_FB_H

#include <linux/fb.h>
#include <linux/fs.h>
#include <linux/pgtable.h>

#include <asm/mman.h>

#define VGA_FB_PHYS 0xA0000
#define VGA_FB_PHYS_LEN 65536

static inline void fb_pgprotect(struct file *file, struct vm_area_struct *vma,
				unsigned long off)
{
	bool wc = cpu_has(CPU_FEAT_WC_LEGACY_VGA) ||
		!(off >= VGA_FB_PHYS && off < (VGA_FB_PHYS + VGA_FB_PHYS_LEN));

	vma->vm_page_prot = wc ? pgprot_writecombine(vma->vm_page_prot)
				: pgprot_noncached(vma->vm_page_prot);
}

extern int fb_is_primary_device(struct fb_info *info);
#endif /* _ASM_E2K_FB_H */
