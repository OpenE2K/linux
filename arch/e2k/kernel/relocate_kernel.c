/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */

#include <linux/kexec.h>
#include <asm/page.h>
#include <asm-l/bootinfo.h>

#define __relocate__	__attribute__((__section__(".kexec_relocate_kernel")))

#define r64(_a)	({						\
		void *_v = (void *)NATIVE_READ_MAS_D(_a, MAS_DISABLED_TRANSLATION); \
		_v; })
#define w64(_v, _a)	NATIVE_WRITE_MAS_D(_a, _v, MAS_DISABLED_TRANSLATION)

static notrace inline void __relocate__ pagecpy(u64 *from, u64 *to)
{
	for (int i = 0; i < PAGE_SIZE / sizeof(*to); i++, to++, from++)
		w64(r64(from), to);
}

static inline void notrace __relocate__ jump_lintel(struct kimage *img)
{
	E2K_MOVE_DREG_TO_DGREG(1, img->arch.bootblock_pa);
	((void (*)(void))img->start)();
}

static inline void notrace  __relocate__ jump_kernel(struct kimage *img)
{
	void (*entry_func)(void) = (void *)(img->start);

	e2k_cud_t	cud;
	e2k_gd_t	gd;
	u64		base, size;
	boot_info_t *bootinfo = (void *)(img->arch.bootblock_pa);
	base = bootinfo->kernel_base;
	size = bootinfo->kernel_size;

	cud = new_cud(base, size, 0, cud_m64);
	write_CUD_reg(cud);
	write_OSCUD_reg(cud);

	gd = new_gd(base, size);
	write_GD_reg(gd);
	write_OSGD_reg(gd);

	E2K_JUMP_ABSOLUTE_WITH_ARGUMENTS_2(entry_func, 0, bootinfo);
}

__interrupt
void notrace __relocate__ relocate_kernel(struct kimage *img)
{
	unsigned long addr = img->head & PAGE_MASK;
	unsigned long ind_bit = img->head & IND_FLAGS;
	unsigned long ptr = 0, entry;
	unsigned long dest = 0;

	bool loop = true;
	while (loop) {
		switch (ind_bit) {
		case IND_INDIRECTION:
			ptr = addr;
			break;
		case IND_SOURCE:
			pagecpy((u64 *)addr, (u64 *)dest);
			dest += PAGE_SIZE;
			break;
		case IND_DESTINATION:
			dest = addr;
			break;
		case IND_DONE:
			loop = false;
			break;
		}

		if (loop) {
			entry = *(unsigned long *)ptr;
			ptr += 8;
			addr = entry & PAGE_MASK;
			ind_bit = entry & IND_FLAGS;
		}
	}

	flush_TLB_all();
	flush_ICACHE_all();

	if (img->arch.kexec_lintel)
		jump_lintel(img);
	else
		jump_kernel(img);
}