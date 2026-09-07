/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */

#ifndef E2K_KEXEC_H
#define E2K_KEXEC_H

#include <asm/page.h>
#include <linux/clockchips.h>

/* Maximum physical address we can use pages from */

#define KEXEC_SOURCE_MEMORY_LIMIT (-1UL)

/* Maximum address we can reach in physical address mode */

#define KEXEC_DESTINATION_MEMORY_LIMIT (-1UL)

/* Maximum address we can use for the control code buffer */

#define KEXEC_CONTROL_MEMORY_LIMIT (-1UL)

#define KEXEC_CONTROL_PAGE_SIZE HPAGE_SIZE

#define KEXEC_ARCH KEXEC_ARCH_E2K

#define ARCH_HAS_KIMAGE_ARCH

#define KEXEC_LINTEL_IMAGE 0x00001000

#define BOOTBLOCK_OFFSET 0x100

#define KERNEL_SEGMENT_ID 0
#define BOOTBLOCK_SEGMENT_ID 1
#define STACKS_SEGMENT_RID (-1)
#define CRASH_STACKS_SEGMENT_RID (-2)

#define	SCC_WR9_RESET_BASE	(1 << 7)
#define	SCC_WR4_PARITY_NONE	(0 << 0)
#define SCC_WR4_STOP_BITS_1	(1 << 2)
#define	SCC_WR4_CLOCK_MODE_X16	(1 << 6)
#define	SCC_WR7_XN_MODE_ENABLE	(1 << 7)
#define	SCC_WR10_ENCODING_NRZ	(0 << 0)
#define	SCC_WR11_TXCLK_BRG	(2 << 3)
#define	SCC_WR11_RXCLK_BRG	(2 << 5)
#define	SCC_WR14_BRG_ENABLE	(1 << 0)
#define	SCC_WR14_BRG_SOURCE	(1 << 1)
#define	SCC_WR3_RX_DATA		(3 << 6)
#define	SCC_WR3_RX_ENABLE	(1 << 0)
#define	SCC_WR5_TX_DATA		(3 << 5)
#define	SCC_WR5_TX_ENABLE	(1 << 3)

struct kimage_arch {
	void __user *bootblock_va;
	phys_addr_t bootblock_pa;
	bool kexec_lintel;
	unsigned long stacks_pa, stacks_size, blocksz;
};

static inline void crash_setup_regs(struct pt_regs *newregs,
					struct pt_regs *oldregs) { }

extern void clockevents_shutdown(struct clock_event_device *dev);

extern const unsigned char __start_kexec_relocate_kernel[];
extern const unsigned char __end_kexec_relocate_kernel[];

extern	bootblock_struct_t *bootblock_virt;

extern struct resource crashk_res;
extern struct resource crashk_low_res;

struct kimage;

extern void relocate_kernel(struct kimage *img);

void kexec_scc_init(u64 base);

#endif /* E2K_KEXEC_H */
