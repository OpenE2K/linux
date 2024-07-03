/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <asm/p2v/boot_v2p.h>

#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/pci.h>
#include <linux/export.h>
#include <linux/pgtable.h>

#include <asm/mman.h>
#include <asm/io.h>
#include <asm/p2v/io.h>
#include <asm/vga.h>
#include <asm/kvm/guest/io.h>
#include <asm/kvm/hypercall.h>
#include <asm/console.h>

#undef	DEBUG_BOOT_KVM_IO_MODE
#undef	DebugBKVMIO
#define	DEBUG_BOOT_KVM_IO_MODE	0	/* boot-time kernel virt machine */
					/* IO debugging */
#define	DebugBKVMIO(fmt, args...)					\
({									\
	if (DEBUG_BOOT_KVM_IO_MODE)					\
		do_boot_printk("%s(): " fmt, __func__, ##args);		\
})

static unsigned long
boot_kvm_guest_mmio(void __iomem *mmio_addr, u64 value, u8 size,
			u8 is_write)
{
	u64 phys_addr = (u64)mmio_addr;
	unsigned long data[1];
	int ret;

	if (is_write) {
		data[0] = value;
		DebugBKVMIO("data to write 0x%lx size %d to addr 0x%lx\n",
			data[0], size, phys_addr);
	}
	ret = HYPERVISOR_guest_mmio_request(phys_addr, data, size, is_write);
	if (!is_write) {
		DebugBKVMIO("read data 0x%lx size %d from addr 0x%lx\n",
			data[0], size, phys_addr);
	}
	return data[0];
}

void boot_kvm_writeb(u8 b, void __iomem *addr)
{
	DebugBKVMIO("started to write byte 0x%02x to MMIO addr %px\n",
		b, addr);
	if (BOOT_IS_HV_GM())
		return boot_native_writeb(b, addr);

	boot_kvm_guest_mmio(addr, b, 1, 1);
}

void boot_kvm_writew(u16 w, void __iomem *addr)
{
	DebugBKVMIO("started to write halfword 0x%04x to MMIO addr %px\n",
		w, addr);
	if (BOOT_IS_HV_GM())
		return boot_native_writew(w, addr);

	boot_kvm_guest_mmio(addr, w, 2, 1);
}

void boot_kvm_writel(u32 l, void __iomem *addr)
{
	DebugBKVMIO("started to write word 0x%08x to MMIO addr %px\n",
		l, addr);
	if (BOOT_IS_HV_GM())
		return boot_native_writel(l, addr);

	boot_kvm_guest_mmio(addr, l, 4, 1);
}

void boot_kvm_writell(u64 q, void __iomem *addr)
{
	DebugBKVMIO("started to write long word 0x%016lx to MMIO addr %px\n",
		q, addr);
	if (BOOT_IS_HV_GM())
		return boot_native_writeq(q, addr);

	boot_kvm_guest_mmio(addr, q, 8, 1);
}

u8 boot_kvm_readb(void __iomem *addr)
{
	DebugBKVMIO("started to read byte from MMIO addr %px\n", addr);
	if (BOOT_IS_HV_GM())
		return boot_native_readb(addr);

	return boot_kvm_guest_mmio(addr, 0, 1, 0);
}

u16 boot_kvm_readw(void __iomem *addr)
{
	DebugBKVMIO("started to read halfword from MMIO addr %px\n", addr);
	if (BOOT_IS_HV_GM())
		return boot_native_readw(addr);

	return boot_kvm_guest_mmio(addr, 0, 2, 0);
}

u32 boot_kvm_readl(void __iomem *addr)
{
	DebugBKVMIO("started to read word from MMIO addr %px\n", addr);
	if (BOOT_IS_HV_GM())
		return boot_native_readl(addr);

	return boot_kvm_guest_mmio(addr, 0, 4, 0);
}

u64 boot_kvm_readll(void __iomem *addr)
{
	DebugBKVMIO("started to read long word from MMIO addr %px\n", addr);
	if (BOOT_IS_HV_GM())
		return boot_native_readq(addr);

	return boot_kvm_guest_mmio(addr, 0, 8, 0);
}
