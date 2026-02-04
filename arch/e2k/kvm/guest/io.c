/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#include <linux/kernel.h>
#include <linux/types.h>
#include <linux/init.h>
#include <linux/vmalloc.h>
#include <linux/pci.h>
#include <linux/export.h>
#include <linux/pgtable.h>

#include <asm/epic.h>
#include <asm/mman.h>
#include <asm/io.h>
#include <asm/vga.h>
#include <asm/e2k_sic.h>
#include <asm/kvm/guest/io.h>
#include <asm/kvm/hypercall.h>
#include <asm/console.h>

#undef	DEBUG_KVM_IO_MODE
#undef	DebugKVMIO
#define	DEBUG_KVM_IO_MODE	0	/* kernel virt machine IO debugging */
#define	DebugKVMIO(fmt, args...)					\
({									\
	if (DEBUG_KVM_IO_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IOPORT_MODE
#undef	DebugKVMIOP
#define	DEBUG_KVM_IOPORT_MODE	0	/* kernel virt machine IO debugging */
#define	DebugKVMIOP(fmt, args...)					\
({									\
	if (DEBUG_KVM_IOPORT_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_MMIO_MODE
#undef	DebugMMIO
#define	DEBUG_KVM_MMIO_MODE	0	/* kernel virt machine MMIO debugging */
#define	DebugMMIO(fmt, args...)						\
({									\
	if (DEBUG_KVM_MMIO_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_CIO_MODE
#undef	DebugCIO
#define	DEBUG_CIO_MODE		0	/* configuration space  */
					/* input/output functions */
#define	DebugCIO(fmt, args...)						\
({									\
	if (DEBUG_CIO_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

static unsigned long
do_guest_mmio(e2k_addr_t phys_addr, u64 value, u8 size, u8 is_write)
{
	unsigned long data[1];
	int ret;

	if (is_write) {
		data[0] = value;
		DebugKVMIO("data to write 0x%lx size %d to addr 0x%lx\n",
			data[0], size, phys_addr);
	}
	if ((phys_addr & MAX_PA_MASK) != (phys_addr & E2K_VA_MASK)) {
		pr_err("%s: MMIO addr 0x%lx, size %d out of physival memory\n",
			__func__, phys_addr, size);
		BUG_ON(true);
	}
	ret = HYPERVISOR_guest_mmio_request(phys_addr, data, size, is_write);
	if (ret) {
		pr_err("%s: could not pass MMIO request to host, error %d\n",
			__func__, ret);
		return -1L;
	}
	if (!is_write) {
		DebugKVMIO("read data 0x%lx size %d from addr 0x%lx\n",
			data[0], size, phys_addr);
	}
	return data[0];
}

/*
 * KVM guest MMIO should be passed to QEMU through host hypercall.
 * KVM MMIO <-> QEMU interface assumes physical address of MMIO request.
 * The function argument can be
 *	physical address;
 *	IO remapped address;
 *	VGA VRAM address
 * IO remapped address is translated to source physical IO address on PCI
 * VGA VRAM address is converted to special physical address into guest
 * IO memory address space (see asm/head.h)
 */
static inline unsigned long
kvm_guest_mmio(volatile void __iomem *mmio_addr, u64 value, u8 size, u8 is_write,
		int domain)
{
	e2k_addr_t addr = (e2k_addr_t)mmio_addr;
	e2k_addr_t phys_addr;
	bool epic = cpu_has_epic();

	DebugMMIO("started to %s KVM MMIO address %px value 0x%02llx size %d\n",
		(is_write) ? "write to" : "read from",
		mmio_addr, value, size);
	if ((addr & MAX_PA_MASK) == addr) {
		/* address is already physical */
		phys_addr = addr;
		DebugMMIO("source address 0x%lx is already physical\n",
			addr);
	} else if (addr >= GUEST_VMALLOC_START && addr < GUEST_VMALLOC_END) {
		/* address inside IO remapping area */
		struct vm_struct *vm;

		vm = find_io_vm_area((const void *)addr);
		if (unlikely(vm == NULL)) {
			pr_err("%s: could not find MMIO address %px into "
				"IO remapping areas\n",
				__func__, mmio_addr);
			BUG_ON(true);
		}
		if (unlikely(!(vm->flags & VM_IOREMAP))) {
			pr_err("%s: MMIO address %px is into not IO remapping "
				"area\n",
				__func__, mmio_addr);
			BUG_ON(true);
		}
		phys_addr = vm->phys_addr;
		DebugMMIO("virtual address 0x%lx is from MMIO remapping space, "
			"converted to physical 0x%lx\n",
			addr, phys_addr);
		BUG_ON(phys_addr == 0 ||
			((phys_addr & MAX_PA_MASK) != phys_addr));
		phys_addr |= (addr & ~PAGE_MASK);
	} else if (unlikely(KVM_IS_VGA_VRAM_VIRT_ADDR(addr))) {
		/* it is virtual address of VGA VRAM */
		phys_addr = KVM_VGA_VRAM_VIRT_TO_PHYS(addr);
		DebugMMIO("virtual address 0x%lx is from VGA VRAM space, "
			"converted to physical 0x%lx\n",
			addr, phys_addr);
	} else {
		pr_err("%s: invalid KVM MMIO address %px\n",
			__func__, mmio_addr);
		BUG_ON(true);
	}
	if (likely(phys_addr >= PCIBIOS_MIN_MEM &&
				phys_addr <= PCIBIOS_MAX_MEM_32)) {
		/* it is address inside PCI space */
		/* pass direct physical address */
		DebugMMIO("physical address 0x%lx is from PCI space\n",
			phys_addr);
	} else if (phys_addr >= get_domain_pci_conf_base(domain) &&
			phys_addr < get_domain_pci_conf_base(domain) +
					get_domain_pci_conf_size(domain)) {
		/* it is address inside PCI config space */
		/* pass direct physical address */
		DebugMMIO("physical address 0x%lx is from PCI config space\n",
			phys_addr);
	} else if (unlikely(KVM_IS_VGA_VRAM_PHYS_ADDR(phys_addr))) {
		/* it is physical address inside VGA VRAM space */
		/* convert to KVM guest "physical" address */
		phys_addr += KVM_VGA_VRAM_PHYS_BASE;
		DebugMMIO("physical address 0x%lx is from VGA VRAM space\n",
			phys_addr);
	} else if (!epic && phys_addr >= APIC_BASE &&
				phys_addr < APIC_BASE + APIC_REGS_SIZE) {
		/* it is local APIC registers address space */
		DebugMMIO("physical address 0x%lx is local APIC register\n",
			phys_addr);
	} else if (!epic && phys_addr >= IO_APIC_DEFAULT_PHYS_BASE &&
				phys_addr < IO_APIC_DEFAULT_PHYS_BASE +
							IO_APIC_SLOT_SIZE) {
		/* it is IO-APIC registers address space */
		DebugMMIO("physical address 0x%lx is IO-APIC register\n",
			phys_addr);
	} else if (epic && phys_addr >= EPIC_DEFAULT_PHYS_BASE &&
		phys_addr < EPIC_DEFAULT_PHYS_BASE + EPIC_REGS_SIZE) {
		/* it is CEPIC registers address space */
		DebugMMIO("physical address 0x%lx is CEPIC register\n",
			phys_addr);
	} else if (epic && phys_addr >= IO_EPIC_DEFAULT_PHYS_BASE &&
		phys_addr < IO_EPIC_DEFAULT_PHYS_BASE + IO_EPIC_REGS_SIZE) {
		/* it is IO-EPIC registers address space */
		DebugMMIO("physical address 0x%lx is IO-EPIC register\n",
			phys_addr);
	} else if (phys_addr >= (e2k_addr_t)THE_NODE_NBSR_PHYS_BASE(0) &&
			phys_addr < (e2k_addr_t)THE_NODE_NBSR_PHYS_BASE(0) +
						NODE_NBSR_SIZE * MAX_NUMNODES) {
		/* it is NBSR (SIC) registers address space */
		DebugMMIO("physical address 0x%lx is SIC-NBSR register\n",
			phys_addr);
	} else {
		pr_err("%s: invalid KVM MMIO physical address 0x%lx for "
			"source virtual address %px\n",
			__func__, phys_addr, mmio_addr);
		BUG_ON(true);
	}
	DebugMMIO("pass request to QEMU to %s KVM MMIO physical address 0x%lx "
		"value 0x%02llx size %d\n",
		(is_write) ? "write to" : "read from",
		phys_addr, value, size);
	return do_guest_mmio(phys_addr, value, size, is_write);
}
unsigned long
kvm_handle_guest_mmio(void __iomem *mmio_addr, u64 value, u8 size, u8 is_write)
{
	return kvm_guest_mmio(mmio_addr, value, size, is_write, 0);
}

u8 kvm_readb(const volatile void __iomem *addr)
{
	DebugKVMIO("started to read byte from MMIO addr %px\n", addr);
	return kvm_guest_mmio((__force volatile void __iomem *) addr, 0, 1, 0, 0);
}
EXPORT_SYMBOL(kvm_readb);

u16 kvm_readw(const volatile void __iomem *addr)
{
	DebugKVMIO("started to read halfword from MMIO addr %px\n", addr);
	return kvm_guest_mmio((__force volatile void __iomem *) addr, 0, 2, 0, 0);
}
EXPORT_SYMBOL(kvm_readw);

u32 kvm_readl(const volatile void __iomem *addr)
{
	DebugKVMIO("started to read word from MMIO addr %px\n", addr);
	return kvm_guest_mmio((__force volatile void __iomem *) addr, 0, 4, 0, 0);
}
EXPORT_SYMBOL(kvm_readl);

u64 kvm_readll(const volatile void __iomem *addr)
{
	DebugKVMIO("started to read long word from MMIO addr %px\n", addr);
	return kvm_guest_mmio((__force volatile void __iomem *) addr, 0, 8, 0, 0);
}
EXPORT_SYMBOL(kvm_readll);

void kvm_writeb(u8 b, volatile void __iomem *addr)
{
	DebugKVMIO("started to write byte 0x%02x to MMIO addr %px\n",
		b, addr);
	kvm_guest_mmio(addr, b, 1, 1, 0);
}
EXPORT_SYMBOL(kvm_writeb);

void kvm_writew(u16 w, volatile void __iomem *addr)
{
	DebugKVMIO("started to write halfword 0x%04x to MMIO addr %px\n",
		w, addr);
	kvm_guest_mmio(addr, w, 2, 1, 0);
}
EXPORT_SYMBOL(kvm_writew);

void kvm_writel(u32 l, volatile void __iomem *addr)
{
	DebugKVMIO("started to write word 0x%08x to MMIO addr %px\n",
		l, addr);
	kvm_guest_mmio(addr, l, 4, 1, 0);
}
EXPORT_SYMBOL(kvm_writel);

void kvm_writell(u64 q, volatile void __iomem *addr)
{
	DebugKVMIO("started to write long word 0x%016llx to MMIO addr %px\n",
		q, addr);
	kvm_guest_mmio(addr, q, 8, 1, 0);
}
EXPORT_SYMBOL(kvm_writell);

static unsigned long
kvm_guest_ioport(u32 port, u32 value, u8 size, u8 is_out)
{
	u32 data[1];
	int ret;

	if (is_out) {
		data[0] = value;
		DebugKVMIOP("data to write 0x%x size %d to port 0x%x\n",
			value, size, port);
	}
	ret = HYPERVISOR_guest_ioport_request(port, data, size, is_out);
	if (!is_out) {
		DebugKVMIOP("read data 0x%x size %d from port 0x%x\n",
			data[0], size, port);
	}
	return data[0];
}

static unsigned long
kvm_guest_ioport_string(u32 port, const void *data, u8 size, u32 count,
			u8 is_out)
{
	unsigned long ret;

	ret = HYPERVISOR_guest_ioport_string_request(port, data, size,
							count, is_out);
	DebugKVMIO("%s data %px size %d, count 0x%x to port 0x%x\n",
		(is_out) ? "written from" : "read to", data, size, count, port);
	return ret;
}

u8 kvm_inb(unsigned short port)
{
	DebugKVMIO("started to read byte from IO port 0x%x\n", port);
	return kvm_guest_ioport(port, 0, 1, 0);
}
EXPORT_SYMBOL(kvm_inb);

u16 kvm_inw(unsigned short port)
{
	DebugKVMIO("started to read halfword from IO port 0x%x\n", port);
	return kvm_guest_ioport(port, 0, 2, 0);
}
EXPORT_SYMBOL(kvm_inw);

u32 kvm_inl(unsigned short port)
{
	DebugKVMIO("started to read word from IO port 0x%x\n", port);
	return kvm_guest_ioport(port, 0, 4, 0);
}
EXPORT_SYMBOL(kvm_inl);

void kvm_outb(unsigned char byte, unsigned short port)
{
	DebugKVMIO("started to write byte 0x%02x to IO port 0x%x\n",
		byte, port);
	kvm_guest_ioport(port, byte, 1, 1);
}
EXPORT_SYMBOL(kvm_outb);

void kvm_outw(unsigned short halfword, unsigned short port)
{
	DebugKVMIO("started to write halfword 0x%04x to IO port 0x%x\n",
		halfword, port);
	kvm_guest_ioport(port, halfword, 2, 1);
}
EXPORT_SYMBOL(kvm_outw);

void kvm_outl(unsigned int word, unsigned short port)
{
	DebugKVMIO("started to write word 0x%08x to IO port 0x%x\n",
		word, port);
	kvm_guest_ioport(port, word, 4, 1);
}
EXPORT_SYMBOL(kvm_outl);

void kvm_outsb(unsigned short port, const void *src, unsigned long count)
{
	DebugKVMIO("started to write 0x%lx bytes fron %px to IO port 0x%x\n",
		count, src, port);
	kvm_guest_ioport_string(port, src, 1, count, 1);
}
EXPORT_SYMBOL(kvm_outsb);

void kvm_outsw(unsigned short port, const void *src, unsigned long count)
{
	DebugKVMIO("started to write 0x%lx halfwords fron %px to "
		"IO port 0x%x\n",
		count, src, port);
	kvm_guest_ioport_string(port, src, 2, count, 1);
}
EXPORT_SYMBOL(kvm_outsw);

void kvm_outsl(unsigned short port, const void *src, unsigned long count)
{
	DebugKVMIO("started to write 0x%lx words fron %px to IO port 0x%x\n",
		count, src, port);
	kvm_guest_ioport_string(port, src, 4, count, 1);
}
EXPORT_SYMBOL(kvm_outsl);

void kvm_insb(unsigned short port, void *dst, unsigned long count)
{
	DebugKVMIO("started to read 0x%lx bytes to %px from IO port 0x%x\n",
		count, dst, port);
	kvm_guest_ioport_string(port, dst, 1, count, 0);
}
EXPORT_SYMBOL(kvm_insb);

void kvm_insw(unsigned short port, void *dst, unsigned long count)
{
	DebugKVMIO("started to read 0x%lx halfwords to %px from IO port 0x%x\n",
		count, dst, port);
	kvm_guest_ioport_string(port, dst, 2, count, 0);
}
EXPORT_SYMBOL(kvm_insw);

void kvm_insl(unsigned short port, void *dst, unsigned long count)
{
	DebugKVMIO("started to read 0x%lx words to %px from IO port 0x%x\n",
		count, dst, port);
	kvm_guest_ioport_string(port, dst, 4, count, 0);
}
EXPORT_SYMBOL(kvm_insl);

void kvm_conf_inb(unsigned int domain, unsigned int bus, unsigned long port,
			u8 *byte)
{
	void __iomem *conf_base;
	void __iomem *conf_port;

	conf_base = (void __iomem *)get_domain_pci_conf_base(domain);
	conf_port = conf_base + port;
	*byte = kvm_guest_mmio(conf_port, 0, 1, 0, domain);
	DebugCIO("kvm_conf_inb(): value %x read from port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) *byte, conf_port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
}

void kvm_conf_inw(unsigned int domain, unsigned int bus, unsigned long port,
			u16 *hword)
{
	void __iomem *conf_base;
	void __iomem *conf_port;

	conf_base = (void __iomem *)get_domain_pci_conf_base(domain);
	conf_port = conf_base + port;
	*hword = kvm_guest_mmio(conf_port, 0, 2, 0, domain);
	DebugCIO("kvm_conf_inw(): value %x read from port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) *hword, conf_port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
}

void kvm_conf_inl(unsigned int domain, unsigned int bus, unsigned long port,
			u32 *word)
{
	void __iomem *conf_base;
	void __iomem *conf_port;

	conf_base = (void __iomem *)get_domain_pci_conf_base(domain);
	conf_port = conf_base + port;
	*word = kvm_guest_mmio(conf_port, 0, 4, 0, domain);
	DebugCIO("kvm_conf_inl(): value %x read from port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) *word, conf_port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
}

void kvm_conf_outb(unsigned int domain, unsigned int bus, unsigned long port,
			u8 byte)
{
	void __iomem *conf_base;
	void __iomem *conf_port;

	conf_base = (void __iomem *)get_domain_pci_conf_base(domain);
	conf_port = conf_base + port;
	DebugCIO("kvm_conf_outb(): value %x write to port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) byte, conf_port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
	kvm_guest_mmio(conf_port, byte, 1, 1, domain);
}

void kvm_conf_outw(unsigned int domain, unsigned int bus, unsigned long port,
			u16 hword)
{
	void __iomem *conf_base;
	void __iomem *conf_port;

	conf_base = (void __iomem *)get_domain_pci_conf_base(domain);
	conf_port = conf_base + port;
	DebugCIO("kvm_conf_outw(): value %x write to port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) hword, conf_port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
	kvm_guest_mmio(conf_port, hword, 2, 1, domain);
}

void kvm_conf_outl(unsigned int domain, unsigned int bus, unsigned long port,
			u32 word)
{
	void __iomem *conf_base;
	void __iomem *conf_port;

	conf_base = (void __iomem *)get_domain_pci_conf_base(domain);
	conf_port = conf_base + port;
	DebugCIO("kvm_conf_outl(): value %x write to port %lx, domain #%d "
		"(node %d, IO link %d)\n",
		(u32) word, conf_port, domain,
		iohub_domain_to_node(domain), iohub_domain_to_link(domain));
	kvm_guest_mmio(conf_port, word, 4, 1, domain);
}

static inline unsigned long
kvm_vga_vram_access(void *addr, u64 value, u8 size, bool is_write)
{
	e2k_addr_t phys_addr = (e2k_addr_t)addr;

	if (is_write) {
		DebugKVMIO("data to write 0x%llx size %d to addr %px\n",
			value, size, addr);
	}
	if (likely(KVM_IS_VGA_VRAM_VIRT_ADDR(phys_addr) ||
			KVM_IS_VGA_VRAM_PHYS_ADDR(phys_addr))) {
		return kvm_guest_mmio(addr, value, size, is_write, 0);
	} else if (KVM_IS_PHYS_MEM_MAP_ADDR(phys_addr)) {
		if (is_write) {
			switch (size) {
			case 1:	/* byte */
				*((u8 *)addr) = (u8)value;
				break;
			case 2:	/* half  word */
				*((u16 *)addr) = (u16)value;
				break;
			default:
				pr_err("%s() Invalid size %d of data "
					"to write\n", __func__, size);
				BUG_ON(true);
			}
			return value;
		} else {
			switch (size) {
			case 1:	/* byte */
				value = *((u8 *)addr);
				break;
			case 2:	/* half  word */
				value = *((u16 *)addr);
				break;
			default:
				pr_err("%s(): Invalid size %d of data "
					"to read\n", __func__, size);
				BUG_ON(true);
			}
			DebugKVMIO("read data 0x%llx size %d from addr %px\n",
				value, size, addr);
			return value;
		}
	} else {
		pr_err("%s(): Invalid address %px to read/write\n",
			__func__, addr);
		BUG_ON(true);
		return -1L;
	}
}

void kvm_scr_writew(u16 w, volatile u16 *addr)
{
	DebugKVMIO("started to write halfword 0x%04x to VGA VRAM addr %px\n",
		w, addr);
	kvm_vga_vram_access((void *) addr, w, 2, true);
}
u16 kvm_scr_readw(volatile const u16 *addr)
{
	DebugKVMIO("started to read halfword from VGA VRAM addr %px\n", addr);
	return kvm_vga_vram_access((void *) addr, 0, 2, false);
}
void kvm_vga_writeb(u8 b, u8 *addr)
{
	DebugKVMIO("started to write byte 0x%02x to VGA VRAM addr %px\n",
		b, addr);
	kvm_vga_vram_access(addr, b, 1, true);
}
u8 kvm_vga_readb(const u8 *addr)
{
	DebugKVMIO("started to read byte from VGA VRAM addr %px\n", addr);
	return kvm_vga_vram_access((void *) addr, 0, 1, false);
}

unsigned long kvm_notify_io(unsigned int notifier_io)
{
	unsigned long ret;

	ret = HYPERVISOR_notify_io(notifier_io);
	return ret;
}

int __init kvm_arch_pci_init(void)
{
	return native_arch_pci_init();
}
