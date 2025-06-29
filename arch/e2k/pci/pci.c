/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Low-Level PCI Support
 */

#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/ioport.h>
#include <linux/init.h>

#include <asm/acpi.h>
#include <asm/mman.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/pgtable_def.h>

/*
 * Propagate PCIe No Snoop setting into actual PCI
 */
static void fixup_pcie_no_snoop(struct pci_dev *dev)
{
	if (dev->vendor == PCI_VENDOR_ID_MCST_TMP &&
	    dev->device == PCI_DEVICE_ID_MCST_IMG_GPU_GX6650) {
		/* Imagination GPU case */
		u16 reg;

		if (cpu_has(CPU_HWBUG_IMGGPU_NOSNOOP_ALWAYS_ON)) {
			pci_err(dev,
				"WARNING: IMG GPU GX6650 does not support disabling PCIe No Snoop on e2c3.rev0\n");
			return;
		}

		if (!pci_read_config_word(dev, 0x40, &reg) &&
		    !pci_write_config_word(dev, 0x40, (reg | 0x10))) {
			pci_info(dev, "clearing PCIe Enable No Snoop\n");
		} else {
			pci_err(dev, "WARNING: failed to write PCIe No Snoop\n");
		}
	} else if (pci_is_pcie(dev)) {
		/* Normal case */
		if (!pcie_capability_clear_word(dev, PCI_EXP_DEVCTL,
						PCI_EXP_DEVCTL_NOSNOOP_EN)) {
			pci_info(dev, "clearing PCIe Enable No Snoop\n");
		} else {
			pci_err(dev, "WARNING: failed to write PCIe No Snoop\n");
		}
	}
}
DECLARE_PCI_FIXUP_EARLY(PCI_ANY_ID, PCI_ANY_ID, fixup_pcie_no_snoop);

#if	HAVE_PCI_LEGACY
/**
 * pci_mmap_legacy_page_range - map legacy memory space to userland
 * @bus: bus whose legacy space we're mapping
 * @vma: vma passed in by mmap
 *
 * Map legacy memory space for this device back to userspace using a machine
 * vector to get the base address.
 */
int
pci_mmap_legacy_page_range(struct pci_bus *bus, struct vm_area_struct *vma,
			   enum pci_mmap_state mmap_state)
{
	unsigned long size = vma->vm_end - vma->vm_start;
	pgprot_t prot;
	unsigned long addr = 0;

	/* We only support mmap'ing of legacy memory space */
	if (mmap_state != pci_mmap_mem)
		return -ENOSYS;

	prot = pgprot_noncached(vma->vm_page_prot);
	vma->vm_pgoff += addr >> PAGE_SHIFT;
	vma->vm_page_prot = prot;

	if (io_remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			    size, vma->vm_page_prot))
		return -EAGAIN;
	return 0;
}

/**
 * pci_legacy_read - read from legacy I/O space
 * @bus: bus to read
 * @port: legacy port value
 * @val: caller allocated storage for returned value
 * @size: number of bytes to read
 *
 * Simply reads @size bytes from @port and puts the result in @val.
 *
 * Again, this (and the write routine) are generic versions that can be
 * overridden by the platform.  This is necessary on platforms that don't
 * support legacy I/O routing or that hard fail on legacy I/O timeouts.
 */
int pci_legacy_read(struct pci_bus *bus, loff_t port, u32 *val, size_t size)
{
	int ret = size;
	switch (size) {
	case 1:
		*((u8 *)val) = inb(port);
		break;
	case 2:
		*((u16 *)val) = inw(port);
		break;
	case 4:
		*((u32 *)val) = inl(port);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

/**
 * pci_legacy_write - perform a legacy I/O write
 * @bus: bus pointer
 * @port: port to write
 * @val: value to write
 * @size: number of bytes to write from @val
 *
 * Simply writes @size bytes of @val to @port.
 */
int pci_legacy_write(struct pci_bus *bus, loff_t port, u32 val, size_t size)
{
	int ret = size;
	switch (size) {
	case 1:
		outb(val, port);
		break;
	case 2:
		outw(val, port);
		break;
	case 4:
		outl(val, port);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}
#endif	/*HAVE_PCI_LEGACY*/
