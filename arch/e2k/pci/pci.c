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

#include <asm-l/pci_l.h>

#undef DEBUG

#ifdef DEBUG
#define DBG(x...) printk(x)
#else
#define DBG(x...)
#endif

/* Hardware gained partial support for no_snoop mode only
 * in iset v6 so assume conservatively that on these cpus
 * we have such devices.
 *
 * Upon boot we will recheck this assumption by scanning
 * through all PCIe devices and checking whether they declare
 * "Enable No Snoop" (see check_for_no_snoop_devices()). */
bool use_pcie_no_snoop = CONFIG_CPU_ISET_MIN >= 7;
EXPORT_SYMBOL(use_pcie_no_snoop);

static bool use_pcie_no_snoop_forced = false;

int init_pcie_no_snoop(void)
{
	/* For generic kernels we have to initialize dynamically */
	if (!use_pcie_no_snoop_forced)
		use_pcie_no_snoop = cpu_has(CPU_FEAT_ISET_V7);
	return 1;
}
pure_initcall(init_pcie_no_snoop);

static int __init pcie_no_snoop_setup(char *str)
{
	if (!cpu_has(CPU_FEAT_ISET_V7)) {
		pr_warn("pcie_no_snoop= option is supported only since iset v7\n");
		return 1;
	}

	if (!strcmp(str, "enable")) {
		use_pcie_no_snoop = true;
	} else if (!strcmp(str, "disable")) {
		use_pcie_no_snoop = false;
	} else {
		pr_warn("Unable to parse pcie_no_snoop=\n");
		return 1;
	}

	pr_info("PCIe Enable No Snoop %s from cmdline\n",
			(use_pcie_no_snoop) ? "enabled" : "disabled");
	use_pcie_no_snoop_forced = true;
	return 1;
}
__setup("pcie_no_snoop=", pcie_no_snoop_setup);

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
			pci_err(dev, "WARNING: IMG GPU GX6650 does not support disabling PCIe No Snoop on e2c3.rev0\n");
			return;
		}

		if (!pci_read_config_word(dev, 0x40, &reg) &&
		    !pci_write_config_word(dev, 0x40,
				(use_pcie_no_snoop) ? (reg & ~0x10) : (reg | 0x10))) {
			pci_info(dev, "%s PCIe Enable No Snoop\n",
					(use_pcie_no_snoop) ? "setting" : "clearing");
		} else {
			pci_err(dev, "WARNING: failed to write PCIe No Snoop\n");
		}
	} else if (pci_is_pcie(dev)) {
		/* Normal case */
		if (!use_pcie_no_snoop && !pcie_capability_clear_word(dev, PCI_EXP_DEVCTL,
							PCI_EXP_DEVCTL_NOSNOOP_EN) ||
		    use_pcie_no_snoop && !pcie_capability_set_word(dev, PCI_EXP_DEVCTL,
							PCI_EXP_DEVCTL_NOSNOOP_EN)) {
			pci_info(dev, "%s PCIe Enable No Snoop\n",
					(use_pcie_no_snoop) ? "setting" : "clearing");
		} else {
			pci_err(dev, "WARNING: failed to write PCIe No Snoop\n");
		}
	}
}
DECLARE_PCI_FIXUP_EARLY(PCI_ANY_ID, PCI_ANY_ID, fixup_pcie_no_snoop);


char *pcibios_setup(char *str)
{
	if (!strcmp(str, "off")) {
		pci_probe = 0;
		return NULL;
	}
	else if (!strcmp(str, "conf1")) {
		pci_probe = PCI_PROBE_CONF1 | PCI_NO_CHECKS;
		return NULL;
	}
	else if (!strcmp(str, "conf2")) {
		pci_probe = PCI_PROBE_CONF2 | PCI_NO_CHECKS;
		return NULL;
	}
	else if (!strcmp(str, "noacpi")) {
		acpi_noirq_set();
		return NULL;
	}
	else if (!strcmp(str, "rom")) {
		pci_probe |= PCI_ASSIGN_ROMS;
		return NULL;
	} else if (!strcmp(str, "assign-busses")) {
		pci_probe |= PCI_ASSIGN_ALL_BUSSES;
		return NULL;
	}
	return str;
}

unsigned int pcibios_assign_all_busses(void)
{
	return (pci_probe & PCI_ASSIGN_ALL_BUSSES) ? 1 : 0;
}

int pcibios_enable_device(struct pci_dev *dev, int mask)
{
	int err;

	if ((err = pci_enable_resources(dev, mask)) < 0)
		return err;

	if (!pci_dev_msi_enabled(dev))
		return pcibios_enable_irq(dev);
	return 0;
}

void pcibios_disable_device (struct pci_dev *dev)
{
	if (!pci_dev_msi_enabled(dev) && pcibios_disable_irq)
		pcibios_disable_irq(dev);
}

void __init pcibios_fixup_resources(struct pci_bus *pbus)
{
	/* Nothing to do */
}

/*
 * Functions for accessing PCI configuration space with type 1 accesses
 */

#define PCI_CONF1_ADDRESS(bus, devfn, reg) \
	(0x80000000 | (bus << 16) | (devfn << 8) | (reg & ~3))

static int pci_conf1_read(unsigned int seg, unsigned int bus,
			  unsigned int devfn, int reg, int len, u32 *value)
{
	unsigned long flags;

	if (!value || (bus > 255) || (devfn > 255) || (reg > 255))
		return -EINVAL;

	raw_spin_lock_irqsave(&pci_config_lock, flags);

	outl(PCI_CONF1_ADDRESS(bus, devfn, reg), 0xCF8);

	switch (len) {
	case 1:
		*value = inb(0xCFC + (reg & 3));
		break;
	case 2:
		*value = inw(0xCFC + (reg & 2));
		break;
	case 4:
		*value = inl(0xCFC);
		break;
	}

	raw_spin_unlock_irqrestore(&pci_config_lock, flags);

	return 0;
}

static int pci_conf1_write(unsigned int seg, unsigned int bus,
			   unsigned int devfn, int reg, int len, u32 value)
{
	unsigned long flags;

	if ((bus > 255) || (devfn > 255) || (reg > 255)) 
		return -EINVAL;

	raw_spin_lock_irqsave(&pci_config_lock, flags);

	outl(PCI_CONF1_ADDRESS(bus, devfn, reg), 0xCF8);

	switch (len) {
	case 1:
		outb((u8)value, 0xCFC + (reg & 3));
		break;
	case 2:
		outw((u16)value, 0xCFC + (reg & 2));
		break;
	case 4:
		outl((u32)value, 0xCFC);
		break;
	}

	raw_spin_unlock_irqrestore(&pci_config_lock, flags);

	return 0;
}

#undef PCI_CONF1_ADDRESS

struct pci_raw_ops pci_direct_conf1 = {
	.read =		pci_conf1_read,
	.write =	pci_conf1_write,
};


/*
 * Functions for accessing PCI configuration space with type 2 accesses
 */

#define PCI_CONF2_ADDRESS(dev, reg)	(u16)(0xC000 | (dev << 8) | reg)

static int pci_conf2_read(unsigned int seg, unsigned int bus,
			  unsigned int devfn, int reg, int len, u32 *value)
{
	unsigned long flags;
	int dev, fn;

	if (!value || (bus > 255) || (devfn > 255) || (reg > 255))
		return -EINVAL;

	dev = PCI_SLOT(devfn);
	fn = PCI_FUNC(devfn);

	if (dev & 0x10) 
		return PCIBIOS_DEVICE_NOT_FOUND;

	raw_spin_lock_irqsave(&pci_config_lock, flags);

	outb((u8)(0xF0 | (fn << 1)), 0xCF8);
	outb((u8)bus, 0xCFA);

	switch (len) {
	case 1:
		*value = inb(PCI_CONF2_ADDRESS(dev, reg));
		break;
	case 2:
		*value = inw(PCI_CONF2_ADDRESS(dev, reg));
		break;
	case 4:
		*value = inl(PCI_CONF2_ADDRESS(dev, reg));
		break;
	}

	outb(0, 0xCF8);

	raw_spin_unlock_irqrestore(&pci_config_lock, flags);

	return 0;
}

static int pci_conf2_write(unsigned int seg, unsigned int bus,
			   unsigned int devfn, int reg, int len, u32 value)
{
	unsigned long flags;
	int dev, fn;

	if ((bus > 255) || (devfn > 255) || (reg > 255)) 
		return -EINVAL;

	dev = PCI_SLOT(devfn);
	fn = PCI_FUNC(devfn);

	if (dev & 0x10) 
		return PCIBIOS_DEVICE_NOT_FOUND;

	raw_spin_lock_irqsave(&pci_config_lock, flags);

	outb((u8)(0xF0 | (fn << 1)), 0xCF8);
	outb((u8)bus, 0xCFA);

	switch (len) {
	case 1:
		outb((u8)value, PCI_CONF2_ADDRESS(dev, reg));
		break;
	case 2:
		outw((u16)value, PCI_CONF2_ADDRESS(dev, reg));
		break;
	case 4:
		outl((u32)value, PCI_CONF2_ADDRESS(dev, reg));
		break;
	}

	outb(0, 0xCF8);    

	raw_spin_unlock_irqrestore(&pci_config_lock, flags);

	return 0;
}

#undef PCI_CONF2_ADDRESS

static struct pci_raw_ops pci_direct_conf2 = {
	.read =		pci_conf2_read,
	.write =	pci_conf2_write,
};

/*
 * Before we decide to use direct hardware access mechanisms, we try to do some
 * trivial checks to ensure it at least _seems_ to be working -- we just test
 * whether bus 00 contains a host bridge (this is similar to checking
 * techniques used in XFree86, but ours should be more reliable since we
 * attempt to make use of direct access hints provided by the PCI BIOS).
 *
 * This should be close to trivial, but it isn't, because there are buggy
 * chipsets (yes, you guessed it, by Intel and Compaq) that have no class ID.
 */
static int __init pci_sanity_check(struct pci_raw_ops *o)
{
	u32 x = 0;
	int devfn;

	if (pci_probe & PCI_NO_CHECKS)
		return 1;

	for (devfn = 0; devfn < 0x100; devfn++) {
		if (o->read(0, 0, devfn, PCI_CLASS_DEVICE, 2, &x))
			continue;
		if (x == PCI_CLASS_BRIDGE_HOST || x == PCI_CLASS_DISPLAY_VGA)
			return 1;

		if (o->read(0, 0, devfn, PCI_VENDOR_ID, 2, &x))
			continue;
		if (x == PCI_VENDOR_ID_INTEL || x == PCI_VENDOR_ID_COMPAQ)
			return 1;
	}

	DBG("PCI: Sanity check failed\n");
	return 0;
}

static int __init pci_check_type1(void)
{
	unsigned long flags;
	unsigned int tmp;
	int works = 0;

	raw_spin_lock_irqsave(&pci_config_lock, flags);

	outb(0x01, 0xCFB);
	tmp = inl(0xCF8);
	outl(0x80000000, 0xCF8);

	if (inl(0xCF8) == 0x80000000) {
		raw_spin_unlock_irqrestore(&pci_config_lock, flags);

		if (pci_sanity_check(&pci_direct_conf1))
			works = 1;

		raw_spin_lock_irqsave(&pci_config_lock, flags);
	}
	outl(tmp, 0xCF8);

	raw_spin_unlock_irqrestore(&pci_config_lock, flags);

	return works;
}

static int __init pci_check_type2(void)
{
	unsigned long flags;
	int works = 0;

	raw_spin_lock_irqsave(&pci_config_lock, flags);

	outb(0x00, 0xCFB);
	outb(0x00, 0xCF8);
	outb(0x00, 0xCFA);

	if (inb(0xCF8) == 0x00 && inb(0xCFA) == 0x00) {
		raw_spin_unlock_irqrestore(&pci_config_lock, flags);

		if (pci_sanity_check(&pci_direct_conf2))
			works = 1;
	} else
		raw_spin_unlock_irqrestore(&pci_config_lock, flags);

	return works;
}

static int __init pci_direct_init(void)
{
	struct resource *region, *region2;

	pci_probe = PCI_PROBE_L;
	if (!HAS_MACHINE_L_SIC)
		pci_probe |= (PCI_PROBE_CONF1 | PCI_PROBE_CONF2);

	if ((pci_probe & PCI_PROBE_CONF1) == 0)
		goto type2;
	region = request_region(0xCF8, 8, "PCI conf1");
	if (!region)
		goto type2;

	if (pci_check_type1()) {
		printk(KERN_INFO "PCI: Using configuration type 1\n");
		raw_pci_ops = &pci_direct_conf1;
		return 0;
	}
	release_resource(region);

 type2:
	if ((pci_probe & PCI_PROBE_CONF2) == 0)
		goto type_l;
	region = request_region(0xCF8, 4, "PCI conf2");
	if (!region)
		goto type_l;
	region2 = request_region(0xC000, 0x1000, "PCI conf2");
	if (!region2)
		goto fail2;

	if (pci_check_type2()) {
		printk(KERN_INFO "PCI: Using configuration type 2\n");
		raw_pci_ops = &pci_direct_conf2;
		return 0;
	}

	release_resource(region2);
 fail2:
	release_resource(region);

 type_l:
	if (HAS_MACHINE_L_SIC)
		return l_pci_direct_init();
	return -1;
}

int __init native_arch_pci_init(void)
{
	return pci_direct_init();
}

static int __init pci_init(void)
{
	return arch_pci_init();
}
arch_initcall(pci_init);

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
