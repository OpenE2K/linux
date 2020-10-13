/*
 *	Low-Level PCI Support for PC
 *
 *	(c) 1999--2000 Martin Mares <mj@ucw.cz>
 */

#include <linux/sched.h>
#include <linux/pci.h>
#include <linux/ioport.h>
#include <linux/init.h>

#include <asm/io.h>
#include <asm/smp.h>
#include <asm/iommu.h>
#include <asm/e90s.h>

#undef	DEBUG_PCI_MODE
#undef	DebugPCI
#define	DEBUG_PCI_MODE		0	/* PCI init */
#define	DebugPCI		if (DEBUG_PCI_MODE) printk


volatile int pci_poke_in_progress;
volatile int pci_poke_cpu = -1;
volatile int pci_poke_faulted;

static DEFINE_RAW_SPINLOCK(pci_poke_lock);

void pci_config_read8(u8 *addr, u8 *ret)
{
	unsigned long flags;
	u8 byte;

	raw_spin_lock_irqsave(&pci_poke_lock, flags);
	pci_poke_cpu = smp_processor_id();
	pci_poke_in_progress = 1;
	pci_poke_faulted = 0;
	__asm__ __volatile__("membar #Sync\n\t"
			     "lduba [%1] %2, %0\n\t"
			     "membar #Sync"
			     : "=r" (byte)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L)
			     : "memory");
	pci_poke_in_progress = 0;
	pci_poke_cpu = -1;
	if (!pci_poke_faulted)
		*ret = byte;
	raw_spin_unlock_irqrestore(&pci_poke_lock, flags);
}

void pci_config_read16(u16 *addr, u16 *ret)
{
	unsigned long flags;
	u16 word;

	raw_spin_lock_irqsave(&pci_poke_lock, flags);
	pci_poke_cpu = smp_processor_id();
	pci_poke_in_progress = 1;
	pci_poke_faulted = 0;
	__asm__ __volatile__("membar #Sync\n\t"
			     "lduha [%1] %2, %0\n\t"
			     "membar #Sync"
			     : "=r" (word)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L)
			     : "memory");
	pci_poke_in_progress = 0;
	pci_poke_cpu = -1;
	if (!pci_poke_faulted)
		*ret = word;
	raw_spin_unlock_irqrestore(&pci_poke_lock, flags);
}

void pci_config_read32(u32 *addr, u32 *ret)
{
	unsigned long flags;
	u32 dword;

	raw_spin_lock_irqsave(&pci_poke_lock, flags);
	pci_poke_cpu = smp_processor_id();
	pci_poke_in_progress = 1;
	pci_poke_faulted = 0;
	__asm__ __volatile__("membar #Sync\n\t"
			     "lduwa [%1] %2, %0\n\t"
			     "membar #Sync"
			     : "=r" (dword)
			     : "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L)
			     : "memory");
	pci_poke_in_progress = 0;
	pci_poke_cpu = -1;
	if (!pci_poke_faulted)
		*ret = dword;
	raw_spin_unlock_irqrestore(&pci_poke_lock, flags);
}

void pci_config_write8(u8 *addr, u8 val)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&pci_poke_lock, flags);
	pci_poke_cpu = smp_processor_id();
	pci_poke_in_progress = 1;
	pci_poke_faulted = 0;
	__asm__ __volatile__("membar #Sync\n\t"
			     "stba %0, [%1] %2\n\t"
			     "membar #Sync"
			     : /* no outputs */
			     : "r" (val), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L)
			     : "memory");
	pci_poke_in_progress = 0;
	pci_poke_cpu = -1;
	raw_spin_unlock_irqrestore(&pci_poke_lock, flags);
}

void pci_config_write16(u16 *addr, u16 val)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&pci_poke_lock, flags);
	pci_poke_cpu = smp_processor_id();
	pci_poke_in_progress = 1;
	pci_poke_faulted = 0;
	__asm__ __volatile__("membar #Sync\n\t"
			     "stha %0, [%1] %2\n\t"
			     "membar #Sync"
			     : /* no outputs */
			     : "r" (val), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L)
			     : "memory");
	pci_poke_in_progress = 0;
	pci_poke_cpu = -1;
	raw_spin_unlock_irqrestore(&pci_poke_lock, flags);
}

void pci_config_write32(u32 *addr, u32 val)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&pci_poke_lock, flags);
	pci_poke_cpu = smp_processor_id();
	pci_poke_in_progress = 1;
	pci_poke_faulted = 0;
	__asm__ __volatile__("membar #Sync\n\t"
			     "stwa %0, [%1] %2\n\t"
			     "membar #Sync"
			     : /* no outputs */
			     : "r" (val), "r" (addr), "i" (ASI_PHYS_BYPASS_EC_E_L)
			     : "memory");
	pci_poke_in_progress = 0;
	pci_poke_cpu = -1;
	raw_spin_unlock_irqrestore(&pci_poke_lock, flags);
}

struct resource *
pcibios_select_root(struct pci_dev *pdev, struct resource *res)
{
	struct resource *root = NULL;

	if (res->flags & IORESOURCE_IO)
		root = &ioport_resource;
	if (res->flags & IORESOURCE_MEM)
		root = &iomem_resource;

	return root;
}

/*
 *  Called after each bus is probed, but before its children
 *  are examined.
 */

void __init  pcibios_fixup_bus(struct pci_bus *b)
{
	pci_read_bridge_bases(b);
}


char * __init  pcibios_setup(char *str)
{
	if (!strcmp(str, "off")) {
		pci_probe = 0;
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

	if ((err = pcibios_enable_resources(dev, mask)) < 0)
		return err;

	return pcibios_enable_irq(dev);
}

void pcibios_disable_device (struct pci_dev *dev)
{
	if (pcibios_disable_irq)
		pcibios_disable_irq(dev);
}


void __init pcibios_fixup_resources(struct pci_bus *pbus)
{
	struct pci_dev *dev;
	struct pci_bus *bus;
	int i;

	list_for_each_entry(dev, &pbus->devices, bus_list){
		for (i = 0; i < PCI_NUM_RESOURCES; i++) {

			if (dev->resource[i].flags & IORESOURCE_IO){ 	
				if (dev->resource[i].start > 0){
					dev->resource[i].start |= BASE_PCIIO;
					dev->resource[i].end |= BASE_PCIIO;
					DebugPCI("%s: fixup resource %s start "
						"0x%llx end 0x%llx\n",
						pci_name(dev),
						dev->resource[i].name,
						dev->resource[i].start,
						dev->resource[i].end);
				}
			}
		}
	}

	list_for_each_entry(bus, &pbus->children, node)
		pcibios_fixup_resources(bus);	
}

/*
 * We need to avoid collisions with `mirrored' VGA ports
 * and other strange ISA hardware, so we always want the
 * addresses to be allocated in the 0x000-0x0ff region
 * modulo 0x400.
 *
 * Why? Because some silly external IO cards only decode
 * the low 10 bits of the IO address. The 0x00-0xff region
 * is reserved for motherboard devices that decode all 16
 * bits, so it's ok to allocate at, say, 0x2800-0x28ff,
 * but we want to try to avoid allocating at 0x2900-0x2bff
 * which might have be mirrored at 0x0100-0x03ff..
 */
resource_size_t pcibios_align_resource(void *data, const struct resource *res,
				resource_size_t size, resource_size_t align)
{
	return res->start;
}

void pcibios_set_master(struct pci_dev *dev)
{
	/* No special bus mastering setup handling */
}

/* Perform the actual remap of the pages for a PCI device mapping, as appropriate
 * for this architecture.  The region in the process to map is described by vm_start
 * and vm_end members of VMA, the base physical address is found in vm_pgoff.
 * The pci device structure is provided so that architectures may make mapping
 * decisions on a per-device or per-bus basis.
 *
 * Returns a negative error code on failure, zero on success.
 */

int pci_mmap_page_range(struct pci_dev *dev, struct vm_area_struct *vma,
			enum pci_mmap_state mmap_state, int write_combine)
{
	return io_remap_pfn_range(vma, vma->vm_start,
				 vma->vm_pgoff,
				 vma->vm_end - vma->vm_start,
				 vma->vm_page_prot);
}

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
	if (remap_pfn_range(vma, vma->vm_start, vma->vm_pgoff,
			    size, vma->vm_page_prot))
		return -EAGAIN;
	return 0;
}

/**
 * ia64_pci_legacy_read - read from legacy I/O space
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
		*((u8 *)val) = inb(BASE_PCIIO + port);
		break;
	case 2:
		*((u16 *)val) = inw(BASE_PCIIO + port);
		break;
	case 4:
		*((u32 *)val) = inl(BASE_PCIIO + port);
		break;
	default:
		ret = -EINVAL;
		break;
	}
	return ret;
}

/**
 * ia64_pci_legacy_write - perform a legacy I/O write
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
		outb(val, BASE_PCIIO + port);
		break;
	case 2:
		outw(val, BASE_PCIIO + port);
		break;
	case 4:
		outl(val, BASE_PCIIO + port);
		break;
	default:
		ret = -EINVAL;
		break;
	}

	return ret;
}
#endif	/*HAVE_PCI_LEGACY*/

#ifdef CONFIG_NUMA
int pcibus_to_node(struct pci_bus *pbus)
{
	return __pcibus_to_node(pbus);
}
EXPORT_SYMBOL(pcibus_to_node);
#endif

static int __init pci_direct_init(void)
{
	pci_probe = PCI_PROBE_L;
	return l_pci_direct_init();
}

arch_initcall(pci_direct_init);
