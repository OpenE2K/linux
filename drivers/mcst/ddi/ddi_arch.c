/*
 * Arch depended part of ddi_support
 * 
 * Supported by Alexey V. Sitnikov, alexmipt@mcst.ru, MCST
 *
 */

#include <linux/mcst/ddi.h>
#include <asm/uaccess.h>
#include <asm/pgtable.h>
#include <asm/io.h>
#include <asm/dma.h>
#include <linux/pci.h>
#include <linux/slab.h>
#include <linux/mcst/pci_dev_info.h>
#include <linux/interrupt.h>

#define	DBG_MODE 0
#define	dbgddi	if (DBG_MODE) printk

typedef struct sbus_dev sbus_dev_t;
typedef struct pci_dev pci_dev_t;

struct pci_dev_info pci_dev_info[MCST_MAX_DRV]	=  {
	MCST_DEVICE_DRIVERS
};

unsigned int
_ddi_read_long(int t, ulong_t *p)
{
	dbgddi("ddi_read_long: start\n");
	if (t == DDI_SBUS_SPARC) {
#if defined(CONFIG_SBUS) 
		return (sbus_readl((const volatile void __iomem *)p));
#elif IS_ENABLED(CONFIG_PCI2SBUS)
		return (my_sbus_readl((long)p));
#else
		printk("_ddi_read_long: Unconfigured dev_type = %d\n", t);
		return 0;
#endif /* CONFIG_SBUS */

	} else if (t == DDI_PCI_SPARC)	{
#ifdef CONFIG_PCI
		return (readl((const volatile void __iomem *)p));
#else
		printk("_ddi_read_long: Unconfigured dev_type = %d\n", t);
		return 0;
#endif /* CONFIG_PCI */
	} else {
		printk("_ddi_read_long: Unknown dev_type = %d\n", t);
		return 0;
	}
}
 
unsigned int
_ddi_write_long(int t, ulong_t *p, ulong_t b)
{
	int v;
	dbgddi("ddi_write_long: start, addr = 0x%lx, val = 0x%lx\n", (unsigned long)p, b);
	v = b & 0xFFFFFFFF;
	if (t == DDI_SBUS_SPARC) {
#if defined(CONFIG_SBUS) 
		sbus_writel(b, (volatile void __iomem *)p);
#elif IS_ENABLED(CONFIG_PCI2SBUS)
		my_sbus_writel(b, (long)p);
#else
		printk("_ddi_write_long: Unconfigured dev_type = %d\n", t);
		return 0;
#endif /* CONFIG_SBUS */
	} else if (t == DDI_PCI_SPARC)	{
#ifdef CONFIG_PCI
		writel(b, (volatile void __iomem *)p);
#else
		printk("_ddi_write_long: Unconfigured dev_type = %d\n", t);
		return 0;
#endif /* CONFIG_PCI */
	}else {
		printk("_ddi_write_long: Unknown dev_type = %d\n", t);
		return 0;
	}
	return 1;
}

extern int curr_drv_nr;

extern char *ddi_drivers[];
extern char *ddi_drv_dir[];
extern unsigned short ddi_vendors[];
extern unsigned short ddi_devices[];

/* dma_memory - О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
dma_addr_t 
ddi_dev_map_mem(struct device *dev, size_t size, unsigned long dma_memory)
{
//      dma_addr_t mem;
	dbgddi("** ddi_dev_map_mem: start **\n");
//		mem = sbus_map_single(dev, (void *)dma_memory, size, SBUS_DMA_FROMDEVICE);
//		mem = pci_map_single(dev, (void *)dma_memory, size, PCI_DMA_FROMDEVICE);
	dbgddi("** ddi_dev_map_mem: finish **\n");
//	return mem;
	return 0;
}

int
_ddi_dma_sync(struct device *dev, dma_addr_t addr, size_t size, int direction)
{
	dbgddi("** ddi_dma_sync: start **\n");
	dma_sync_single_for_cpu(dev, addr, size, direction);
	dbgddi("** ddi_dma_sync: finish **\n");
	return 0;
}

dma_addr_t
ddi_dev_alloc_mem(struct device *dev, size_t size, unsigned long *va)
{
	dma_addr_t	mem;

	dbgddi("** ddi_dev_alloc_mem: start **\n");
	*va = (unsigned long)dma_alloc_coherent(dev, size, &mem, GFP_DMA);
	dbgddi("** ddi_dev_alloc_mem: finish **\n");
	return mem;
}

void
ddi_dev_free_mem(struct device *dev, size_t size, unsigned long va, dma_addr_t dma_addr)
{
	dbgddi("** ddi_dev_free_mem: start **\n");
	dbgddi("** ddi_dev_free_mem: dma_addr = 0x%lx, va = 0x%lx **\n", 
			(unsigned long)dma_addr, (unsigned long)va);

        dma_free_coherent(dev, size, (void *)va, dma_addr);
	dbgddi("** ddi_dev_free_mem: finish **\n");
	return;
}

/* dev_memory - О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
/* dma_memory - О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫ О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫О©╫ */
void
ddi_dev_unmap_mem(struct device *dev, size_t size, unsigned long dma_memory, dma_addr_t dev_memory)
{
	dbgddi("** ddi_dev_unamp_mem: start **\n");
//		sbus_unmap_single(dev, dev_memory, size, SBUS_DMA_FROMDEVICE);
//		pci_unmap_single(dev, dev_memory, size, PCI_DMA_FROMDEVICE);
	dbgddi("** ddi_dev_unamp_mem: dev_memory = 0x%lx, dma_memory = 0x%lx **\n",
		 (unsigned long)dev_memory, (unsigned long)dma_memory);

	dbgddi("** ddi_dev_unmap_mem: finish **\n");
	return;
}

int
ddi_get_order(size_t sz)
{
	dbgddi("ddi_get_order: start\n");
	return(get_order(sz));
}

