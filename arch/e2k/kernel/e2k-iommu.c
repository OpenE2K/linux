#define DEBUG
#include <linux/dma-mapping.h>
#include <linux/err.h>
#include <linux/io.h>
#include <linux/iommu.h>
#include <linux/interrupt.h>
#include <linux/list.h>
#include <linux/pm_runtime.h>
#include <linux/slab.h>
#include <linux/dma-iommu.h>
#include <linux/iova.h>
#include <linux/syscore_ops.h>
#include <linux/pci.h>
#include <linux/kvm_host.h>

#include <asm/sic_regs.h>
#include <asm/io_epic.h>
#include <asm/e2k-iommu.h>
#include <asm-l/swiotlb.h>
#include <trace/events/iommu.h>

#define E2K_DTE_MAX_BUS_NR	(1 << 8)
#define E2K_DTE_ENTRIES_NR	(E2K_DTE_MAX_BUS_NR * 256)
#define E2K_MAX_DOMAIN_ID	(1 << 12)

struct dte {
/* P - DTE tanslation validity */
	unsigned long h_present : 1;
/*
 * Host Translation Enable - whether to allow DMA request translation
 * to HPA space, when HTE = 0 all DMA requests from this device will
 * use physical addresses
 */
	unsigned long h_enable : 1;
/*
 * Host Translation Caching Enable
 */
	unsigned long h_cached : 1;
/*
 * Prefetch Buffer Enable - prefetch enabled for this device, see chapter 5.7.1.
 */
	unsigned long h_prefetch : 1;
	long reserved1 : 5;
/*
 * Host Virtual Address Width - VA width in native mode and GPA width in
 * guest virtual mode:
 */
#define	E2K_DTE_HVAW_30_BITS	1
#define	E2K_DTE_HVAW_39_BITS	2
#define	E2K_DTE_HVAW_48_BITS	3
	long h_addr_width : 3;
/*
 * Host Page Table Pointer - page table root in native mode,
 * and also PT second level root in guest virtual mode
 */
	long h_page_table : 36;
	long reserved2 : 16;

	unsigned long reserved3 : 1;
/*
 * Guest Translation Enable - whether to allow translation of DMA requests,
 * when GTE = 0 all DMA requests of this device will be blocked
 */
	unsigned long g_enable : 1;
/*
 * Guest Translation Caching Enable
 */
	unsigned long g_cached : 1;
	long reserved4 : 6;

/*
 * Guest Virtual Address Width - VA width in native mode and GPA width
 * in guest virtual mode:
 */
	long g_addr_width : 3;

/*
 * Guest Page Table Pointer - page table root in native mode
 * and also PT second level root in guest virtual mode
 */
	long g_page_table : 36;
	long reserved5 : 16;

/*
 * Interrupt Enable - enable receiving interrupts from this device
 */
	unsigned long int_enable : 1;
	long reserved6 : 11;
/*
 * Guest Interrupt Table Pointer - address of structure for guest interrupts bookkeeping
 */
	long int_table : 36;
	long reserved7 : 16;

	long reserved8 : 16;
/*
 * EDID.did:
 * Domain ID in native mode
 * or
 * Guest ID in passthrough mode
 */
	long id : 12;
/*
 * EDID.g:
 * 0 - native mode
 * 1 - passthrough mode
 */
	unsigned long guest : 1;
	long reserved9 : 3;

/*
 * Guest Emulated Version Number - version of IOMMU that guest OS uses
 */
#define	E2K_DTE_E8C_VERSION	1
#define	E2K_DTE_E8C2_VERSION	2
#define	E2K_DTE_E8C16_VERSION	3
	long g_iommu_version : 4;
	long reserved10 : 28;
} __packed;

#define IO_PTE_PRESENT	(1 << 0)
#define IO_PTE_WRITE	(1 << 1)
#define IO_PTE_READ	(1 << 2)
#define IO_PTE_PREFETCH	(1 << 3)
#define IO_PTE_PAGE_SIZE	(1 << 7)


#define IO_PAGE_SHIFT		12
#define IO_PAGE_SIZE			(1UL << IO_PAGE_SHIFT)
#define IO_PAGE_MASK			(~(IO_PAGE_SIZE-1))
#define IO_PAGE_ALIGN(addr)		ALIGN(addr, IO_PAGE_SIZE)


#define E2K_IOMMU_MAX_LEVELS		4
#define E2K_IOMMU_START_LVL()		0

#define E2K_IOMMU_GRANULE()		IO_PAGE_SIZE

static int e2k_iommu_no_domains = 0;
static struct iommu_ops e2k_iommu_ops;
typedef u64 io_pte;


/* IOPTE accessors */
#define iopte_deref(pte)	__va(iopte_to_pa(pte))

#define iopte_leaf(pte)	(pte & IO_PTE_PAGE_SIZE)
#define iopte_present(pte)	(pte & IO_PTE_PRESENT)

#define pa_to_iopte(addr) ((io_pte)(addr & IO_PAGE_MASK))
#define iopte_to_pa(iopte) ((phys_addr_t)(iopte) & IO_PAGE_MASK)

#define E2K_IOMMU_PER_LEVEL_SHIFT ilog2(E2K_IOMMU_GRANULE() / sizeof(io_pte))
#define E2K_IOMMU_PER_LEVEL_MASK (~((1 << E2K_IOMMU_PER_LEVEL_SHIFT) - 1))

#define E2K_IOMMU_LVL_SHIFT(lvl) \
	((E2K_IOMMU_MAX_LEVELS - (lvl + 1)) * E2K_IOMMU_PER_LEVEL_SHIFT)

#define E2K_IOMMU_LEVEL_SHIFT(lvl) (IO_PAGE_SHIFT + E2K_IOMMU_LVL_SHIFT(lvl))

#define E2K_IOMMU_LVL_IDX(addr,lvl) \
	((addr >> E2K_IOMMU_LEVEL_SHIFT(lvl)) & ~E2K_IOMMU_PER_LEVEL_MASK)

#define E2K_IOMMU_LEVEL_MASK(lvl) \
	(~((1UL << E2K_IOMMU_LEVEL_SHIFT(lvl)) - 1))

const long e2k_iommu_page_sizes[] = {
	-1, SZ_1G, SZ_2M, SZ_4K
};
#define E2K_IOMMU_PGSIZE(lvl)	e2k_iommu_page_sizes[lvl]

static io_pte e2k_iommu_prot_to_pte(int prot)
{
	io_pte pte = 0;
	if (prot & IOMMU_READ)
		pte |= IO_PTE_READ;

	if (prot & IOMMU_WRITE)
		pte |= IO_PTE_WRITE;
	return pte;
}

struct e2k_iommu {
	struct dte *dtable;
	io_pte	*pgtable;
	spinlock_t lock;
	int node;
	struct iommu_group *default_group;
	struct iommu_device iommu;	/* IOMMU core handle */
};

struct e2k_iommu_domain {
	struct mutex mutex;
	io_pte	*pgtable;
	struct e2k_iommu *e2k_iommu;
	int id;

	struct iommu_domain domain; /* generic domain data structure */
};

static struct e2k_iommu_domain *to_e2k_domain(struct iommu_domain *dom)
{
	return container_of(dom, struct e2k_iommu_domain, domain);
}

static struct e2k_iommu *dev_to_iommu(struct device *dev)
{
	struct iohub_sysdata *sd;

	if(WARN_ON(!dev))
		return NULL;
	if(WARN_ON(!dev_is_pci(dev)))
		return NULL;

	sd = to_pci_dev(dev)->bus->sysdata;

	return sd->l_iommu;
}

static u16 to_sid(int bus, int slot, int func)
{
	return (bus << 8) | (slot << 3) | func;
}

static u16 dev_to_sid(struct device *dev)
{
	int bus = to_pci_dev(dev)->bus->number;
	int devfn = to_pci_dev(dev)->devfn;
	return to_sid(bus, PCI_SLOT(devfn), PCI_FUNC(devfn));
}

static struct dte *dev_to_dte(struct e2k_iommu *i, struct device *dev)
{
	if (i->dtable)
		return i->dtable + dev_to_sid(dev);
	return NULL;
}

#define E2K_IOMMU_CTRL		SIC_iommu_ctrl
# define IOMMU_CTRL_GT_EN		(1 << 13)
# define IOMMU_CTRL_DEV_TABLE_EN	(1 << 12)
# define IOMMU_CTRL_NEW_VERS		(3 <<  8)
# define IOMMU_CTRL_PREFETCH_EN		0x00000040	/* enable prefeth TTE */
# define IOMMU_CTRL_CASHABLE_TTE	0x00000020	/* Cachable TTE */
# define IOMMU_CTRL_ENAB		0x00000001	/* IOMMU Enable */
#define E2K_IOMMU_PTBAR		SIC_iommu_ba_lo
# define IOMMU_PTBAR_DFLT_SZ		(3 << 9) /* 48-bit */
# define IOMMU_PTBAR_PREFETCH_EN	(1 << 2) /* enable prefeth TTE */
# define IOMMU_PTBAR_CASHABLE_TTE	(1 << 1)
# define IOMMU_PTBAR_PRESENT		(1 << 0)

#define E2K_IOMMU_DTBAR		SIC_iommu_dtba_lo
# define IOMMU_DTBAR_DFLT_SZ	(E2K_DTE_MAX_BUS_NR << 2)
# define IOMMU_DTBAR_CASHABLE_DTE	(1 << 1)
# define IOMMU_DTBAR_PRESENT	(1 << 0)

#define E2K_IOMMU_CMD		SIC_iommu_cmd_c_lo
# define E2K_IOMMU_CMD_ERR	2
# define E2K_IOMMU_CMD_RUN	1
# define FL_ALL 0 /*Flush All*/
# define FL_ID  1 /*Flush Guest/Domain*/
# define FL_SID 3 /*Flush Device*/
# define FL_PTE 4 /* Flush virtual page of guest or hypervisor */
# define FL_PDE 5 /* Flush intermediate translations */
# define FL_SLPDE 0x06 /* Flush GPA -> HPA translation */
# define FL_DTE 0x07 /* Flush Device Table row */
# define FL_TLB 0x08 /*Flush TLB*/
# define FL_TLU 0x09 /*Flush TLU*/
# define FL_SLTLU 0x0a /*Flush SLTLU*/
# define FL_DTLB 0x0b /*Flush DTLB*/
# define DRA_PTE 0x10	/* Associative diagnostic read of PTE from cache */
# define DRA_PDE 0x11	/* Associative diagnostic read of	*/
			/* intermediate translations from cache */
# define DRA_SLPDE 0x12	/* Associative diagnostic read of	*/
			/* GPA -> HPA translations from cache	*/
# define DRA_DTE 0x13	/* Associative diagnostic read of	*/
			/* Device Table row from cache		*/
# define DRND_PTE 0x14  /* Diagnostic read of TLB line data */
# define DRND_PDE 0x15  /* Diagnostic read of TLU line data */
# define DRND_SLPDE 0x16 /* Diagnostic read of SLTLU line data */
# define DRND_DTE 0x17  /* Diagnostic read of DTLB line data */
# define DRNT_PTE 0x18  /* Diagnostic read of TLB line tags */
# define DRNT_PDE 0x19  /* Diagnostic read of TLU line tags */
# define DRNT_SLPDE 0x1a /* Diagnostic read of SLTLU line tags */
# define DRNT_DTE 0x1b  /* Diagnostic read of DTLB line tags */


#define E2K_IOMMU_DATA		SIC_iommu_cmd_d_lo
#define E2K_IOMMU_ERR		SIC_iommu_err

#define	E2K_IOMMU_MMU_MISS		(1 << 0)
#define	E2K_IOMMU_PROT_VIOL_WR		(1 << 1)
#define	E2K_IOMMU_PROT_VIOL_RD		(1 << 2)
#define	E2K_IOMMU_MLT_HIT		(1 << 3)
#define	E2K_IOMMU_PTE_ERR		(1 << 4)
#define	E2K_IOMMU_ADDR_RANGE		(1 << 5)
#define	E2K_IOMMU_BUS_RANGE		(1 << 6)
#define	E2K_IOMMU_MSI			(1 << 7)
#define	E2K_IOMMU_CEP_OVERFLOW		(1 << 8)

#define E2K_IOMMU_ERR_INFO		SIC_iommu_err_info_lo
#define E2K_IOMMU_EDBC_OFFSET		(SIC_edbc_iommu_ctrl - SIC_iommu_ctrl)
#define E2K_IOMMU_EMBEDDED_OFFSET	(SIC_embedded_iommu_base - SIC_iommu_ctrl)
#define E2K_IOMMU_NR			SIC_e2c3_iommu_nr
#define E2K_IOMMU_EDID_GUEST_MASK	(1 << 12)

union iommu_cmd_c {
	u64	raw;
	struct {
		u64	rs		: 1,
			cs		: 1,
			__reserved1	: 2,
			code		: 5,
			__reserved2	: 3,
			addr		: 36,
			id		: 16;
	} __packed bits;
};

static u32 e2k_iommu_read(unsigned int node, int iommu, unsigned long addr)
{
	if (iommu) /* for embedded devices */
		addr += E2K_IOMMU_EMBEDDED_OFFSET +
				(iommu - 1) * SIC_iommu_reg_size;
	return sic_read_node_iolink_nbsr_reg(node, 0, addr);
}

static u64 e2k_iommu_readll(unsigned node, int iommu, unsigned long addr)
{
	if (iommu) /* for embedded devices */
		addr += E2K_IOMMU_EMBEDDED_OFFSET +
				(iommu - 1) * SIC_iommu_reg_size;
	return sic_readll_node_iolink_nbsr_reg(node, 0, addr);
}

static void e2k_iommu_write(unsigned node, u32 val, unsigned long addr)
{
	sic_write_node_iolink_nbsr_reg(node, 0, addr, val);
	/* for embedded devices */
	sic_write_node_iolink_nbsr_reg(node, 0,
					addr + E2K_IOMMU_EDBC_OFFSET, val);
}

static void e2k_iommu_writell(unsigned node, u64 val, unsigned long addr)
{
	sic_writell_node_iolink_nbsr_reg(node, 0, addr, val);
	/* for embedded devices */
	sic_writell_node_iolink_nbsr_reg(node, 0,
					addr + E2K_IOMMU_EDBC_OFFSET, val);
}

static void e2k_iommu_flush(struct e2k_iommu *i, u64 iova, u64 id, u64 cmd)
{
	u64 v = (iova & IO_PAGE_MASK) | (cmd << 4) |
				(id << 48) | E2K_IOMMU_CMD_RUN;
	e2k_iommu_writell(i->node, v, E2K_IOMMU_CMD);
}

static void e2k_iommu_flush_dev(struct e2k_iommu *i, struct device *dev)
{
	e2k_iommu_flush(i, 0, dev_to_sid(dev), FL_SID);
}

static void e2k_iommu_flush_pte(struct e2k_iommu_domain *d, u64 iova)
{
	e2k_iommu_flush(d->e2k_iommu, iova, d->id, FL_PTE);
	trace_flush(d->id, iova);
}

static void e2k_iommu_flush_pde(struct e2k_iommu_domain *d, u64 iova, int lvl)
{
	iova &= E2K_IOMMU_LEVEL_MASK(lvl);
	iova |= (~E2K_IOMMU_LEVEL_MASK(lvl)) >> 1;
	e2k_iommu_flush(d->e2k_iommu, iova, d->id, FL_PDE);
}

static void e2k_iommu_flush_domain(struct e2k_iommu_domain *d)
{
	e2k_iommu_flush(d->e2k_iommu, 0, d->id, FL_ID);
}

static void e2k_iommu_flush_all(struct e2k_iommu *i)
{
	e2k_iommu_flush(i, 0, 0, FL_ALL);
}

void e2k_iommu_flush_page(struct device *dev,
			  const void *virt, phys_addr_t phys)
{
	struct e2k_iommu_domain *d =
			 to_e2k_domain(iommu_get_domain_for_dev(dev));
	e2k_iommu_flush_pte(d, (unsigned long)virt);
}
static void __e2k_iommu_free_pgtable(struct e2k_iommu_domain *d,
				unsigned long iova, int lvl, io_pte *ptep);

static void e2k_iommu_init_hw(struct e2k_iommu *i)
{
	int node = i->node;
	u64 d = __pa(i->dtable) | IOMMU_DTBAR_PRESENT |
			IOMMU_DTBAR_CASHABLE_DTE | IOMMU_DTBAR_DFLT_SZ;
	u64 p = __pa(i->pgtable) | IOMMU_PTBAR_PRESENT |
			IOMMU_PTBAR_CASHABLE_TTE | IOMMU_PTBAR_DFLT_SZ;
	u32 c = IOMMU_CTRL_NEW_VERS | IOMMU_CTRL_PREFETCH_EN |
			 IOMMU_CTRL_CASHABLE_TTE | IOMMU_CTRL_ENAB;

	if (i->dtable) {
		p = 0;
		c |= IOMMU_CTRL_DEV_TABLE_EN;
	} else {
		d = 0;
	}
	e2k_iommu_write(node, 0, E2K_IOMMU_CTRL);
	/* clear errors & unmask interrupts */
	e2k_iommu_writell(node, 0, E2K_IOMMU_ERR);
	e2k_iommu_flush_all(i);

	e2k_iommu_writell(node, p, E2K_IOMMU_PTBAR);
	e2k_iommu_writell(node, d, E2K_IOMMU_DTBAR);
	e2k_iommu_write  (node, c, E2K_IOMMU_CTRL);
	/* enable error sending to device */
	c = sic_read_node_nbsr_reg(node, SIC_hc_ctrl);
	sic_write_node_nbsr_reg(node, SIC_hc_ctrl, c | 1);
}

static void *__e2k_iommu_alloc_pages(size_t size, gfp_t gfp, int node)
{
	int order = get_order(size);
	struct page *page = alloc_pages_node(node,
				GFP_ATOMIC | __GFP_ZERO, order);
	if (!page)
		return NULL;

	return page_address(page);
}

static void __e2k_iommu_free_pages(void *pages, size_t size)
{
	free_pages((unsigned long)pages, get_order(size));
}

static struct e2k_iommu *__e2k_iommu_init(int node, struct device *parent)
{
	struct e2k_iommu *i;
	if (node < 0)
		node = 0;

	i = kzalloc_node(sizeof(*i), GFP_KERNEL, node);
	if (!i)
		return i;

	if (e2k_iommu_no_domains) {
		i->pgtable = __e2k_iommu_alloc_pages(E2K_IOMMU_GRANULE(),
					     GFP_KERNEL, i->node);
	} else {
		i->dtable = __e2k_iommu_alloc_pages(E2K_DTE_ENTRIES_NR *
					sizeof(struct dte), GFP_KERNEL, node);
	}
	if (!i->pgtable && !i->dtable)
		goto fail;

	i->node = node;
	spin_lock_init(&i->lock);

	iommu_device_sysfs_add(&i->iommu, parent, NULL, "iommu%d", node);
	iommu_device_set_ops(&i->iommu, &e2k_iommu_ops);
	iommu_device_register(&i->iommu);
	e2k_iommu_init_hw(i);
	return i;
fail:
	kfree(i);
	return NULL;
}

static void __e2k_iommu_set_pte(io_pte *ptep, io_pte pte)
{
	*ptep = pte;
}

static int e2k_iommu_init_pte(struct e2k_iommu_domain *d, unsigned long iova,
			phys_addr_t paddr, io_pte prot, int lvl, io_pte *ptep)
{
	io_pte pte = pa_to_iopte(paddr) |  prot |
				IO_PTE_PRESENT | IO_PTE_PAGE_SIZE;
	io_pte old = *ptep;
	if (iopte_leaf(old)) {
		/* We require an unmap first */
		WARN_ON(1);
		return -EEXIST;
	} else if (iopte_present(old)) {
		/*
		 * We need to unmap and free the old table before
		 * overwriting it with a block entry.
		 */
		__e2k_iommu_set_pte(ptep, 0);
		__e2k_iommu_free_pgtable(d, iova, lvl + 1, iopte_deref(old));
	}
	__e2k_iommu_set_pte(ptep, pte);
	return 0;
}

static int __e2k_iommu_map(struct e2k_iommu_domain *d, unsigned long iova,
				phys_addr_t paddr, size_t size, io_pte prot,
					int lvl, io_pte *ptep)
{
	io_pte *cptep, pte;
	size_t page_size = E2K_IOMMU_PGSIZE(lvl);

	/* Find our entry at the current level */
	ptep += E2K_IOMMU_LVL_IDX(iova, lvl);

	/* If we can install a leaf entry at this level, then do so */
	if (size == page_size)
		return e2k_iommu_init_pte(d, iova, paddr, prot, lvl, ptep);

	/* We can't allocate tables at the final level */
	if (WARN_ON(lvl >= E2K_IOMMU_MAX_LEVELS - 1))
		return -EINVAL;

	/* Grab a pointer to the next level */
	pte = *ptep;
	if (!pte) {
		io_pte oldpte;
		cptep = __e2k_iommu_alloc_pages(E2K_IOMMU_GRANULE(),
					       GFP_ATOMIC, d->e2k_iommu->node);
		if (!cptep)
			return -ENOMEM;

		pte = pa_to_iopte(__pa(cptep)) | IO_PTE_READ | IO_PTE_PRESENT;
		oldpte = cmpxchg64(ptep, 0ULL, pte);
		if (oldpte) { /* Someone else set it while we were thinking;
				use theirs. */
			__e2k_iommu_free_pages(cptep, E2K_IOMMU_GRANULE());
			pte = oldpte;
		}
	} else if (iopte_leaf(pte)) {
		/* We require an unmap first */
		WARN_ON(1);
		return -EEXIST;
	}
	cptep = iopte_deref(pte);

	return __e2k_iommu_map(d, iova, paddr, size, prot, lvl + 1, cptep);
}

static void __e2k_iommu_free_pgtable(struct e2k_iommu_domain *d,
				unsigned long iova, int lvl, io_pte *ptep)
{
	io_pte *start, *end;
	unsigned long table_size = E2K_IOMMU_GRANULE();

	start = ptep;

	/* Only leaf entries at the last level */
	if (lvl == E2K_IOMMU_MAX_LEVELS - 1)
		end = ptep;
	else
		end = (void *)ptep + table_size;

	while (ptep != end) {
		io_pte pte = *ptep++;

		if (!pte || WARN_ON(iopte_leaf(pte)))
			continue;

		__e2k_iommu_free_pgtable(d, iova, lvl + 1, iopte_deref(pte));
	}
	e2k_iommu_flush_pde(d, iova, lvl);
	__e2k_iommu_free_pages(start, table_size);
}

static size_t __e2k_iommu_unmap(struct e2k_iommu_domain *d, unsigned long iova,
					size_t size, int lvl, io_pte *ptep)
{
	io_pte pte;
	size_t page_size = E2K_IOMMU_PGSIZE(lvl);

	/* Something went horribly wrong and we ran out of page table */
	if (WARN_ON(lvl == E2K_IOMMU_MAX_LEVELS))
		return 0;

	ptep += E2K_IOMMU_LVL_IDX(iova, lvl);
	pte = *ptep;
	if (WARN_ON(!pte))
		return 0;

	/* If the size matches this level, we're in the right place */
	if (size == page_size) {
		__e2k_iommu_set_pte(ptep, 0);
		if (!iopte_leaf(pte)) {
			__e2k_iommu_free_pgtable(d, iova,
					lvl + 1, iopte_deref(pte));
			e2k_iommu_flush_domain(d);
		}
		return size;
	} else if (iopte_leaf(pte)) {
		WARN_ON(1);
		return 0;
	}

	/* Keep on walkin' */
	ptep = iopte_deref(pte);
	return __e2k_iommu_unmap(d, iova, size, lvl + 1, ptep);
}

static phys_addr_t __e2k_iommu_iova_to_phys(io_pte *pgtable, dma_addr_t iova,
							io_pte *pout)
{
	io_pte pte, *ptep = pgtable;
	int lvl = E2K_IOMMU_START_LVL();
	if (pout)
		*pout = 0;

	do {
		/* Valid IOPTE pointer? */
		if (!ptep)
			return 0;

		/* Grab the IOPTE we're interested in */
		pte = *(ptep + E2K_IOMMU_LVL_IDX(iova, lvl));

		/* Valid entry? */
		if (!pte)
			return 0;

		/* Leaf entry? */
		if (iopte_leaf(pte))
			goto found_translation;

		/* Take it to the next level */
		ptep = iopte_deref(pte);
	} while (++lvl < E2K_IOMMU_MAX_LEVELS);

	/* Ran out of page tables to walk */
	return 0;

found_translation:
	if (pout)
		*pout = pte;
	return iopte_to_pa(pte) + iova % E2K_IOMMU_PGSIZE(lvl);
}

static void __e2k_iommu_error_interrupt(char *str, int len, int iommu,
			u64 err, u64 err_i, struct dte *dte, io_pte *pgtable)
{
	int node = numa_node_id();
	io_pte pte;
	int cpu = smp_processor_id(), s;
	char *e;
	dma_addr_t iova;
	int bus, slot, func;

	if (node < 0)
		node = 0;

	iova = err_i & IO_PAGE_MASK & ((1UL << 48) - 1);
	bus  = (err_i >> (8 + 48)) & 0xff;
	slot = (err_i >> (3 + 48)) & 0x1f,
	func = (err_i >> (0 + 48)) & 0x07;

	e =	  err & E2K_IOMMU_MMU_MISS	? "Page miss"
		: err & E2K_IOMMU_PROT_VIOL_WR	? "Write protection error"
		: err & E2K_IOMMU_PROT_VIOL_RD	? "Read protection error"
		: err & E2K_IOMMU_PTE_ERR	? "PTE Error"
		: err & E2K_IOMMU_ADDR_RANGE	? "Address Range Violation"
		: err & E2K_IOMMU_BUS_RANGE	? "Bus Range Violation"
		: err & E2K_IOMMU_MSI		? "MSI Protection"
		: err & E2K_IOMMU_CEP_OVERFLOW	? "CEP overflow"
		: "Unknown error";

	s = snprintf(str, len, "IOMMU:%d:%d: error on cpu %d:\n"
		       "\t%s at address 0x%llx "
			"(device: %02x:%02x.%d, error regs:%llx,%llx).\n",
			node, iommu, cpu,
			e, iova,
			bus, slot, func,
			err, err_i);
	if (dte) {
		dte += to_sid(bus, slot, func);
		pgtable = dte->h_page_table ?
			 __va(dte->h_page_table << IO_PAGE_SHIFT) :
			NULL;
	}
	if (pgtable) {
		__e2k_iommu_iova_to_phys(pgtable, iova, &pte);
		s += snprintf(str + s, len - s, "\t pte:%08llx -> pa:%08llx\n",
				(u64)(pte), iopte_to_pa(pte));
	}
}

void e2k_iommu_error_interrupt(void)
{
	int node = numa_node_id(), i;
	char str[1024];

	if (node < 0)
		node = 0;

	for (i = 0; i < E2K_IOMMU_NR; i++) {
		u64 err   = e2k_iommu_readll(node, i, E2K_IOMMU_ERR);
		u64 err_i = e2k_iommu_readll(node, i, E2K_IOMMU_ERR_INFO);
		struct dte *dte = __va(e2k_iommu_readll(node, i,
				       E2K_IOMMU_DTBAR) & IO_PAGE_MASK);
		io_pte *pte = __va(e2k_iommu_readll(node, i, E2K_IOMMU_PTBAR) &
						IO_PAGE_MASK);
		if (err == 0 || err == ~0ULL)
			continue;
		if (e2k_iommu_no_domains)
			dte = NULL;
		__e2k_iommu_error_interrupt(str, sizeof(str), i, err, err_i,
			dte, pte);
		e2k_iommu_writell(node, err, E2K_IOMMU_ERR);
		break;
	}

	debug_dma_dump_mappings(NULL);

	if (iommu_panic_off)
		pr_emerg("%s", str);
	else
		panic(str);
}

void e2k_iommu_virt_enable(int node)
{
	unsigned int val;

	pr_info("e2k_iommu: enabling virtualization support (node %d)\n", node);

	val = e2k_iommu_read(node, 0, E2K_IOMMU_CTRL);
	if (!(val & IOMMU_CTRL_GT_EN)) {
		val |= IOMMU_CTRL_GT_EN;
		e2k_iommu_write(node, val, E2K_IOMMU_CTRL);
	}

}

/* Handle intercepted guest writes and reads */
void e2k_iommu_guest_write_ctrl(u32 reg_value)
{
	if (reg_value & IOMMU_CTRL_ENAB)
		pr_info("e2k_iommu: guest enabled IOMMU support %s\n",
			reg_value & IOMMU_CTRL_DEV_TABLE_EN ?
			"with device table enabled: passthrough not supported" :
			"with device table disabled: passthrough supported");
}

/* Enable second level of DMA translation */
void e2k_iommu_setup_guest_2d_dte(struct kvm *kvm, u64 g_page_table)
{
	struct irq_remap_table *irt = kvm->arch.irt;
	struct device *dev;
	struct e2k_iommu *iommu;
	struct e2k_iommu_domain *domain;
	struct dte *dte_old, dte_new;
	unsigned long flags;

	dev = &irt->vfio_dev->dev;
	iommu = dev_to_iommu(dev);
	domain = to_e2k_domain(iommu_get_domain_for_dev(dev));
	dte_old = dev_to_dte(iommu, dev);

	memcpy(&dte_new, dte_old, sizeof(struct dte));

	dte_new.g_enable = 1;
	dte_new.g_cached = 1;
	dte_new.g_addr_width = E2K_DTE_HVAW_48_BITS;
	dte_new.g_page_table = g_page_table >> IO_PAGE_SHIFT;

	spin_lock_irqsave(&iommu->lock, flags);

	memcpy(dte_old, &dte_new, sizeof(struct dte));

	spin_unlock_irqrestore(&iommu->lock, flags);

	e2k_iommu_flush_domain(domain);
}

void e2k_iommu_flush_guest(struct kvm *kvm, u64 command)
{
	struct irq_remap_table *irt = kvm->arch.irt;
	u32 edid = (u32) kvm->arch.vmid.nr | E2K_IOMMU_EDID_GUEST_MASK;
	struct device *dev;
	struct e2k_iommu *iommu;
	union iommu_cmd_c reg;

	dev = &irt->vfio_dev->dev;
	iommu = dev_to_iommu(dev);

	reg.raw = command;

	if (!reg.bits.rs) {
		pr_err("e2k_iommu: ignore guests's command without cmd_c.rs\n");
		return;
	}

	switch (reg.bits.code) {
	case FL_PTE:
		e2k_iommu_flush(iommu, reg.bits.addr << IO_PAGE_SHIFT, edid,
			FL_PTE);
		break;
	case FL_ALL:
		e2k_iommu_flush(iommu, 0, edid, FL_ID);
		break;
	default:
		pr_err("e2k_iommu: ignore unsupported guest's command %d\n",
			reg.bits.code);
		break;
	}
}

#ifdef CONFIG_PM
static int e2k_iommu_suspend(void)
{
	return 0;
}

static void e2k_iommu_resume(void)
{
	//TODO
}

static struct syscore_ops e2k_iommu_syscore_ops = {
	.resume		= e2k_iommu_resume,
	.suspend	= e2k_iommu_suspend,
};

static void __init e2k_iommu_init_pm_ops(void)
{
	register_syscore_ops(&e2k_iommu_syscore_ops);
}

#else
static void e2k_iommu_init_pm_ops(void) {}
#endif	/* CONFIG_PM */
#if defined CONFIG_IOMMU_DEBUGFS

#include <linux/debugfs.h>
#include <linux/seq_file.h>


static void e2k_iommu_wr(int node, u64 iova, u64 id, u64 cmd)
{
	u64 v = (iova & IO_PAGE_MASK) | (cmd << 4) |
				(id << 48) | E2K_IOMMU_CMD_RUN;
	e2k_iommu_writell(node, v, E2K_IOMMU_CMD);
}

static void e2k_iommu_read_tag_and_data(int node, int iommu, int line,
				u64 *tag, u64 *data)
{
	u64 v;
	e2k_iommu_wr(node, line, 0, DRNT_PTE);
	v = e2k_iommu_readll(node, iommu, E2K_IOMMU_CMD);
	if (v & E2K_IOMMU_CMD_ERR) { /*tag is not valid */
		*tag  = 0;
		*data = 0;
		return;
	}
	*tag = e2k_iommu_readll(node, iommu, E2K_IOMMU_DATA);
	e2k_iommu_wr(node, line, 0, DRND_PTE);
	*data = e2k_iommu_readll(node, iommu, E2K_IOMMU_DATA);
}

static int e2k_iommu_debugfs_show(struct seq_file *s, void *null)
{
	int n, i, l;
	for_each_online_node(n) {
	for (i = 0; i < E2K_IOMMU_NR; i++) {
		seq_printf(s, "iommu[%d][%d]: line, tag, data:\n", n, i);
	for (l = 0; l < 256; l++) {
		u64 tag, data;
		e2k_iommu_read_tag_and_data(n, i, l << (12 + 4), &tag, &data);
		if (tag & 0xff && !(data & 1))
			continue;
		seq_printf(s, "% 2x: %016llx %016llx\n", l, tag, data);
	}
	}
	}
	return 0;
}

static int e2k_iommu_debugfs_open(struct inode *inode, struct file *file)
{
	return single_open(file, e2k_iommu_debugfs_show, NULL);
}

static const struct file_operations e2k_iommu_debugfs_operations = {
	.open = e2k_iommu_debugfs_open,
	.read = seq_read,
	.llseek = seq_lseek,
	.release = single_release,
};
#endif /* CONFIG_IOMMU_DEBUGFS */

static int __init e2k_iommu_debugfs_init(void)
{
#if defined CONFIG_IOMMU_DEBUGFS
	struct dentry *dentry = debugfs_create_file("tlb", S_IFREG | S_IRUGO,
				iommu_debugfs_dir, NULL,
				&e2k_iommu_debugfs_operations);
	return IS_ERR(dentry) ? PTR_ERR(dentry) : 0;
#else /* CONFIG_IOMMU_DEBUGFS */
	return 0;
#endif /* CONFIG_IOMMU_DEBUGFS */
}

/* IOMMU API */
static int e2k_iommu_map(struct iommu_domain *iommu_domain,
			    unsigned long iova, phys_addr_t paddr, size_t size,
			    int iommu_prot)
{
	struct e2k_iommu_domain *d = to_e2k_domain(iommu_domain);

	io_pte *ptep = d->pgtable;
	int lvl = E2K_IOMMU_START_LVL();
	io_pte prot;

	if(WARN_ON(!IS_ALIGNED(paddr, size)))
		return -EINVAL;
	if(WARN_ON(!IS_ALIGNED(iova, size)))
		return -EINVAL;
	if(WARN_ON(size != SZ_4K && size != SZ_2M && size != SZ_1G))
		return -EINVAL;

	/* If no access, then nothing to do */
	if (!(iommu_prot & (IOMMU_READ | IOMMU_WRITE)))
		return 0;

	prot = e2k_iommu_prot_to_pte(iommu_prot);
	return __e2k_iommu_map(d, iova, paddr, size, prot, lvl, ptep);
}

static size_t e2k_iommu_unmap(struct iommu_domain *iommu_domain,
				unsigned long iova, size_t size,
     				struct iommu_iotlb_gather *gather)
{
	struct e2k_iommu_domain *d = to_e2k_domain(iommu_domain);
	size_t unmapped;
	io_pte *ptep = d->pgtable;
	int lvl = E2K_IOMMU_START_LVL();

	if(WARN_ON(!IS_ALIGNED(iova, size)))
		return 0;
	if(WARN_ON(size != SZ_4K && size != SZ_2M && size != SZ_1G))
		return 0;

	unmapped = __e2k_iommu_unmap(d, iova, size, lvl, ptep);
	if (unmapped > 0)
		e2k_iommu_flush_pte(d, iova);

	return unmapped;
}

static phys_addr_t e2k_iommu_iova_to_phys(struct iommu_domain *iommu_domain,
					  dma_addr_t iova)
{
	struct e2k_iommu_domain *d = to_e2k_domain(iommu_domain);
	return __e2k_iommu_iova_to_phys(d->pgtable, iova, NULL);
}

static void e2k_iommu_detach_device(struct iommu_domain *iommu_domain,
				    struct device *dev)
{
	struct e2k_iommu *i = dev_to_iommu(dev);
	struct e2k_iommu_domain *d = to_e2k_domain(iommu_domain);
	unsigned long flags;
	struct dte *dte;
	if (WARN_ON(!i))
		return;
	dev->archdata.iommu.domain = NULL;
	dte = dev_to_dte(i, dev);
	if (dte) {
		spin_lock_irqsave(&i->lock, flags);
		memset(dte, 0, sizeof(*dte));
		spin_unlock_irqrestore(&i->lock, flags);
	}
	e2k_iommu_flush_dev(i, dev);
}

static int e2k_iommu_attach_device(struct iommu_domain *iommu_domain,
				   struct device *dev)
{
	struct e2k_iommu *i = dev_to_iommu(dev);
	struct e2k_iommu_domain *d = to_e2k_domain(iommu_domain);
	unsigned long flags;
	struct dte *dte;
	struct dte dteval = {
		.h_present = 1,
		.h_enable = 1,
		.h_cached = 1,
		.h_prefetch = 1,
		.h_addr_width = E2K_DTE_HVAW_48_BITS,
		.h_page_table = __pa(d->pgtable) >> IO_PAGE_SHIFT,
		.int_enable = 1,
		.id = iommu_group_id(dev->iommu_group),
	};

	if (dev->archdata.iommu.domain)
		e2k_iommu_detach_device(&dev->archdata.iommu.domain->domain,
			dev);

	dev->archdata.iommu.domain = d;

	if (!i)
		return -EINVAL;


	dte = dev_to_dte(i, dev);

	mutex_lock(&d->mutex);
	if (!d->e2k_iommu) {
		d->e2k_iommu = i;
		d->pgtable = i->pgtable;

		if (iommu_domain->type == IOMMU_DOMAIN_UNMANAGED) {
			struct kvm *kvm = dev->archdata.iommu.kvm;
			unsigned long int_table;
			u32 edid;

			/* Should be initialized in kvm_setup_passthrough() */
			BUG_ON(!kvm);

			int_table = __pa(page_address(kvm->arch.epic_pages));
			edid = (u32) kvm->arch.vmid.nr |
				E2K_IOMMU_EDID_GUEST_MASK;

			e2k_iommu_virt_enable(i->node);
			dteval.int_table = int_table >> IO_PAGE_SHIFT;
			dteval.id = kvm->arch.vmid.nr;
			dteval.guest = 1;

			d->id = edid;
		} else {
			d->id = iommu_group_id(dev->iommu_group);
		}
	} else if (WARN_ON(d->e2k_iommu != i)) {
		mutex_unlock(&d->mutex);
		return -EINVAL;
	}

	if (!d->pgtable)
		d->pgtable = __e2k_iommu_alloc_pages(E2K_IOMMU_GRANULE(),
					     GFP_KERNEL, i->node);

	if (!d->pgtable) {
		mutex_unlock(&d->mutex);
		return -ENOMEM;
	}
	mutex_unlock(&d->mutex);

	dteval.h_page_table = __pa(d->pgtable) >> IO_PAGE_SHIFT;
	if (dte) {
		spin_lock_irqsave(&i->lock, flags);
		memcpy(dte, &dteval, sizeof(struct dte));
		spin_unlock_irqrestore(&i->lock, flags);
	}

	return 0;
}

static struct iommu_domain *__e2k_iommu_domain_alloc(unsigned type, int node)
{
	struct e2k_iommu_domain *d = kzalloc_node(sizeof(*d), GFP_KERNEL, node);
	if (!d)
		return NULL;

	if (type == IOMMU_DOMAIN_DMA) {
		if (iommu_get_dma_cookie(&d->domain) != 0)
			goto err_pgtable;
	} else if (type != IOMMU_DOMAIN_UNMANAGED) {
		goto err_pgtable;
	}
	mutex_init(&d->mutex);
	d->domain.geometry.aperture_start = 0;
	d->domain.geometry.aperture_end   = (1UL << 48) - 1;
	d->domain.geometry.force_aperture = true;

	return &d->domain;

err_pgtable:
	kfree(d);
	return NULL;
}

static struct iommu_domain *e2k_iommu_domain_alloc(unsigned type)
{
		return __e2k_iommu_domain_alloc(type, -1);
}

static void e2k_iommu_domain_free(struct iommu_domain *iommu_domain)
{
	struct e2k_iommu_domain *d = to_e2k_domain(iommu_domain);
	io_pte *ptep = d->pgtable;

	iommu_put_dma_cookie(iommu_domain);
	__e2k_iommu_free_pgtable(d, 0, E2K_IOMMU_START_LVL(), ptep);

	if (!d->e2k_iommu || (d->e2k_iommu->pgtable != ptep))
		__e2k_iommu_free_pages(ptep, E2K_IOMMU_GRANULE());

	if (d->e2k_iommu)
		e2k_iommu_flush_domain(d);

	kfree(d);
}

static int e2k_iommu_add_device(struct device *dev)
{
	struct iommu_group *group = iommu_group_get_for_dev(dev);

	if (IS_ERR(group))
		return PTR_ERR(group);

	iommu_group_put(group);
	iommu_device_link(&dev_to_iommu(dev)->iommu, dev);
	iommu_setup_dma_ops(dev, 0, dma_get_mask(dev) + 1);

	return 0;
}

static void e2k_iommu_remove_device(struct device *dev)
{
	iommu_device_unlink(&dev_to_iommu(dev)->iommu, dev);
	iommu_group_remove_device(dev);
}

static struct iommu_group *e2k_iommu_device_group(struct device *dev)
{
	struct pci_dev *p = to_pci_dev(dev);
	struct e2k_iommu *i = dev_to_iommu(dev);

	if (i->default_group)
		return i->default_group;
	if (e2k_iommu_no_domains) {
		unsigned long flags;
		spin_lock_irqsave(&i->lock, flags);
		i->default_group = generic_device_group(dev);
		spin_unlock_irqrestore(&i->lock, flags);
		return i->default_group;
	}
	/* hw bug: ohci uses ehci device-id, so put them to one group */
	if (p->vendor == PCI_VENDOR_ID_MCST_TMP &&
			(p->device == PCI_DEVICE_ID_MCST_OHCI ||
			 p->device == PCI_DEVICE_ID_MCST_EHCI)) {
		struct pci_dev *pdev = pci_get_domain_bus_and_slot(
					pci_domain_nr(p->bus),
					p->bus->number,
					PCI_DEVFN(PCI_SLOT(p->devfn),
					PCI_FUNC(p->devfn) ^ 1));
		if (!pdev)
			return NULL;
		if (pdev->dev.iommu_group)
			return pdev->dev.iommu_group;
		else
			generic_device_group(dev);
	}
	return generic_device_group(dev);
}

static bool e2k_iommu_capable(enum iommu_cap cap)
{
	switch (cap) {
	case IOMMU_CAP_CACHE_COHERENCY:
		return true;
	case IOMMU_CAP_INTR_REMAP:
		return true; /* MSIs are just memory writes */
	case IOMMU_CAP_NOEXEC:
		return true;
	default:
		return false;
	}
}

#define VGA_MEMORY_OFFSET            0x000A0000
#define VGA_MEMORY_SIZE              0x00020000
#define RT_MSI_MEMORY_SIZE           0x100000	/* 1 Mb */
static void e2k_iommu_get_resv_regions(struct device *dev,
				      struct list_head *head)
{
	struct iommu_resv_region *region;
	int prot = IOMMU_WRITE | IOMMU_NOEXEC | IOMMU_MMIO;
	struct iohub_sysdata *sd;

	if(WARN_ON(!dev_is_pci(dev)))
		return;

	sd = to_pci_dev(dev)->bus->sysdata;

	if (!sd->pci_msi_addr_lo)
		return;

	region = iommu_alloc_resv_region(((u64)sd->pci_msi_addr_hi)
			<< 32 |	sd->pci_msi_addr_lo, RT_MSI_MEMORY_SIZE,
					prot, IOMMU_RESV_MSI);
	if (!region)
		return;
	list_add_tail(&region->list, head);

	region = iommu_alloc_resv_region(VGA_MEMORY_OFFSET, VGA_MEMORY_SIZE,
					 prot, IOMMU_RESV_RESERVED);
	if (!region)
		return;
	list_add_tail(&region->list, head);

	iommu_dma_get_resv_regions(dev, head);
}

static void e2k_iommu_put_resv_regions(struct device *dev,
				      struct list_head *head)
{
	struct iommu_resv_region *entry, *next;

	list_for_each_entry_safe(entry, next, head, list)
		kfree(entry);
}

static struct iommu_ops e2k_iommu_ops = {
	.map = e2k_iommu_map,
	.unmap = e2k_iommu_unmap,
	.iova_to_phys = e2k_iommu_iova_to_phys,

	.domain_alloc = e2k_iommu_domain_alloc,
	.domain_free = e2k_iommu_domain_free,
	.attach_dev = e2k_iommu_attach_device,
	.detach_dev = e2k_iommu_detach_device,
	.add_device = e2k_iommu_add_device,
	.remove_device = e2k_iommu_remove_device,
	.device_group = e2k_iommu_device_group,
	.capable = e2k_iommu_capable,

	.get_resv_regions	= e2k_iommu_get_resv_regions,
	.put_resv_regions	= e2k_iommu_put_resv_regions,

	.pgsize_bitmap = SZ_4K | SZ_2M | SZ_1G,
};

static int __init e2k_iommu_setup(char *str)
{
	if (!strcmp(str, "no-domains"))
		e2k_iommu_no_domains = 1;
	return 1;
}
__setup("e2k-iommu=", e2k_iommu_setup);

static int __init e2k_iommu_init(void)
{
	int ret;
	struct pci_bus *b;

	if (!HAS_MACHINE_E2K_IOMMU || l_use_swiotlb)
		return 0;

	BUILD_BUG_ON(sizeof(struct dte) != 32);

	list_for_each_entry(b, &pci_root_buses, node) {
		struct iohub_sysdata *sd;
		struct e2k_iommu *i;
		int node = 0;

		sd = b->sysdata;
#ifdef CONFIG_IOHUB_DOMAINS
		node = sd->node;
#endif
		i = __e2k_iommu_init(node, &b->dev);
		if (!i)
			return -ENOMEM;
		sd->l_iommu = i;
	}

	ret  = bus_set_iommu(&pci_bus_type, &e2k_iommu_ops);
	if (ret)
		return ret;
	e2k_iommu_init_pm_ops();
	e2k_iommu_debugfs_init();
	return ret;
}

/*
 * Needs to be done after pci initialization which are subsys_initcall.
 */
subsys_initcall_sync(e2k_iommu_init);
