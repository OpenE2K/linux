/* $Id: page.h,v 1.41 2009/07/24 12:02:54 kravtsunov_e Exp $
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef _E2K_PAGE_H
#define _E2K_PAGE_H

#include <linux/const.h>

#define IOREMAP_MAX_ORDER PMD_SHIFT
#define HAVE_ARCH_HUGETLB_UNMAPPED_AREA

#define	E2K_4K_PAGE_SHIFT		12		   /*  4 KBytes page */
#define	E2K_2M_PAGE_SHIFT		21		   /*  2 MBytes page */
#define	E2K_4M_PAGE_SHIFT		22		   /*  4 MBytes page */

#define	E2K_SMALL_PAGE_SHIFT		E2K_4K_PAGE_SHIFT  /*  4 KBytes page */

/* 
 * large page: 4MBytes for E2C+ and 2MBytes for others
 */

#define	E2K_LARGE_PAGE_SHIFT \
	(!cpu_has(CPU_FEAT_ISET_V3) ? E2K_4M_PAGE_SHIFT : E2K_2M_PAGE_SHIFT)

#define	BOOT_E2K_LARGE_PAGE_SHIFT \
	(!boot_cpu_has(CPU_FEAT_ISET_V3) ? E2K_4M_PAGE_SHIFT : E2K_2M_PAGE_SHIFT)

/*  4 KBytes page */
#define	PAGE_SHIFT			E2K_SMALL_PAGE_SHIFT

/*  large page    */
#define	LARGE_PAGE_SHIFT		E2K_LARGE_PAGE_SHIFT

#ifndef __ASSEMBLY__
#define	E2K_2M_PAGE_SIZE		(1UL << E2K_2M_PAGE_SHIFT)
#define	E2K_4M_PAGE_SIZE		(1UL << E2K_4M_PAGE_SHIFT)
#endif	/* !(__ASSEMBLY__) */

#define	E2K_SMALL_PAGE_SIZE		(1 << E2K_SMALL_PAGE_SHIFT)

#define	E2K_LARGE_PAGE_SIZE		(1 << E2K_LARGE_PAGE_SHIFT)
#define	BOOT_E2K_LARGE_PAGE_SIZE	(1 << BOOT_E2K_LARGE_PAGE_SHIFT)

#define PAGE_SIZE			_BITUL(PAGE_SHIFT)
#define LARGE_PAGE_SIZE    		E2K_LARGE_PAGE_SIZE

#if defined(CONFIG_CPU_ES2)
# define E2K_MAX_PAGE_SIZE		(1 << E2K_4M_PAGE_SHIFT)
#else
# define E2K_MAX_PAGE_SIZE		(1 << E2K_2M_PAGE_SHIFT)
#endif

#define	E2K_SMALL_PAGE_MASK		(~(E2K_SMALL_PAGE_SIZE - 1))

#define	E2K_LARGE_PAGE_MASK		(~(E2K_LARGE_PAGE_SIZE - 1))
#define	BOOT_E2K_LARGE_PAGE_MASK	(~(BOOT_E2K_LARGE_PAGE_SIZE - 1))

#define	PAGE_MASK			(~(PAGE_SIZE - 1))
#define	LARGE_PAGE_MASK			E2K_LARGE_PAGE_MASK

#define HPAGE_SHIFT			E2K_LARGE_PAGE_SHIFT
#define HPAGE_SIZE			((1UL) << HPAGE_SHIFT)
#define HPAGE_MASK			(~(HPAGE_SIZE - 1))
#define HUGETLB_PAGE_ORDER		(HPAGE_SHIFT - PAGE_SHIFT)

#define HPAGE_PMD_MAX_ORDER		(E2K_4M_PAGE_SHIFT - PAGE_SHIFT)


#ifdef __KERNEL__

#include <linux/init.h>
#include <linux/threads.h>

#include <asm/types.h>
#include <asm/errors_hndl.h>
#ifndef __ASSEMBLY__
#include <asm/atomic.h>
#include <asm/e2k_api.h>
#include <asm/bootinfo.h>
#include <asm/string.h>
#include <asm/pv_info.h>
#endif	/* !(__ASSEMBLY__) */


/*
 * To align the pointer to the (next) page boundary or to the beginning of
 * the page
 */

/*
 * Round up the beginning of the address.
 */
#define	_PAGE_ALIGN_UP(addr, page_size) \
		((e2k_addr_t)(addr) & ~(page_size-1))

/*
 * Round down the end of the address.
 */
#define	_PAGE_ALIGN_DOWN(addr, page_size) \
		(((e2k_addr_t)(addr) + (page_size-1)) & ~(page_size-1))

#define	E2K_SMALL_PAGE_ALIGN_DOWN(addr) \
		_PAGE_ALIGN_DOWN(addr, E2K_SMALL_PAGE_SIZE)
#define	E2K_SMALL_PAGE_ALIGN_UP(addr) \
		_PAGE_ALIGN_UP(addr, E2K_SMALL_PAGE_SIZE)
#define	E2K_SMALL_PAGE_ALIGN(addr)	E2K_SMALL_PAGE_ALIGN_DOWN(addr)

#define	E2K_LARGE_PAGE_ALIGN_DOWN(addr) \
		_PAGE_ALIGN_DOWN(addr, E2K_LARGE_PAGE_SIZE)
#define	E2K_LARGE_PAGE_ALIGN_UP(addr) \
		_PAGE_ALIGN_UP(addr, E2K_LARGE_PAGE_SIZE)
#define	E2K_LARGE_PAGE_ALIGN(addr)	E2K_LARGE_PAGE_ALIGN_DOWN(addr)


#define	PAGE_ALIGN_DOWN(addr)		_PAGE_ALIGN_DOWN(addr, PAGE_SIZE)
#define	PAGE_ALIGN_UP(addr)		_PAGE_ALIGN_UP(addr, PAGE_SIZE)
#define	LARGE_PAGE_ALIGN_DOWN(addr)	_PAGE_ALIGN_DOWN(addr, LARGE_PAGE_SIZE)
#define	LARGE_PAGE_ALIGN_UP(addr)	_PAGE_ALIGN_UP(addr, LARGE_PAGE_SIZE)

#define	E2K_ALIGN_SIZE_UP(addr, size)	\
		(((size) == 0) ? (addr) : ALIGN_MASK_UP(addr, ((size)-1)))
#define	E2K_ALIGN_SIZE_DOWN(addr, size)	\
		(((size) == 0) ? (addr) : ALIGN_MASK_DOWN(addr, ((size)-1)))
#define	E2K_ALIGN_SIZE(addr, size)		\
		(((size) == 0) ? (addr) : ALIGN_MASK(addr, ((size)-1)))

#define	ALIGN_MASK_UP(addr, mask)	((addr) & ~(mask))
#define	ALIGN_MASK_DOWN(addr, mask)	(((addr) + (mask)) & ~(mask))
#define	ALIGN_TO_MASK(addr, mask)	ALIGN_MASK_DOWN(addr, mask)
#define	ALIGN_SIZE_UP(addr, size)	\
		(((size) == 0) ? (addr) : ALIGN_MASK_UP(addr, ((size)-1)))
#define	ALIGN_SIZE_DOWN(addr, size)	\
		(((size) == 0) ? (addr) : ALIGN_MASK_DOWN(addr, ((size)-1)))
#define	ALIGN_TO_SIZE(addr, size)	\
		(((size) == 0) ? (addr) : ALIGN_TO_MASK(addr, ((size)-1)))

#ifndef __ASSEMBLY__

#define CLEAR_MEMORY_TAG ETAGNUM /* memory filling mode: zeroing */
/* #define CLEAR_MEMORY_TAG ETAGEWD / * memory filling mode: emptying */

/*
 * A _lot_ of the kernel time is spent clearing pages, so
 * do this as fast as it possibly can.
 *
 * #95931: try to keep small pages in cache, but avoid cache trashing
 * when clearing huge pages.
 */

#define clear_memory_8(addr, size, tag) \
		fast_tagged_memory_set(addr, 0, tag, size, \
		LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT | \
		MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT)

#define clear_page(addr) clear_memory_8((addr), PAGE_SIZE, CLEAR_MEMORY_TAG)

#define clear_user_page(addr, vaddr, page) \
do { \
	u64 strd_opcode; \
	/* Use WC stores to clear huge pages. \
	 * e4c does not have shared L3 so cacheable stores are not _that_ \
	 * bad and it also has hardware bug which forces to issue memory \
	 * barrier after WC stores, so we avoid WC there. */ \
	if (!IS_MACHINE_E2S && PageCompound(page)) { \
		strd_opcode = LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT | \
			MAS_BYPASS_ALL_CACHES << LDST_REC_OPC_MAS_SHIFT; \
	} else { \
		strd_opcode = LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT | \
			MAS_BYPASS_L1_CACHE << LDST_REC_OPC_MAS_SHIFT; \
	} \
	fast_tagged_memory_set((addr), 0, CLEAR_MEMORY_TAG, \
				PAGE_SIZE, strd_opcode); \
} while (0)

#define clear_user_highpage(page, vaddr) \
		clear_user_page(page_address(page), (vaddr), (page))

#define __HAVE_ARCH_COPY_USER_HIGHPAGE
#define copy_user_highpage(to, from, vaddr, vma) \
		copy_page(page_address(to), page_address(from))

#define copy_tagged_page(to, from)	__tagged_memcpy_8(to, from, PAGE_SIZE)

#define copy_page(to, from)		copy_tagged_page(to, from)
#define copy_user_page(to, from, vaddr, page)	copy_page(to, from)

typedef struct page *pgtable_t;

#define __pa(x)			((e2k_addr_t)(x) - PAGE_OFFSET)
#define __va(x)			((void *)((e2k_addr_t) (x) + PAGE_OFFSET))
#define __boot_pa(x)		((e2k_addr_t)(x) - BOOT_PAGE_OFFSET)
#define __boot_va(x)		((void *)((e2k_addr_t) (x) + BOOT_PAGE_OFFSET))

#define __pa_symbol(x)		vpa_to_pa(kernel_va_to_pa((unsigned long) (x)))

/*
 * PFNs are real physical page numbers.  However, mem_map only begins to record
 * per-page information starting at pfn_base.
 * This is to handle systems where the first physical page in the machine
 * is not 0.
 */

struct page;

extern struct page *e2k_virt_to_page(const void *kaddr);

#define phys_to_page(kaddr)	pfn_to_page((kaddr) >> PAGE_SHIFT)
#define page_to_phys(page)	(page_to_pfn(page) << PAGE_SHIFT)

#define virt_to_page(kaddr)						\
		(((e2k_addr_t)(kaddr) >= PAGE_OFFSET && 		\
			(e2k_addr_t)(kaddr) < PAGE_OFFSET + MAX_PM_SIZE) ? \
				phys_to_page(__pa(kaddr))		\
				:					\
				e2k_virt_to_page((void *) (kaddr)))


#define pfn_to_kaddr(pfn)      __va((pfn) << PAGE_SHIFT)

#define virt_to_phys		__pa
#define phys_to_virt		__va

#define virt_to_pfn(kaddr)	(__pa(kaddr) >> PAGE_SHIFT)

#define	page_valid(page)	pfn_valid(page_to_pfn(page))
#define phys_addr_valid(addr)	pfn_valid((addr) >> PAGE_SHIFT)
#define virt_addr_valid(kaddr)  ((e2k_addr_t)(kaddr) >= PAGE_OFFSET && \
					pfn_valid(virt_to_pfn(kaddr)))
#define kern_addr_valid(kaddr)	page_valid(virt_to_page(kaddr))

#define	boot_pa(x)	((BOOT_READ_OSCUD_LO_REG().OSCUD_lo_base >= \
								PAGE_OFFSET) \
				? \
				__pa(x) : (void *)(boot_pa_to_vpa(x)))
#define	boot_va(x)	((BOOT_READ_OSCUD_LO_REG().OSCUD_lo_base >= \
								PAGE_OFFSET) \
				? \
				__va(x) : (void *)(boot_pa_to_vpa(x)))

/*
 * E2K architecture additional vm_flags
 */

#define VM_HW_STACK_PS	 0x00100000000UL /* procedure stack area */
#define	VM_TAGMAPPED	 0x00200000000UL /* the tags area appropriate */
					 /* to this data VM area was mapped */
#define VM_HW_STACK_PCS	 0x00400000000UL /* chain stack area */
#define	VM_WRITECOMBINED 0x00800000000UL
#define VM_PRIVILEGED	 0x04000000000UL /* pages are privileged */
#define	VM_MPDMA	 0x10000000000UL /* pages are under MPDMA */
					 /* hardware protection */
#define VM_SIGNAL_STACK	 0x20000000000UL /* Signal stack area */
#define VM_CUI		 0xffff000000000000UL /* CUI for pages in VMA */
#define VM_CUI_SHIFT	 48

/*
 * E2K architecture additional gup_flags
 */
#define FOLL_MPDMA	0x01000000	/* page is not writable only for DMA */

/*
 * We don't set the valid bit for PROT_NONE areas, otherwise
 * semi-speculative loads will cause page faults which is bad
 * for performance when such loads come from an unrolled loop.
 */
#define	VM_PAGESVALID		(VM_READ | VM_WRITE | VM_EXEC)

/*
 * The following structure is used to hold the physical memory configuration
 * of the machine. This is filled in 'boot_probe_memory()' and is later
 * used by 'boot_mem_init()' to setup boot-time memory map and by 'mem_init()'
 * to set up 'mem_map[]'.
 * A base address of a bank should be page aligned.
 * The structure item 'mem_bitmap' is a map pointer. The map bits represent
 * the physical memory on the bank in terms of small pages (4 KB).
 * To reduce the boot-time map size, the boot map represents only needed
 * to boot tasks first 'BOOT_MAX_PHYS_MEM_SIZE' bytes of real physical memory
 * configuration. Some of memory areas are prereserved ('text' & 'data'
 * segments, stack, boot information etc) and have been allocated by BIOS or
 * boot loaders. All these areas are known and listed in the header
 * 'asm/boot_init.h' Such area can be allocated on any physical address and
 * can be out of the boot map, which represents reserved memory
 * The structure 'e2k_busy_mem_t' represents occupied memory areas in a bank,
 * which can not be described by the boot map.
 * Array of 'E2K_MAX_PHYS_BANKS' of these structures is statically allocated
 * into the kernel image.
 * The entry after the last valid one has 'pages_num == 0'.
 */

typedef	unsigned long	e2k_mem_map_t;	/* double-word (64 bits == 64 pages) */

typedef enum busy_mem_type {
	undefined_mem_type = 0,		/* unknown data area */
	boot_loader_mem_type,		/* data and binary of boot loader */
	kernel_image_mem_type,		/* kernel image (text & data) */
	data_stack_mem_type,		/* local data stack */
	hw_stack_mem_type,		/* hardware procedure or chain stack */
	page_table_mem_type,		/* page tables */
	kernel_data_mem_type,		/* kernel data/structures/tables */
					/* and other areas of memory */
	bootblock_mem_type,		/* boot block (common data with boot */
					/* loader) */
	boot_time_data_mem_type,	/* kernel data & structures allocated */
					/* while boot-time init */
	hw_reserved_mem_type,		/* reserved for hardware purposes */
					/* (for example: bugs workaround) */
	hw_stripped_mem_type,		/* hardware stripped out physical */
					/* memory (IO, ROM, VGA ...) */
	dma32_mem_type,			/* low memory reserved for DMA and */
					/* bounce buffers */
} busy_mem_type_t;

typedef	struct e2k_busy_mem {
	e2k_size_t	start_page;	/* start page # of an area in a bank */
	e2k_size_t	pages_num;	/* number of occupied pages by the */
					/* area in the bank */
	short		next;		/* index of next area (last = -1) */
					/* busy areas is ordered list */
					/* on increase of addresses */
	unsigned short	flags;		/* boot-time busy area flags */
					/* (see asm/boot_phys.h) */
	busy_mem_type_t	type;		/* memory type */
} e2k_busy_mem_t;

#define BOOT_RESERVED_AREAS_SIZE	(2 * PAGE_SIZE)

/* max number of prereserved areas at boot-time */
#define	BOOT_MAX_PRERESERVED_AREAS	\
		(1 +			/* 0-page (hardware bug workaround) */ \
		3 * NR_CPUS +		/* 3 stacks (data/procedure/chain) */ \
					/* on each CPU */ \
		1 +			/* kernel image 'text' section */ \
		1 +			/* kernel image 'protexted text' */ \
		1 +			/* kernel '.data..ro_after_init' */ \
		1 +			/* kernel 'data/bss' */ \
		1 +			/* kernel 'init' */ \
		1 +			/* low IO memory (VGA memory) */ \
		1 +			/* bootblock */ \
		1 +			/* INITRD */ \
		1 +			/* mp table */ \
		1 +			/* MP floating table */ \
		1 * L_MAX_BUSY_AREAS +	/* boot loader busy memory */ \
		1 +			/* list of all occupied areas */ \
		0)

#ifdef	CONFIG_ONLY_HIGH_PHYS_MEM
/* max number of prereserved  areas at low physical memory */
#define	MAX_PRERESERVED_LOW_AREAS	2
#else	/* ! CONFIG_ONLY_HIGH_PHYS_MEM */
#define	MAX_PRERESERVED_LOW_AREAS	0	/* none such areas */
#endif	/* CONFIG_ONLY_HIGH_PHYS_MEM */

#define	E2K_MAX_PRERESERVED_AREAS	\
		(BOOT_MAX_PRERESERVED_AREAS + MAX_PRERESERVED_LOW_AREAS)

typedef struct e2k_phys_bank {
	e2k_addr_t	base_addr;	/* base physical address of the start */
					/* page of the bank */
	e2k_size_t	pages_num;	/* total number of pages in the bank */
	bool maybe_remapped_to_hi;	/* the low bank can be remapped to */
					/* high range bank */
	short		next;		/* index of next bank (last = -1) */
					/* node bnaks is ordered list */
					/* on increase of addresses */
	atomic64_t	free_pages_num;	/* current number of free pages */
					/* in the map */
	short		busy_areas_num;	/* number of areas in the list of */
					/* occupied areas in the bank */
	short		first_area;	/* index of first busy area */
	e2k_busy_mem_t	busy_areas_prereserved[E2K_MAX_PRERESERVED_AREAS];
					/* list of all occupied areas in the */
					/* bank, which not included to the */
					/* memory bitmap */
	e2k_busy_mem_t	*busy_areas;	/* pointer to list of all occupied */
					/* areas in the bank */
	bool		mapped[L_MAX_MEM_NUMNODES];
					/* the bank was already mapped */
					/* on node [node_id] */
} e2k_phys_bank_t;

typedef struct node_phys_mem {
	e2k_size_t	start_pfn;	/* start page number on the node */
	e2k_size_t	pfns_num;	/* number of pages on the node */
					/* including holes between banks */
	short		banks_num;	/* total number of banks in the list */
	short		first_bank;	/* index of first bank on the list */
					/* (starts from start_pfn) */
	e2k_phys_bank_t	banks[L_MAX_NODE_PHYS_BANKS];
} node_phys_mem_t;

extern  node_phys_mem_t	nodes_phys_mem[L_MAX_MEM_NUMNODES];

#define boot_nodes_phys_mem	\
		(boot_vp_to_pp((node_phys_mem_t *)nodes_phys_mem))

#define VM_DATA_DEFAULT_FLAGS	(VM_READ | VM_WRITE | \
				 VM_MAYREAD | VM_MAYWRITE | VM_MAYEXEC)

#ifndef CONFIG_E2K_HAS_OPT_BITOPS
#include <asm-generic/getorder.h>
#else
#include <asm/bitsperlong.h>
static inline int get_order(unsigned long size)
{
	int lz = 0;

	size = (size - 1) >> PAGE_SHIFT;
	lz = E2K_LZCNTD(size);

	return BITS_PER_LONG - lz;
}
#endif /* CONFIG_E2K_HAS_OPT_BITOPS */

struct task_struct;

extern e2k_addr_t node_kernel_address_to_phys(int node, e2k_addr_t address);
extern e2k_addr_t user_address_to_pva(struct task_struct *tsk,
		e2k_addr_t address);
extern e2k_addr_t kernel_address_to_pva(e2k_addr_t address);

#define ARCH_ZONE_DMA_BITS	32

#endif /* !(__ASSEMBLY__) */

#endif /* !(__KERNEL__) */

#include <asm-generic/memory_model.h>

#endif /* !(_E2K_PAGE_H) */
