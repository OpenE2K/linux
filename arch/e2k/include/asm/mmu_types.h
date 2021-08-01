#ifndef _E2K_MMU_TYPES_H_
#define _E2K_MMU_TYPES_H_

#include <linux/types.h>

#include <uapi/asm/iset_ver.h>

#ifndef	__ASSEMBLY__

/*
 * These are used to make use of C type-checking..
 */
typedef unsigned long	pteval_t;
typedef unsigned long	pmdval_t;
typedef unsigned long	pudval_t;
typedef unsigned long	pgdval_t;
typedef unsigned long	pgprotval_t;

typedef struct { pteval_t pte; } pte_t;
typedef struct { pmdval_t pmd; } pmd_t;
typedef struct { pudval_t pud; } pud_t;
typedef struct { pgdval_t pgd; } pgd_t;
typedef struct { pgprotval_t pgprot; } pgprot_t;

#define pte_val(x)	((x).pte)
#define pmd_val(x)	((x).pmd)
#define pud_val(x)	((x).pud)
#define pgd_val(x)	((x).pgd)
#define pgprot_val(x)	((x).pgprot)

#define __pte(x)	((pte_t) { (x) } )
#define __pmd(x)	((pmd_t) { (x) } )
#define __pud(x)	((pud_t) { (x) } )
#define __pgd(x)	((pgd_t) { (x) } )
#define __pgprot(x)	((pgprot_t) { (x) } )

#endif	/* ! __ASSEMBLY__ */

/* one page table occupies one 4K page and has 512 entries */
#define	PT_ENTRIES_SHIFT	3	/* 8 bytes, 3 bits */
#define	PT_ENTRIES_BITS		(PAGE_SHIFT - PT_ENTRIES_SHIFT)	/* 9 bits */
#define	PT_ENTRIES_PER_PAGE	(1 << PT_ENTRIES_BITS)	/* 512 ptes */

/*
 * Definitions for 4-th (root) level:
 *
 * PGDIR_SHIFT determines what a root-level page table entry
 * can map:
 *		pages of 3-th level page table entries
 *
 * Cannot use the top 0xffff ff00 0000 0000 - 0xffff ffff ffff ffff addresses
 * because virtual page table lives there.
 */
#define PGDIR_SHIFT	(PAGE_SHIFT + 3 * PT_ENTRIES_BITS)
#define PGDIR_SIZE	(1UL << PGDIR_SHIFT)
#define PGDIR_MASK	(~(PGDIR_SIZE-1))
#define	PAGE_PGD_SIZE	PGDIR_SIZE
#define PTRS_PER_PGD	(1UL << PT_ENTRIES_BITS)
#define	PGD_TABLE_SIZE	(PTRS_PER_PGD * sizeof(pgd_t))
#define USER_PTRS_PER_PGD (TASK_SIZE / PGDIR_SIZE)
#define FIRST_USER_ADDRESS 0

/*
 * Definitions for 3-th level:
 *
 * PUD_SHIFT determines the size of the area a 3-th level page tables
 * can map:
 *		pages of second-level page table entries
 */
#define PUD_SHIFT	(PAGE_SHIFT + 2 * PT_ENTRIES_BITS)
#define PUD_SIZE	(1UL << PUD_SHIFT)
#define PUD_MASK	(~(PUD_SIZE-1))
#define	PAGE_PUD_SIZE	PUD_SIZE
#define PTRS_PER_PUD	(1UL << PT_ENTRIES_BITS)
#define	PUD_TABLE_SIZE	(PTRS_PER_PUD * sizeof(pud_t))

/*
 * Definitions for 2-nd level:
 *
 * PMD_SHIFT determines the size of the area a middle level page tables
 * can map:
 *		pages of first level page table entries
 */
#define PMD_SHIFT	(PAGE_SHIFT + 1 * PT_ENTRIES_BITS)
#define PMD_SIZE	(1UL << PMD_SHIFT)
#define PMD_MASK	(~(PMD_SIZE-1))
#define	PAGE_PMD_SIZE	PMD_SIZE
#define PTRS_PER_PMD	(1UL << PT_ENTRIES_BITS)
#define	PMD_TABLE_SIZE	(PTRS_PER_PMD * sizeof(pmd_t))

/*
 * Definitions for first (page table entries) level:
 *
 * PTE - Entries per user pages.
 */
#define PTE_SHIFT	(PAGE_SHIFT)		/* PAGE_SHIFT */
#define PTE_SIZE	(1UL << PTE_SHIFT)	/* PAGE_SIZE */
#define PTE_MASK	(~(PTE_SIZE-1))		/* PAGE_MASK */
#define PTRS_PER_PTE	(1UL << PT_ENTRIES_BITS)
#define	PTE_TABLE_SIZE	(PTRS_PER_PTE * sizeof(pte_t))

/*
 * The index in the 4-th (root-level) page table directory.
 */
#define	pgd_index(virt_addr)		(((virt_addr) >> PGDIR_SHIFT) & \
					(PTRS_PER_PGD - 1))

/* Additional trap cellar fields are located at this offset */
#define TC_EXT_OFFSET	512

#ifndef	__ASSEMBLY__

/*
 * Hardware MMUs page tables have some differences from one ISET to other
 * moreover each MMU supports a few different page tables:
 *	native (primary)
 *	secondary page tables for sevral modes (VA32, VA48, PA32, PA48 ...)
 * The follow structures and tables present these differences for each instance
 * to manage page tables as common item
 */

/* max possible number of page table levels for all ISETs, types, modes */
/* to can describe any supported by MMUs type of page tables */
#define	ARCH_MAX_PT_LEVELS	4	/* for 48 bits virtual address */
					/* and 48 bits physical address */

#define	E2K_PT_LEVELS_NUM	4	/* native mode page tables have */
					/* equal number of levels up to now */
#define	E2K_PAGES_LEVEL_NUM	0	/* level number of physical pages */
#define	E2K_PTE_LEVEL_NUM	1	/* level number of native pte */
#define	E2K_PMD_LEVEL_NUM	2	/* level number of native pmd */
#define	E2K_PUD_LEVEL_NUM	3	/* level number of native pud */
#define	E2K_PGD_LEVEL_NUM	4	/* level number of native pgd */

/* max level # on which can map huge pages: pmd, pud */
#define	MAX_HUGE_PAGES_LEVEL	E2K_PUD_LEVEL_NUM

#define	MAX_NUM_HUGE_PTES	2	/* max number of page table entries */
					/* to present one huge page on any */
					/* PT level */
					/* Now e2c+ MMU need 2 pmd entries */
					/* to present 4 Mb page */

typedef enum dtlb_type {
	UNUSED_DTLB_TYPE,		/* DTLB unused for page table entries */
	COMMON_DTLB_TYPE,		/* common DTLB N-lines x M-sets */
	FULL_ASSOCIATIVE_DTLB_TYPE,	/* full associative buffer */
					/* used for 1 Gb pages */
} dtlb_type_t;

typedef enum pt_type {
	UNDEFINED_PT_TYPE,		/* undefined (not known) PT type */
	E2K_PT_TYPE,			/* arch native 4-th level PT */
	X86_2_LEVELS_PT_TYPE,		/* secondary PT VA32 - PA32 */
	X86_3_LEVELS_PT_TYPE,		/* secondary PT VA32 - PA48 */
	X86_4_LEVELS_PT_TYPE,		/* secondary PT VA48 - PA48 */
} pt_type_t;

typedef struct pt_level {
	int		id;		/* level ID (now is level #) */
	e2k_size_t	pt_size;	/* page size, which the level one */
					/* entry can map */
	e2k_size_t	page_size;	/* page or huge page size, which */
					/* the level real map, this size can */
					/* differ from pt_size above, because */
					/* of a few entries should present */
					/* one huge page */
	int		pt_shift;	/* youngest bit of page address, */
					/* which the level one entry can map */
	int		page_shift;	/* youngest bit of huge page address, */
					/* which the level is mapped */
	e2k_addr_t	pt_mask;	/* mask of page address, which */
					/* the level one entry can map */
	e2k_addr_t	pt_offset;	/* mask of offset into the level */
					/* page address */
	e2k_addr_t	pt_index_mask;	/* mask of index bits into the level */
					/* page address */
	e2k_addr_t	page_mask;	/* mask of huge page address, which */
					/* the level is mapped */
	e2k_addr_t	page_offset;	/* mask of offset into the level */
					/* huge page address */
	int		ptrs_per_pt;	/* number of entries in one table of */
					/* the level */
	bool		is_pte;		/* page table entries level */
	bool		is_huge;	/* the level can be as huge page */
					/* table entries */
	unsigned char	huge_ptes;	/* number of the level page table */
					/* entries to present one huge page */
	dtlb_type_t	dtlb_type;	/* DTLB cache type for page tables */
					/* entries on the level */

	/* interface function to handle some things on the level */
	pte_t * (*boot_get_huge_pte)(e2k_addr_t virt_addr, pgprot_t *ptp);
	pte_t * (*init_get_huge_pte)(e2k_addr_t virt_addr, pgprot_t *ptp);
	pte_t * (*get_huge_pte)(e2k_addr_t virt_addr, pgprot_t *ptp);
	void (*boot_set_pte)(e2k_addr_t addr, pte_t *ptep, pte_t pte,
				bool host_map);
	void (*init_pte_clear)(pte_t *ptep);
	void (*split_pt_page)(pgprot_t *ptp, pte_t *ptes[MAX_NUM_HUGE_PTES]);
	void (*map_pt_huge_page_to_prev_level)(pgprot_t *pt_page,
				e2k_addr_t phys_page, pgprot_t pgprot);

} pt_level_t;

typedef struct pt_struct {
	pt_type_t	type;		/* PT type */
	const char	*name;		/* PT type name */
	bool		pt_v6;		/* PT entry structure V6 or above */
	int		levels_num;	/* real number of page table levels */

	/* some useful PT entries structure bit mask */
	/* can be different for some PT types (depend on fields type, pt_v6) */
	pgprotval_t	pfn_mask;	/* pfn # */
	pgprotval_t	accessed_mask;	/* page accessed flags */
	pgprotval_t	dirty_mask;	/* page was updated */
	pgprotval_t	present_mask;	/* page is present */
	pgprotval_t	valid_mask;	/* page is present */
	pgprotval_t	user_mask;	/* page of user */
	pgprotval_t	priv_mask;	/* page is privileged */
	pgprotval_t	non_exec_mask;	/* page is not executable */
	pgprotval_t	exec_mask;	/* page is executable */

	/* mask of bits available for software */
	pgprotval_t	sw_bit1_mask;	/* # 1 */
	pgprotval_t	sw_bit2_mask;	/* # 2 */
	pgprotval_t	sw_mmio_mask;	/* shadow pte is for MMIO */

	/* some useful PT entries page protection base values */
	pgprotval_t	ptd_kernel_prot; /* kernel PT directories protection */
	pgprotval_t	ptd_user_prot;	/* user PT directories protection */

	/* interface function to get/set some protections */
	unsigned int (*get_pte_val_memory_type)(pgprot_t pte_val);
	pgprot_t (*set_pte_val_memory_type)(pgprot_t pte_val,
						unsigned int memory_type);
	unsigned int (*get_pte_val_memory_type_rule)(pgprot_t pte_val);
	pgprot_t (*set_pte_val_memory_type_rule)(pgprot_t pte_val,
						unsigned int mtcr);

			/* level #0 is always physical page */
	pt_level_t	levels[ARCH_MAX_PT_LEVELS + 1];
} pt_struct_t;

static inline int
get_pt_level_id(const pt_level_t *pt_level)
{
	/* now PT level is number of the level */
	return pt_level->id;
}

static inline bool
is_page_pt_level(const pt_level_t *pt_level)
{
	return pt_level->is_pte;
}

static inline bool
is_huge_pt_level(const pt_level_t *pt_level)
{
	return pt_level->is_huge;
}

static inline e2k_size_t
get_pt_level_size(const pt_level_t *pt_level)
{
	return pt_level->pt_size;
}

static inline e2k_size_t
get_pt_level_page_size(const pt_level_t *pt_level)
{
	return pt_level->page_size;
}

static inline int
get_pt_level_shift(const pt_level_t *pt_level)
{
	return pt_level->pt_shift;
}

static inline int
get_pt_level_page_shift(const pt_level_t *pt_level)
{
	return pt_level->page_shift;
}

static inline e2k_addr_t
get_pt_level_mask(const pt_level_t *pt_level)
{
	return pt_level->pt_mask;
}
static inline e2k_addr_t
get_pt_level_offset(const pt_level_t *pt_level)
{
	return pt_level->pt_offset;
}
static inline e2k_addr_t
get_pt_level_addr_index(e2k_addr_t addr, const pt_level_t *pt_level)
{
	return (addr & pt_level->pt_index_mask) >>
				get_pt_level_shift(pt_level);
}
static inline e2k_addr_t
set_pt_level_addr_index(e2k_addr_t addr, e2k_addr_t index, const pt_level_t *pt_level)
{
	return (addr & ~pt_level->pt_index_mask) |
			((index << get_pt_level_shift(pt_level)) &
						pt_level->pt_index_mask);
}

static inline e2k_addr_t
get_pt_level_page_mask(const pt_level_t *pt_level)
{
	return pt_level->page_mask;
}

static inline e2k_addr_t
get_pt_level_page_offset(const pt_level_t *pt_level)
{
	return pt_level->page_offset;
}

static inline int
get_ptrs_per_pt_level(const pt_level_t *pt_level)
{
	return pt_level->ptrs_per_pt;
}

static inline int
get_pt_level_huge_ptes_num(const pt_level_t *pt_level)
{
	return pt_level->huge_ptes;
}

static inline const pt_level_t *
get_pt_struct_level_on_id(const pt_struct_t *pt_struct, int level_id)
{
	/* now PT level is number of the level */
	return &pt_struct->levels[level_id];
}

static inline bool
is_page_pt_struct_level(const pt_struct_t *pt_struct, int level_id)
{
	return is_page_pt_level(&pt_struct->levels[level_id]);
}

static inline bool
is_huge_pt_struct_level(const pt_struct_t *pt_struct, int level_id)
{
	return is_huge_pt_level(&pt_struct->levels[level_id]);
}

static inline e2k_size_t
get_pt_struct_level_size(const pt_struct_t *pt_struct, int level_id)
{
	return get_pt_level_size(&pt_struct->levels[level_id]);
}

static inline e2k_size_t
get_pt_struct_level_page_size(const pt_struct_t *pt_struct, int level_id)
{
	return get_pt_level_page_size(&pt_struct->levels[level_id]);
}

static inline int
get_pt_struct_level_huge_ptes_num(const pt_struct_t *pt_struct, int level_id)
{
	return get_pt_level_huge_ptes_num(&pt_struct->levels[level_id]);
}

/* This is definition of MMU TRAP_CELLAR types */

struct mmu_tc_dst {
	unsigned address	:8;	/* [0-7] */
	unsigned vr		:1;	/* [8]   */
	unsigned vl		:1;	/* [9]   */
};

typedef union {
	unsigned word;
	struct   mmu_tc_dst fields;
} tc_dst_t;

/* Maximum size for memory access from single channel is 8
 * (16 since e8c2) */
#define E2K_MAX_FORMAT 16

struct mmu_tc_opcode {
	unsigned fmt		:3;	/* [0-2] */
	unsigned npsp		:1;	/* [3]   */
	unsigned fmtc		:2;	/* [4-5] */
};

#endif	/* ! __ASSEMBLY__ */

#define	LDST_BYTE_FMT		1UL	/* load/store byte (8 bits) */
#define	LDST_HALF_FMT		2UL	/* load/store halfword (16 bits) */
#define	LDST_WORD_FMT		3UL	/* load/store word (32 bits) */
#define	LDST_DWORD_FMT		4UL	/* load/store double-word (64 bits) */
#define	LDST_QWORD_FMT		5UL	/* load/store quad-word (128 bits) */
#define	LDST_QP_FMT		7UL	/* load/store qpacked word (128 bits) */

#define LDRD_FMT_QWORD_A	0xdUL
#define LDRD_FMT_QPWORD_A	0xfUL

#define TC_FMT_QPWORD_Q		0xdUL	/* Single 16 position, tags as for Q */
#define TC_FMT_QWORD_QP		0xfUL	/* Two 16 positions, tags as for QP */
#define TC_FMT_DWORD_Q		0x15UL	/* Single 8 position, tags as for Q */
#define TC_FMT_DWORD_QP		0x1fUL	/* Single 8 position, tag as for QP */


#ifndef	__ASSEMBLY__
static inline bool tc_fmt_has_valid_mask(int fmt)
{
	return fmt == LDST_QP_FMT || fmt == TC_FMT_QWORD_QP || fmt == TC_FMT_DWORD_QP;
}


typedef union {
	unsigned word;
	struct   mmu_tc_opcode fields;
} tc_opcode_t;

#define TC_OPCODE_FMT_FULL(opcode) (AS(opcode).fmt || (AS(opcode).fmtc << 3))

struct mmu_tc_fault_type {
	unsigned global_sp		:1;	/* [35] */
	unsigned page_bound		:1;	/* [36] */
	unsigned exc_mem_lock		:1;	/* [37] */
	unsigned ph_pr_page		:1;	/* [38] */
	unsigned io_page		:1;	/* [39] */
	unsigned isys_page		:1;	/* [40] */
	unsigned prot_page		:1;	/* [41] */
	unsigned priv_page		:1;	/* [42] */
	unsigned illegal_page		:1;	/* [43] */
	unsigned nwrite_page		:1;	/* [44] */
	unsigned page_miss		:1;	/* [45] */
	unsigned ph_bound		:1;	/* [46] */
	unsigned intl_res_bits		:1;	/* [47] */
};

typedef union {
	unsigned word;
	struct   mmu_tc_fault_type fields;
} tc_fault_type_t;

typedef union mmu_tc_cond_dword {
	struct {
		u64 dst		:10;	// [0-9]
		u64 opcode	:6;	// [10-15]
		u64 r0		:1;	// [16]
		u64 store	:1;	// [17]
		u64 mode_80	:1;	// [18]
		u64 s_f		:1;	// [19]
		u64 mas		:7;	// [20-26]
		u64 root	:1;	// [27]
		u64 scal	:1;	// [28]
		u64 sru		:1;	// [29]
		u64 spec	:1;	// [30]
		u64 pm		:1;	// [31]
		u64 chan	:2;	// [32-33]
		u64 r1		:1;	// [34]
		u64 fault_type :13;	// [35-47]
		u64 miss_lvl	:2;	// [48-49]
		u64 num_align	:1;	// [50]
		u64 empt	:1;	// [51]
		u64 clw		:1;	// [52]
		u64 dst_rcv	:10;	// [53-62]
		u64 rcv		:1;	// [63]
	};
	struct {
		u64 address	:8;	// [0-7]
		u64 vr		:1;	// [8]
		u64 vl		:1;	// [9]
		u64 fmt		:3;	// [10-12]
		/* Be careful: npsp=1 => access is not protected,
		 * but npsp=0 does not mean that access is protected. */
		u64 npsp	:1;	// [13]
		u64 fmtc	:2;	// [14-15]
		u64 ___x1	:19;	// [34-16]
		u64 global_sp	:1;	/* [35] */
		u64 page_bound	:1;	/* [36] */
		u64 exc_mem_lock :1;	/* [37] */
		u64 ph_pr_page	:1;	/* [38] */
		u64 io_page	:1;	/* [39] */
		u64 isys_page	:1;	/* [40] */
		u64 prot_page	:1;	/* [41] */
		u64 priv_page	:1;	/* [42] */
		u64 illegal_page :1;	/* [43] */
		u64 nwrite_page	:1;	/* [44] */
		u64 page_miss	:1;	/* [45] */
		u64 ph_bound	:1;	/* [46] */
		u64 intl_res_bits :1;	/* [47] */
		u64 ___x0	:5;	/* [52:48] */
		u64 dst_ind	:8;	/* [60:53] */
		u64 ___x2	:3;	/* [63-61] */
	};
} mmu_tc_cond_dword_t;

typedef union {
	u64 word;
	union mmu_tc_cond_dword fields;
} tc_cond_t;

#define TC_COND_FMT_FULL(cond) (AS(cond).fmt | (AS(cond).fmtc << 3))

static inline bool tc_cond_is_special_mmu_aau(tc_cond_t cond)
{
	unsigned int mas = AS(cond).mas;
	int chan = AS(cond).chan;
	int store = AS(cond).store;
	int spec_mode = AS(cond).spec;

	if (unlikely(is_mas_special_mmu_aau(mas) && (store ||
			!store && !spec_mode && (chan == 1 || chan == 3))))
		return true;

	return false;
}

static inline bool tc_cond_is_check_ld(tc_cond_t cond)
{
	unsigned int mas = AS(cond).mas;
	int store = AS(cond).store;
	int spec_mode = AS(cond).spec;

	return is_mas_check(mas) && !spec_mode && !store;
}

static inline bool tc_cond_is_check_unlock_ld(tc_cond_t cond)
{
	unsigned int mas = AS(cond).mas;
	int store = AS(cond).store;
	int spec_mode = AS(cond).spec;

	return is_mas_check_unlock(mas) && !spec_mode && !store;
}

static inline bool tc_cond_is_lock_check_ld(tc_cond_t cond)
{
	unsigned int mas = AS(cond).mas;
	int store = AS(cond).store;
	int spec_mode = AS(cond).spec;

	return is_mas_lock_check(mas) && spec_mode && !store;
}

static inline bool tc_cond_is_spec_lock_check_ld(tc_cond_t cond)
{
	unsigned int mas = AS(cond).mas;
	int store = AS(cond).store;
	int spec_mode = AS(cond).spec;

	return is_mas_spec_lock_check(mas) && spec_mode && !store;
}

/*
 * Caveat: for qword accesses this will return 16 bytes for
 * the first entry in trap cellar and 8 bytes for the second one.
 */
static inline int tc_cond_to_size(tc_cond_t cond)
{
	const int fmt = TC_COND_FMT_FULL(cond);
	int size;

	if (fmt == LDST_QP_FMT || fmt == TC_FMT_QPWORD_Q) {
		size = 16;
	} else if (fmt == LDST_QWORD_FMT || fmt == TC_FMT_QWORD_QP) {
		if (AS(cond).chan == 0 || AS(cond).chan == 2)
			size = 16;
		else
			size = 8;
	} else if (fmt == TC_FMT_DWORD_Q || fmt == TC_FMT_DWORD_QP) {
		size = 8;
	} else {
		size = 1 << ((fmt & 0x7) - 1);
	}

	return size;
}

typedef union {
	u64 word;
	struct {
		u64 mask_lo : 8;	/* [7-0] */
		u64 mask_hi : 8;	/* [15-8] */
		u64 __reserved1 : 48;	/* [63-16] */
	};
	struct {
		u64 mask : 16;		/* [15-0] */
		u64 __reserved2 : 48;	/* [63-16] */
	};
} tc_mask_t;

static inline int
ldst_chan_opc_to_chan_num(int chan_opc)
{
	switch (chan_opc) {
	case 0: return 0;
	case 1: return 2;
	case 2: return 3;
	case 3: return 5;
	default: return -1;
	}
}
static inline int
ldst_chan_num_to_chan_opc(int chan_opc)
{
	switch (chan_opc) {
	case 0: return 0;
	case 2: return 1;
	case 3: return 2;
	case 5: return 3;
	default: return -1;
	}
}

static inline bool
tc_cond_load_has_store_semantics(tc_cond_t condition, unsigned iset_ver)
{
	const unsigned mas = AS(condition).mas;
	const unsigned mod = (mas & MAS_MOD_MASK) >> MAS_MOD_SHIFT;
	const unsigned chan = AS(condition).chan;
	const bool root = AS(condition).root;
	const bool spec = AS(condition).spec;

	if (chan != 0)
		return false;
	if (spec)
		return false;
	return mod == _MAS_MODE_LOAD_OP_WAIT
			|| iset_ver < E2K_ISET_V3 &&
				mod == _MAS_MODE_LOAD_OP_TRAP_ON_LD
			|| root && iset_ver >= E2K_ISET_V3 &&
				((mas & MAS_TRAP_ON_LD_ST_MASK) ==
						MAS_LOAD_SEC_TRAP_ON_LD_ST
				|| mas == MAS_SEC_SLT)
			|| iset_ver >= E2K_ISET_V5 &&
				mod == _MAS_MODE_LOAD_OP_WAIT_1 &&
				tc_cond_to_size(condition) == 16;
}

static inline bool
tc_cond_is_store(tc_cond_t condition, unsigned iset_ver)
{
	const unsigned mas = AS(condition).mas;

	if (AS(condition).store && (mas != MAS_DCACHE_LINE_FLUSH))
		return true;
	return tc_cond_load_has_store_semantics(condition, iset_ver);
}

/* Trap cellar flags */

#define TC_DONE_FLAG		0x01
#define TC_NESTED_EXC_FLAG	0x02
#define	TC_IS_HVA_FLAG		0x10	/* address at trap cellar is already */
					/* converted GVA->HVA */

/*
 * Trap cellar as it is in hardware plus additional fields
 */
typedef struct {
	unsigned long	address;
	unsigned long	data;
	tc_cond_t	condition;
	unsigned long	data_ext;
	tc_mask_t	mask;
	unsigned char	flags;
} trap_cellar_t;

/* bug 96719 - combination s_f = 0, store=1, sru =1 conside
 *  as  s_f = 1, store=1, sru =1
 *  */
#define IS_SPILL(tc) (cpu_has(CPU_HWBUG_TRAP_CELLAR_S_F) && \
		      AS((tc).condition).store && AS((tc).condition).sru)

/*
 * Trap cellar as it is in hardware
 */
typedef struct {
	unsigned long	address;
	unsigned long	data;
	tc_cond_t	condition;
} kernel_trap_cellar_t;

typedef struct {
	unsigned long __reserved;
	unsigned long data;
	tc_mask_t mask;
} kernel_trap_cellar_ext_t;

/**
 * is_record_asynchronous - return true if the record is asynchronous
 * @cond: cond mask of record
 *
 * Asynchronous records are the ones that did not originate from wide
 * instruction in user code, i.e. hardware-generated records.
 *
 * In current processor models (and probably in all future ones) only
 * CLW records can mix with synchronous ones.
 */
static inline bool is_record_asynchronous(tc_cond_t cond)
{
	/* We use bitwise OR for performance */
	return AS(cond).mode_80 | AS(cond).s_f | AS(cond).sru | AS(cond).clw;
}

/**
 * tc_record_asynchronous - return true if the record
 * in tcellar is asynchronous
 * @tcellar: record in question
 */
static inline int tc_record_asynchronous(trap_cellar_t *tcellar)
{
	tc_cond_t cond = tcellar->condition;

	return is_record_asynchronous(cond);
}

#endif	/* ! __ASSEMBLY__ */

/*
 * Second operand of Load and Store recovery instruction (LDRD & STRD):
 *
 *	operation code and MAS flags
 */

#define	LDST_REC_OPC_INDEX_SHIFT	 0
#define	LDST_REC_OPC_INDEX_SIZE		32	/* [31- 0] byte index */
#define	LDST_REC_OPC_MAS_SHIFT		32
#define	LDST_REC_OPC_MAS_SIZE		 7	/* [38-32] MAS */
#define	LDST_REC_OPC_PROT_SHIFT		39
#define	LDST_REC_OPC_PROT_SIZE		 1	/*    [39] protected access */
#define	LDST_REC_OPC_FMT_SHIFT		40
#define	LDST_REC_OPC_FMT_SIZE		 3	/* [42-40] format of access */
#define	LDST_REC_OPC_ROOT_SHIFT		43
#define	LDST_REC_OPC_ROOT_SIZE		 1	/*    [43] virtual space */
						/*	   type flag */
#define	LDST_REC_OPC_RG_SHIFT		44
#define	LDST_REC_OPC_RG_SIZE		 8	/* [51-44] physical address */
						/*	   of an NR (in terms */
						/*	   of single-NR) used */
						/*	   for handling */
						/*	   memory locks */
						/*	   conflicts */
#define	LDST_REC_OPC_FMT_H_SHIFT	52
#define	LDST_REC_OPC_FMT_H_SIZE		1	/* [52] format of access */
#define	LDST_REC_OPC_MODE_H_SHIFT	53
#define	LDST_REC_OPC_MODE_H_SIZE	1	/* [53] mode (hi) of access */
#define	LDST_REC_OPC_UNUSED_SHIFT	54
#define	LDST_REC_OPC_UNUZED_SIZE	2	/* [55-54] unused bits */

#define LDST_REC_OPC_MASK_SHIFT		56
#define LDST_REC_OPC_MASK_SIZE		8

#define	LDST_REC_OPC_PROT		(1UL << LDST_REC_OPC_PROT_SHIFT)
#define	LDST_REC_OPC_ROOT		(1UL << LDST_REC_OPC_ROOT_SHIFT)
#define	LDST_REC_OPC_MODE_H		(1UL << LDST_REC_OPC_MODE_H_SHIFT)
#define	LDST_REC_OPC_MODE_MASK		\
		(LDST_REC_OPC_PROT | LDST_REC_OPC_ROOT | LDST_REC_OPC_MODE_H)

#define	LDST_REC_OPC_GET_MODE(ldst_rec_opc)	\
		((((ldst_rec_opc) & LDST_REC_OPC_PROT) >> \
					(LDST_REC_OPC_PROT_SHIFT - 0)) | \
		(((ldst_rec_opc) & LDST_REC_OPC_ROOT) >> \
					(LDST_REC_OPC_ROOT_SHIFT - 1)) | \
		(((ldst_rec_opc) & LDST_REC_OPC_MODE_H) >> \
					(LDST_REC_OPC_MODE_H_SHIFT - 2)))
#define	LDST_REC_OPC_SET_MODE(ldst_rec_opc, mode)	\
		(((ldst_rec_opc) & ~LDST_REC_OPC_MODE_MASK) | \
			(((mode) & 0x01) << (LDST_REC_OPC_PROT_SHIFT - 0)) | \
			(((mode) & 0x02) << (LDST_REC_OPC_ROOT_SHIFT - 1)) | \
			(((mode) & 0x04) << (LDST_REC_OPC_MODE_H_SHIFT - 2)))

#ifndef	__ASSEMBLY__
typedef union {
	struct {
		u64 index	: 32;	// [31- 0]
		u64 mas		: 7;	// [38-32]
		u64 prot	: 1;	//    [39]
		u64 fmt		: 3;	// [42-40]
		u64 root	: 1;	//    [43]
		/* Used only on ES2 (E2K_ISET_V2), deprecated everywhere else. */
		u64 rg_deprecated : 8;	// [51-44]
		u64 fmt_h	: 1;	// [52]
		u64 mode_h	: 1;	// [53]
		u64 unused	: 2;	// [55-54]
		u64 mask	: 8;	// [63-56]
	};
	unsigned long word;
} ldst_rec_op_t;
#define	LD_ST_REC_OPC_index(ld_st_rec)	(ld_st_rec.index)
#define	LD_ST_REC_OPC_mas(ld_st_rec)	(ld_st_rec.mas)
#define	LD_ST_REC_OPC_prot(ld_st_rec)	(ld_st_rec.prot)
#define	LD_ST_REC_OPC_fmt(ld_st_rec)	(ld_st_rec.fmt)
#define	LD_ST_REC_OPC_root(ld_st_rec)	(ld_st_rec.root)
#define	LD_ST_REC_OPC_fmt_h(ld_st_rec)	(ld_st_rec.fmt_h)
#define	LD_ST_REC_OPC_mode_h(ld_st_rec)	(ld_st_rec.mode_h)
#define	LD_ST_REC_OPC_mask(ld_st_rec)	(ld_st_rec.mask)
#define	LD_ST_REC_OPC_reg(ld_st_rec)	(ld_st_rec.word)

#endif	/* ! __ASSEMBLY__ */

#define LDST_REC_OPC_BYPASS_L1		(MAS_BYPASS_L1_CACHE << \
							LDST_REC_OPC_MAS_SHIFT)
#define LDST_REC_OPC_BYPASS_CACHE	(MAS_BYPASS_ALL_CACHES << \
							LDST_REC_OPC_MAS_SHIFT)

#define	TAGGED_MEM_LOAD_REC_OPC	(0UL | \
			LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT | \
			MAS_FILL_OPERATION << LDST_REC_OPC_MAS_SHIFT)
#define	TAGGED_MEM_LOAD_REC_OPC_W (0UL | \
			LDST_WORD_FMT << LDST_REC_OPC_FMT_SHIFT | \
			MAS_FILL_OPERATION << LDST_REC_OPC_MAS_SHIFT)
#define	TAGGED_MEM_STORE_REC_OPC (LDST_QWORD_FMT << LDST_REC_OPC_FMT_SHIFT)
#define	TAGGED_MEM_STORE_REC_OPC_W (LDST_WORD_FMT << LDST_REC_OPC_FMT_SHIFT)
#define	MEM_STORE_REC_OPC_B (LDST_BYTE_FMT << LDST_REC_OPC_FMT_SHIFT)


#endif /* _E2K_MMU_TYPES_H_ */
