/*
 * asm-e2k/mmu_regs.h: E2K MMU structures & registers.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_MMU_REGS_TYPES_H_
#define	_E2K_MMU_REGS_TYPES_H_

#include <linux/types.h>

/*
 * MMU registers structures
 */

/* MMU address to access to MMU internal registers */

#ifndef __ASSEMBLY__
typedef	e2k_addr_t			mmu_addr_t;
#define	mmu_addr_val(mmu_addr)		(mmu_addr)
#define	__mmu_addr(mmu_addr_val)	(mmu_addr_val)
#endif /* __ASSEMBLY__ */

#define	_MMU_ADDR_REG_NO_SHIFT		4	/* [ 9: 4] */

#define _MMU_ADDR_REG_NO	0x0000000000000ff0	/* # of register */

#define _MMU_CR_NO		0x00	/* Control register */
#define _MMU_CONT_NO		0x01	/* Context register */
#define	_MMU_PID_NO		_MMU_CONT_NO	/* renamed name of CONT */
#define _MMU_CR3_RG_NO		0x02	/* CR3 register for secondary space */
#define	_MMU_U2_PPTB_NO		_MMU_CR3_RG_NO	/* renamed name of CR3 */
#define _MMU_ELB_PTB_NO		0x03	/* ELBRUS page table virtual base */
#define	_MMU_U_VPTB_NO		_MMU_ELB_PTB_NO	/* renamed name of ELB_PTB */
#define _MMU_ROOT_PTB_NO	0x04	/* Root Page Table Base register */
#define	_MMU_U_PPTB_NO		_MMU_ROOT_PTB_NO /* renamed name of ROOT_PTB */
#define _MMU_TRAP_POINT_NO	0x05	/* Trap Pointer register */
#define _MMU_TRAP_COUNT_NO	0x06	/* Trap Counter register */
#define _MMU_MPT_B_NO		0x07	/* Phys Protection Table Base */
					/* register for secondary space */
#define _MMU_PCI_L_B_NO		0x08	/* PCI Low Bound register */
					/* for secondary space */
#define _MMU_US_CL_D_NO		0x09	/* User Stack Clearing Disable */
					/* register */
#define _MMU_PH_H_B_NO		0x0a	/* Low Phys memory High Bound */
					/* for secondary space */
#define _MMU_USED_4KB_DTLB_NO	0x0b	/* ??? */
#define	_MMU_USED_DTLB_MPT_DW_NO 0x0c	/* ??? */
#define	_MMU_APIC_BASE_NO	0x0d	/* local APIC/EPIC registers base */
#define	_MMU_HW0_NO		0x0e	/* MMU hardware register #0 */
#define	_MMU_PID2_NO		0x0f	/* secondary process ID */
#define _MMU_MTRR_START_NO	0x10	/* Memory Type Range Register */
					/* (first register) */
					/* for secondary space */
#define _MMU_MTRR_PAIRS_END_NO	0x1f	/* Memory Type Range Register */
					/* (mtrr15 - last pairs register) */
					/* for secondary space */
#define _MMU_MTRR_END_NO	0x30	/* Memory Type Range Register */
					/* (last register) */
					/* for secondary space */
#define	_MMU_PAT_NO		0x31	/* page attribute table */
#define	_MMU_PH_HI_L_B_NO	0x32	/* High Phys memory Low Bound */
					/* for secondary space */
#define	_MMU_PH_HI_H_B_NO	0x33	/* High Phys memory High Bound */
					/* for secondary space */
#define	_MMU_OS_VPTB_NO		0x34	/* virtual base of kernel PTs */
#define	_MMU_OS_PPTB_NO		0x35	/* physical base of kernel PTs */
#define	_MMU_PDPTE0_NO		0x38	/* pud[0] 3-th level PT entry #0 */
#define	_MMU_PDPTE1_NO		0x39	/* pud[1] 3-th level PT entry #1 */
#define	_MMU_PDPTE2_NO		0x3a	/* pud[2] 3-th level PT entry #2 */
#define	_MMU_PDPTE3_NO		0x3b	/* pud[3] 3-th level PT entry #3 */
#define	_MMU_TLU_CACHE_NO	0x3c	/* TLU cache ??? */
#define	_MMU_OS_VAB_NO		0x4c	/* kernel virtual space base */
					/* PAGE_OFFSET */
#define	MMU_REGS_NUM		(_MMU_MTRR_END_NO + 1)
#define MTRR_LAST_DEFAULT	0x806	/* Default value of last MTRR */

#define	_MMU_REG_NO_TO_MMU_ADDR_VAL(reg_no)	\
		(((reg_no) << _MMU_ADDR_REG_NO_SHIFT) & _MMU_ADDR_REG_NO)
#define	MMU_REG_NO_TO_MMU_ADDR(reg_no)	\
		__mmu_addr(_MMU_REG_NO_TO_MMU_ADDR_VAL(reg_no))
#define	MMU_REG_NO_FROM_MMU_ADDR(mmu_addr) \
		((mmu_addr_val(mmu_addr) & _MMU_ADDR_REG_NO) >> \
		_MMU_ADDR_REG_NO_SHIFT)

#define	MMU_ADDR_CR		MMU_REG_NO_TO_MMU_ADDR(_MMU_CR_NO)
#define	MMU_ADDR_CONT		MMU_REG_NO_TO_MMU_ADDR(_MMU_CONT_NO)
#define	MMU_ADDR_PID		MMU_ADDR_CONT	/* renamed name */
#define	MMU_ADDR_CR3_RG		MMU_REG_NO_TO_MMU_ADDR(_MMU_CR3_RG_NO)
#define	MMU_ADDR_U2_PGTB	MMU_ADDR_CR3_RG	/* renamed name */
#define	MMU_ADDR_ELB_PTB	MMU_REG_NO_TO_MMU_ADDR(_MMU_ELB_PTB_NO)
#define	MMU_ADDR_U_VPTB		MMU_ADDR_ELB_PTB	/* rename name */
#define	MMU_ADDR_ROOT_PTB	MMU_REG_NO_TO_MMU_ADDR(_MMU_ROOT_PTB_NO)
#define	MMU_ADDR_U_PPTB		MMU_ADDR_ROOT_PTB	/* rename name */
#define	MMU_ADDR_TRAP_POINT	MMU_REG_NO_TO_MMU_ADDR(_MMU_TRAP_POINT_NO)
#define	MMU_ADDR_TRAP_COUNT	MMU_REG_NO_TO_MMU_ADDR(_MMU_TRAP_COUNT_NO)
#define	MMU_ADDR_MPT_B		MMU_REG_NO_TO_MMU_ADDR(_MMU_MPT_B_NO)
#define	MMU_ADDR_PCI_L_B	MMU_REG_NO_TO_MMU_ADDR(_MMU_PCI_L_B_NO)
#define	MMU_ADDR_US_CL_D	MMU_REG_NO_TO_MMU_ADDR(_MMU_US_CL_D_NO)
#define	MMU_ADDR_PH_H_B		MMU_REG_NO_TO_MMU_ADDR(_MMU_PH_H_B_NO)
#define	MMU_ADDR_WATCH_POINT	MMU_REG_NO_TO_MMU_ADDR(_MMU_WATCH_POINT_NO)
#define	MMU_ADDR_MTRR_START	MMU_REG_NO_TO_MMU_ADDR(_MMU_MTRR_START_NO)
#define	MMU_ADDR_MTRR_END	MMU_REG_NO_TO_MMU_ADDR(_MMU_MTRR_END_NO)
#define	MMU_ADDR_MTRR(no)	MMU_REG_NO_TO_MMU_ADDR(no)
#define	MMU_ADDR_OS_VPTB	MMU_REG_NO_TO_MMU_ADDR(_MMU_OS_VPTB_NO)
#define	MMU_ADDR_OS_PPTB	MMU_REG_NO_TO_MMU_ADDR(_MMU_OS_PPTB_NO)
#define	MMU_ADDR_SH_OS_VPTB	MMU_REG_NO_TO_MMU_ADDR(_MMU_SH_OS_VPTB_NO)
#define	MMU_ADDR_SH_OS_PPTB	MMU_REG_NO_TO_MMU_ADDR(_MMU_SH_OS_PPTB_NO)
#define	MMU_ADDR_OS_VAB		MMU_REG_NO_TO_MMU_ADDR(_MMU_OS_VAB_NO)

/* MMU internel register contents */

#ifndef __ASSEMBLY__
typedef	unsigned long long		mmu_reg_t;
#define	mmu_reg_val(mmu_reg)		(mmu_reg)
#define	__mmu_reg(mmu_reg_val)		(mmu_reg_val)

/* Size of trap_cellar */

/* while bug for size of env for setjmp use TC_INTO_PT_REGS == 0 */
#define MAX_TC_SIZE		10

/*
 * MMU Control Register MMU_CR
 */

typedef union {
	struct {
		u64 tlb_en  : 1;
		u64 cd      : 2;
		u64 set1    : 1;
		u64 set2    : 1;
		u64 set3    : 1;
		u64 cr0_pg  : 1;
		u64 cr4_pse : 1;
		u64 cr0_cd  : 1;
		u64 tlu2_en : 1;
		u64 spae    : 1;
		u64 ipd     : 1;
		u64 upt     : 1;
		u64 slma    : 1;
		u64 spcd    : 1;
		u64 snxe    : 1;
		u64         : 48;
	};
	u64 word;
} e2k_mmu_cr_t;

#define MMU_CR_CD_EN		0UL	/* all caches enabled */
#define MMU_CR_CD_D1_DIS	1UL	/* L1D disabled */
#define MMU_CR_CD_D_DIS		2UL	/* L1D and L2 disabled */
#define MMU_CR_CD_DIS		3UL	/* all caches disabled */
#define MMU_CR_IPD_DIS		0UL	/* Disable icache prefetch */
#define MMU_CR_IPD_2_LINES	1UL	/* 2 icache lines for prefetch */

#define	MMU_CR_KERNEL ((e2k_mmu_cr_t) { \
	/* Important: C dictates that exactly 1 union member is initialized, \
	 * otherwise the later initialization will have priority. */ \
	tlb_en : 1, \
	cd     : MMU_CR_CD_EN, \
	ipd    : MMU_CR_IPD_2_LINES, \
	set3   : 1, \
})
#define	MMU_CR_KERNEL_OFF ((e2k_mmu_cr_t) { \
	cd     : MMU_CR_CD_DIS, \
	ipd    : MMU_CR_IPD_DIS, \
})
#endif /* __ASSEMBLY__ */

/*
 * MMU Process ID Register MMU_PID (renamed name from MMU_CONT)
 */

#define _MMU_CONTEXT		0x0000000000000fff
#define	_MMU_CONTEXT_SIZE	(_MMU_CONTEXT + 1)
#define MMU_PID_SIZE		_MMU_CONTEXT_SIZE

/*
 * Kernel virtual memory context
 */
#define	E2K_KERNEL_CONTEXT	0x000
#define	E2K_KERNEL_PID		E2K_KERNEL_CONTEXT	/* renamed name */

#define MMU_CONTEXT(context)	__mmu_reg(context)
#define	MMU_KERNEL_CONTEXT	MMU_CONTEXT(E2K_KERNEL_CONTEXT)
#define	MMU_PID(pid)		MMU_CONTEXT(pid)	/* renamed name */
#define	MMU_KERNEL_PID		MMU_KERNEL_CONTEXT	/* renamed name */

/*
 * MMU Control Register of secondary space table MMU_CR3_RG
 * The physical address of the INTEL page directory base,
 * aligned to table size
 */

#define _MMU_CR3_PAGE_DIR	0x0000000fffff000UL
#define	_MMU_CR3_PCD		0x000000000000010UL
#define	_MMU_CR3_PWT		0x000000000000008UL

#define	MMU_CR3_KERNEL(page_dir)	\
				(((e2k_addr_t)(page_dir)) & _MMU_CR3_PAGE_DIR)

/*
 * MMU Page Table virtual Base Registers MMU_OS_VPTB & MMU_U_VPTB
 * (renamed MMU_ELB_PTB)
 * The virtual address of the page table beginning, aligned to table size
 */
/* OS page table virtual base for separate virtual spaces */
#define	_MMU_VPTB_MASK			(PGDIR_MASK & E2K_VA_PAGE_MASK)
#define	MMU_ADDR_TO_VPTB(virt_addr)	\
		__mmu_reg((virt_addr) & _MMU_VPTB_MASK)

/* Separate Page Tables virtual bases */
#define	MMU_SEPARATE_KERNEL_VPTB	MMU_ADDR_TO_VPTB(KERNEL_VPTB_BASE_ADDR)
#define	MMU_SEPARATE_USER_VPTB		MMU_ADDR_TO_VPTB(USER_VPTB_BASE_ADDR)
/* United Page Tables virtual base */
#define	MMU_UNITED_KERNEL_VPTB		MMU_ADDR_TO_VPTB(KERNEL_VPTB_BASE_ADDR)
#define	MMU_UNITED_USER_VPTB		MMU_UNITED_KERNEL_VPTB

/*
 * MMU Root Page Table physical Bases register MMU_OS_PPTB & MMU_U_PPTB
 * (renamed MMU_ROOT_PTB)
 * The physical address of the root elbrus page table beginning,
 * aligned to table size
 */

#define _MMU_PPTB_MASK			(MAX_PA_MASK & PAGE_MASK)
#define MMU_ADDR_TO_PPTB(phys_addr)	__mmu_reg((phys_addr) & _MMU_PPTB_MASK)
#define MMU_KERNEL_PPTB			MMU_ADDR_TO_PPTB(KERNEL_PPTB_BASE_ADDR)

/* Separate Page Tables physical bases */
#define MMU_SEPARATE_KERNEL_PPTB	MMU_KERNEL_PPTB
#define	MMU_SEPARATE_USER_PPTB(phys_addr) MMU_ADDR_TO_PPTB(phys_addr)
/* United Page Tables virtual base */
#define	MMU_UNITED_KERNEL_PPTB		MMU_KERNEL_PPTB
#define	MMU_UNITED_USER_PPTB(phys_addr)	MMU_ADDR_TO_PPTB(phys_addr)

/*
 * MMU Base address of virtual space of kernel MMU_OS_VAB
 * The virtual address of the kernel space should be aligned to 2**44
 */
#define _MMU_VAB_MASK			0x0000f00000000000
#define MMU_ADDR_TO_VAB(virt_addr)	__mmu_reg((virt_addr) & _MMU_VAB_MASK)
#define	MMU_SEPARATE_KERNEL_VAB		MMU_ADDR_TO_VAB(PAGE_OFFSET)

/*
 * MMU Trap Pointer register MMU_TRAP_POINT
 * The physical address of the beginning of an area, where the attributes
 * of nonexecuted requests to memory are stored in case of the exception
 * arising on it ("cellar")
 */

#define	MMU_ALIGN_TRAP_POINT_BASE_V3	9
#define	MMU_ALIGN_TRAP_POINT_BASE_MASK_V3	\
		((1UL << MMU_ALIGN_TRAP_POINT_BASE_V3) - 1)
#define	MMU_TRAP_POINT_MASK_V3	~MMU_ALIGN_TRAP_POINT_BASE_MASK_V3
#define	MMU_TRAP_CELLAR_MAX_SIZE_V3		64	/* double-words */

#define	MMU_ALIGN_TRAP_POINT_BASE	10
#define	MMU_ALIGN_TRAP_POINT_BASE_MASK	((1UL << MMU_ALIGN_TRAP_POINT_BASE) - 1)
#define	MMU_TRAP_POINT_MASK		~MMU_ALIGN_TRAP_POINT_BASE_MASK
#define	MMU_TRAP_CELLAR_MAX_SIZE	\
		((TC_EXT_OFFSET + 7)/8 + 64)	/* double-words */

#define	_MMU_TRAP_POINT(phys_addr)	((phys_addr) & MMU_TRAP_POINT_MASK)
#define	MMU_TRAP_POINT(phys_addr)	__mmu_reg(_MMU_TRAP_POINT(phys_addr))
#define MMU_KERNEL_TRAP_POINT		MMU_TRAP_POINT(KERNEL_TRAP_CELLAR)

/*
 * MMU Trap Counter register MMU_TRAP_COUNT
 * Number of double-words in the "cellar" of the trap
 */

#define _MMU_TRAP_COUNT_MASK		0x000000000000002f
#define	_MMU_TRAP_COUNT(counter)	(counter & _MMU_TRAP_COUNT_MASK)
#define	MMU_TRAP_COUNT(counter)		__mmu_reg(_MMU_TRAP_COUNT(counter))
#define	MMU_TRAP_COUNT_GET(mmu_reg)	_MMU_TRAP_COUNT(mmu_reg_val(mmu_reg))

#define	mmu_trap_count_get(mmu_reg)	MMU_TRAP_COUNT_GET(mmu_reg)

/*
 * MMU PCI Low Bound MMU_PCI_L_B
 * Fix the boundary between PCIand main memory addresses
 * for Intel accesses
 */

#define _MMU_PCI_L_B		0x00000000ffc00000UL
#define	_MMU_PCI_L_B_ALIGN_MASK	0x00000000003fffffUL

/*
 * MMU Phys High Bound MMU_PH_H_B
 * Fix the high boundary Intel physical memory
 * for Intel accesses
 */

#define _MMU_PH_H_B		0x00000000ffc00000UL
#define	_MMU_PH_H_B_ALIGN_MASK	0x00000000003fffffUL

/*
 * CACHEs (DCACHE & ICACHE) structure
 */

#define	E2K_DCACHE_L1_LINES_BITS_NUM	9
#define	E2K_DCACHE_L1_LINES_NUM		(1 << E2K_DCACHE_L1_LINES_BITS_NUM)
#define	E2K_DCACHE_L1_SETS_BITS_NUM	2
#define	E2K_DCACHE_L1_SETS_NUM		(1 << E2K_DCACHE_L1_SETS_BITS_NUM)

#define	E2K_DCACHE_L2_LINES_BITS_NUM	10
#define	E2K_DCACHE_L2_LINES_NUM		(1 << E2K_DCACHE_L2_LINES_BITS_NUM)
#define	E2K_DCACHE_L2_SETS_BITS_NUM	2
#define	E2K_DCACHE_L2_SETS_NUM		(1 << E2K_DCACHE_L2_SETS_BITS_NUM)

#define	E2K_ICACHE_SETS_NUM		4
#define	E2K_ICACHE_SET_SIZE		256
#define	E2K_ICACHE_SET_MASK		(E2K_ICACHE_SET_SIZE - 1)
#define	E2K_ICACHE_LINES_NUM		64

/*
 * CACHEs (DCACHE & ICACHE) registers operations
 */

/* CACHEs (DCACHE & ICACHE) registers access operations address */

#ifndef	__ASSEMBLY__
typedef	e2k_addr_t	dcache_addr_t;
typedef dcache_addr_t	dcache_l1_addr_t;
typedef dcache_addr_t	dcache_l2_addr_t;
#endif	/* ! __ASSEMBLY__ */

#define dcache_addr_val(dcache_addr)	      (dcache_addr)
#define dcache_l1_addr_val(dcache_l1_addr)    dcache_addr_val(dcache_l1_addr)
#define dcache_l2_addr_val(dcache_l2_addr)    dcache_addr_val(dcache_l2_addr)

#define __dcache_addr(dcache_addr_val)	      (dcache_addr_val)
#define __dcache_l1_addr(dcache_l1_addr_val)  __dcache_addr(dcache_l1_addr_val)
#define __dcache_l2_addr(dcache_l2_addr_val)  __dcache_addr(dcache_l2_addr_val)

#define _E2K_DCACHE_L1_SET		0x00000000C0000000
#define _E2K_DCACHE_L1_TYPE		0x0000000020000000
#define _E2K_DCACHE_L1_TYPE_H		0x0000000008000000
#define _E2K_DCACHE_L1_LINE		0x0000000000003FE0
#define _E2K_DCACHE_L1_WORD		0x0000000000000018

#define _E2K_DCACHE_L1_SET_SHIFT	30
#define _E2K_DCACHE_L1_TYPE_SHIFT	29
#define _E2K_DCACHE_L1_TYPE_H_SHIFT	27
#define _E2K_DCACHE_L1_LINE_SHIFT	5
#define _E2K_DCACHE_L1_WORD_SHIFT	3

#define	DCACHE_L1_VADDR_TO_ADDR(virt_addr)				     \
		((virt_addr) & _E2K_DCACHE_L1_LINE)

#define	dcache_l1_set_set(addr, set)					     \
		(__dcache_l1_addr(					     \
			(dcache_l1_addr_val(addr) & ~_E2K_DCACHE_L1_SET) |   \
			((set) << _E2K_DCACHE_L1_SET_SHIFT) &		     \
			_E2K_DCACHE_L1_SET))
#define	dcache_l1_get_set(addr)						     \
		(dcache_l1_addr_val(addr) & _E2K_DCACHE_L1_SET)

#define	dcache_l1_set_type_h(addr, type_h)				      \
		(__dcache_l1_addr(					      \
			(dcache_l1_addr_val(addr) & ~_E2K_DCACHE_L1_TYPE_H) | \
			((type_h) << _E2K_DCACHE_L1_TYPE_H_SHIFT) &	      \
			_E2K_DCACHE_L1_TYPE_H))
#define	dcache_l1_get_type_h(addr)					     \
		(dcache_l1_addr_val(addr) & _E2K_DCACHE_L1_TYPE_H)

#define	dcache_l1_set_type(addr, type)					     \
		(__dcache_l1_addr(					     \
			(dcache_l1_addr_val(addr) & ~_E2K_DCACHE_L1_TYPE) |  \
			((type) << _E2K_DCACHE_L1_TYPE_SHIFT) &		     \
			_E2K_DCACHE_L1_TYPE))
#define	dcache_l1_get_type(addr)					     \
		(dcache_l1_addr_val(addr) & _E2K_DCACHE_L1_TYPE)

#define	dcache_l1_set_line(addr, line)					     \
		(__dcache_l1_addr(					     \
			(dcache_l1_addr_val(addr) & ~_E2K_DCACHE_L1_LINE) |  \
			((line) << _E2K_DCACHE_L1_LINE_SHIFT) &		     \
			_E2K_DCACHE_L1_LINE))
#define	dcache_l1_get_line(addr)					     \
		(dcache_l1_addr_val(addr) & _E2K_DCACHE_L1_LINE)

#define	dcache_l1_set_word(addr, word)					     \
		(__dcache_l1_addr(					     \
			(dcache_l1_addr_val(addr) & ~_E2K_DCACHE_L1_WORD) |  \
			((word) << _E2K_DCACHE_L1_WORD_SHIFT) &		     \
			_E2K_DCACHE_L1_WORD))
#define	dcache_l1_get_word(addr)					     \
		(dcache_l1_addr_val(addr) & _E2K_DCACHE_L1_WORD)

#define mk_dcache_l1_addr(virt_addr, set, type, type_h, word)		     \
({									     \
	dcache_l1_addr_t addr;						     \
	addr = __dcache_l1_addr(DCACHE_L1_VADDR_TO_ADDR(virt_addr));	     \
	addr = dcache_l1_set_set(addr, set);				     \
	addr = dcache_l1_set_type(addr, type);				     \
	addr = dcache_l1_set_type_h(addr, type_h);			     \
	addr = dcache_l1_set_word(addr, word);				     \
	addr;								     \
})

#define _E2K_DCACHE_L2_TYPE		0x0000000030000000
 #define _E2K_DCACHE_L2_DATA_TYPE		0x0
 #define _E2K_DCACHE_L2_REGS_TYPE		0x1
 #define _E2K_DCACHE_L2_TAG_TYPE		0x2
 #define _E2K_DCACHE_L2_REGS_TYPE2		0x3
#define _E2K_DCACHE_L2_LINE		0x000000000007ffc0
#define	_E2K_DCACHE_L2_REG_NUM		0x000000000000ff00
 #define _E2K_DCACHE_L2_BIST_SIG1_REG		0x00
 #define _E2K_DCACHE_L2_BIST_SIG2_REG		0x01
 #define _E2K_DCACHE_L2_BISR_CTRL_REG		0x02
 #define _E2K_DCACHE_L2_CTRL_REG		0x03
 #define _E2K_DCACHE_L2_ECC_DBG_REG		0x04
 #define _E2K_DCACHE_L2_ERR_REG			0x05
 #define _E2K_DCACHE_L2_CNT_ERR1_REG		0x06
 #define _E2K_DCACHE_L2_CNT_ERR2_REG		0x07
 #define _E2K_DCACHE_L2_CTRL_EXT_REG		0x08
#define	_E2K_DCACHE_L2_BANK_NUM		0x00000000000000c0
#define _E2K_DCACHE_L2_WORD		0x0000000000000038

#define _E2K_DCACHE_L2_TYPE_SHIFT	28
#define _E2K_DCACHE_L2_LINE_SHIFT	6
#define _E2K_DCACHE_L2_REG_NUM_SHIFT	8
#define _E2K_DCACHE_L2_BANK_NUM_SHIFT	6
#define _E2K_DCACHE_L2_WORD_SHIFT	3

#define	E2K_L2_BANK_NUM			4

#define	E2K_L2_CNTR_EN_CORR		0x0000000000000001
#define	E2K_L2_CNTR_EN_DET		0x0000000000000002
#define	E2K_L2_CNTR_EN_CINT		0x0000000000000004

#define	DCACHE_L2_PADDR_TO_ADDR(phys_addr)				     \
		((virt_addr) & _E2K_DCACHE_L2_LINE)

#define	dcache_l2_set_type(addr, type)					     \
		(__dcache_l2_addr(					     \
			(dcache_l2_addr_val(addr) & ~_E2K_DCACHE_L2_TYPE) |  \
			((type) << _E2K_DCACHE_L2_TYPE_SHIFT) &		     \
			_E2K_DCACHE_L2_TYPE))
#define	dcache_l2_get_type(addr)					     \
		(dcache_l2_addr_val(addr) & _E2K_DCACHE_L2_TYPE)

#define	dcache_l2_set_line(addr, line)					     \
		(__dcache_l2_addr(					     \
			(dcache_l2_addr_val(addr) & ~_E2K_DCACHE_L2_LINE) |  \
			((index) << _E2K_DCACHE_L2_LINE_SHIFT) &	     \
			_E2K_DCACHE_L2_LINE))
#define	dcache_l2_get_line(addr)					     \
		(dcache_l2_addr_val(addr) & _E2K_DCACHE_L2_LINE)

#define	dcache_l2_set_reg_num(addr, reg_num)				     \
		(__dcache_l2_addr(					     \
			(dcache_l2_addr_val(addr) &			     \
				~_E2K_DCACHE_L2_REG_NUM) |		     \
			((reg_num) << _E2K_DCACHE_L2_REG_NUM_SHIFT) &	     \
			_E2K_DCACHE_L2_REG_NUM))
#define	dcache_l2_get_reg_num(addr)					     \
		(dcache_l2_addr_val(addr) & _E2K_DCACHE_L2_REG_NUM_SHIFT)

#define	dcache_l2_set_bank_num(addr, bank_num)				     \
		(__dcache_l2_addr(					     \
			(dcache_l2_addr_val(addr) &			     \
				~_E2K_DCACHE_L2_BANK_NUM) |		     \
			((bank_num) << _E2K_DCACHE_L2_BANK_NUM_SHIFT) &      \
			_E2K_DCACHE_L2_BANK_NUM))
#define	dcache_l2_get_bank_num(addr)					     \
		(dcache_l2_addr_val(addr) & _E2K_DCACHE_L2_BANK_NUM_SHIFT)

#define	dcache_l2_set_word(addr, word)					     \
		(__dcache_l2_addr(					     \
			(dcache_l2_addr_val(addr) & ~_E2K_DCACHE_L2_WORD) |  \
			((word) << _E2K_DCACHE_L2_WORD_SHIFT) &		     \
			_E2K_DCACHE_L2_WORD))
#define	dcache_l2_get_word(addr)					     \
		(dcache_l2_addr_val(addr) & _E2K_DCACHE_L2_WORD)

#define mk_dcache_l2_addr(phys_addr, type, word)			     \
({									     \
	dcache_l2_addr_t addr = 0;					     \
	addr = __dcache_l2_addr(DCACHE_L1_PADDR_TO_ADDR(phys_addr));	     \
	addr = dcache_l2_set_type(addr, type);				     \
	addr = dcache_l2_set_word(addr, word);				     \
	addr;								     \
})

#define mk_dcache_l2_reg_addr(reg_num, bank_num)			     \
({									     \
	dcache_l2_addr_t addr = 0;					     \
	addr = dcache_l2_set_type(addr, _E2K_DCACHE_L2_REGS_TYPE);	     \
	addr = dcache_l2_set_reg_num(addr, reg_num);			     \
	addr = dcache_l2_set_bank_num(addr, bank_num);			     \
	addr;								     \
})

/*
 * ICACHE/DTLB/ITLB line flush operations
 */

/* ICACHE/DTLB/ITLB line flush operations address */

#ifndef	__ASSEMBLY__
typedef	e2k_addr_t			flush_op_t;
#endif	/* ! __ASSEMBLY__ */

#define FLUSH_OP_TYPE			ULL(7)	/* type of operation */
#define	FLUSH_ICACHE_LINE_USER_OP	ULL(0)
#define	FLUSH_TLB_PAGE_OP		ULL(1)
#define	FLUSH_ICACHE_LINE_SYS_OP	ULL(2)
#define	FLUSH_TLB_PAGE_TLU_CACHE_OP	ULL(3)

#define	flush_op_get_type(flush_op)	((flush_op) & FLUSH_OP_TYPE)
#define	flush_op_set_type(flush_op, type)	\
		(((flush_op) & ~FLUSH_OP_TYPE) | ((type) & FLUSH_OP_TYPE))

/* ICACHE/DTLB/ITLB line flush extended virtual address structure */

#ifndef	__ASSEMBLY__
typedef	e2k_addr_t			flush_addr_t;
#endif	/* ! __ASSEMBLY__ */

#define	FLUSH_ADDR_CONTEXT_SHIFT ULL(50)		/* [61:50] */
#define FLUSH_ADDR_VA		ULL(0x0000ffffffffffff)	/* virtual address */
#define FLUSH_ADDR_CONTEXT	ULL(0x3ffc000000000000)	/* context # */
#define FLUSH_ADDR_ROOT		ULL(0x4000000000000000)	/* should be 0 */
#define FLUSH_ADDR_PHYS		ULL(0x8000000000000000)	/* should be 0 */

#define	FLUSH_VADDR_TO_VA(virt_addr)	((virt_addr) & FLUSH_ADDR_VA)

#define	flush_addr_get_pid(flush_addr)	\
		(((flush_addr) & FLUSH_ADDR_CONTEXT) >> FLUSH_ADDR_CONTEXT_SHIFT)
#define	_flush_addr_make_sys(virt_addr, context, root)			\
({									\
	e2k_addr_t __addr_val = FLUSH_VADDR_TO_VA(virt_addr);		\
	__addr_val |= (((long)(context) << FLUSH_ADDR_CONTEXT_SHIFT) &	\
				FLUSH_ADDR_CONTEXT);			\
	if (root)							\
		__addr_val |= FLUSH_ADDR_ROOT;				\
	__addr_val;							\
})
#define	flush_addr_make_sys(virt_addr, context) \
		_flush_addr_make_sys((virt_addr), (context), 0)
#define	flush_addr_make_user(virt_addr)		FLUSH_VADDR_TO_VA(virt_addr)
#define	flush_addr_make_ss(virt_addr, context) \
		_flush_addr_make_sys((virt_addr), (context), 1)

/*
 * CACHE(s) flush operations
 */

/* CACHE(s) flush operations address */

#define	_FLUSH_WRITE_BACK_CACHE_L12_OP	0x0000000000000001

/* instruction set begining V3 has not invalidate operation */
/* only flush all caches (same as write back) */
#define	_FLUSH_CACHE_L12_OP		_FLUSH_WRITE_BACK_CACHE_L12_OP

#define	flush_op_set_write_back_cache_L12(flush_op)	\
		flush_op_set_type(flush_op, _FLUSH_WRITE_BACK_CACHE_L12_OP)
#define	flush_op_set_cache_all(flush_op)		\
		flush_op_set_write_back_cache_L12(flush_op)
#define	flush_op_write_back_cache_L12	((long)_FLUSH_WRITE_BACK_CACHE_L12_OP)

/*
 * ICACHE/TLB flush operations
 */

/* ICACHE/TLB flush operations address */

#define	_FLUSH_ICACHE_ALL_OP		0x0000000000000000
#define	_FLUSH_TLB_ALL_OP		0x0000000000000001

#define	flush_op_set_icache_all(flush_op)	\
		flush_op_set_type(flush_op, _FLUSH_ICACHE_ALL_OP)
#define	flush_op_set_tlb_all(flush_op)	\
		flush_op_set_type(flush_op, _FLUSH_TLB_ALL_OP)
#define	flush_op_icache_all		((long)_FLUSH_ICACHE_ALL_OP)
#define	flush_op_tlb_all		((long)_FLUSH_TLB_ALL_OP)


/*
 * MU address to access to CLW internal registers
 */

#ifndef __ASSEMBLY__
typedef	e2k_addr_t			clw_addr_t;
#endif /* __ASSEMBLY__ */

#define ADDR_US_CL_B		0x024	/* User stack bottom to clean */
#define ADDR_US_CL_UP		0x124	/* User stack up to clean */
#define ADDR_US_CL_M0		0x004	/* User stack bit-mask [0:63] */
#define ADDR_US_CL_M1		0x084	/* User stack bit-mask [64:127] */
#define ADDR_US_CL_M2		0x104	/* User stack bit-mask [128:195] */
#define ADDR_US_CL_M3		0x184	/* User stack bit-mask [196:255] */

/* CLW internel register contents */

#ifndef __ASSEMBLY__
typedef	unsigned long			clw_reg_t;
#endif /* __ASSEMBLY__ */

/*
 * User Stack Window clean bit-mask structure
 */

#define	CLW_MASK_WORD_NUM	 4	/* number of words in bit-mask */
#define	CLW_BITS_PER_MASK_WORD	64	/* number of bits in one bit-mask */
					/* word */
#define	CLW_BYTES_PER_BIT	32	/* one bit describes 32 bytes of */
					/* stack area */
#define	CLW_BYTES_PER_MASK		/* number of bytes in full bit-mask */ \
		(CLW_BYTES_PER_BIT * CLW_MASK_WORD_NUM * CLW_BITS_PER_MASK_WORD)

/*
 * MMU DEBUG registers
 */

#define	_MMU_ADDR_REGS_TYPE	0x0000000000000007	/* [2:0] type of op. */
#define _MMU_ADDR_DEBUG_REG_NO	0x00000000000001e0	/* [8:5] # of reg. */
#define	_MMU_ADDR_DEBUG_REG_NO_SHIFT		5	/* [8:5] */
#define	_MMU_ADDR_DEBUG_REG_TYPE		7	/* access to DEBUG */
							/* registers */

#define MMU_DDBAR0_REG_NO	0	/* Data access breakpoint address */
#define MMU_DDBAR1_REG_NO	1	/* registers # 0 - 3 */
#define MMU_DDBAR2_REG_NO	2
#define MMU_DDBAR3_REG_NO	3
#define MMU_DDBCR_REG_NO	4	/* Data access breakpoint control */
#define MMU_DDBSR_REG_NO	5	/* Data access breakpoint status */
#define MMU_DDMAR0_REG_NO	6	/* Data monitor accumulator */
#define MMU_DDMAR1_REG_NO	7	/* registers # 0 - 1 */
#define MMU_DDMCR_REG_NO	8	/* Data monitor control register */
#define	MMU_DEBUG_REGS_NUM	(MMU_DDMCR_REG_NO + 1)

#define	_DEBUG_REG_NO_TO_MMU_ADDR(reg_no)	\
		((((reg_no) << _MMU_ADDR_DEBUG_REG_NO_SHIFT) & \
			_MMU_ADDR_DEBUG_REG_NO) | _MMU_ADDR_DEBUG_REG_TYPE)

#ifndef	__ASSEMBLY__

typedef union {
	u32 half_word[2];
	struct {               /* structure of register */
		u32 user    : 1;     /*  [ 0: 0] */
		u32 system  : 1;     /*  [ 1: 1] */
		u32 trap    : 1;     /*  [ 2: 2] */
		u32 unused  : 13;    /* [15: 3] */
		u32 event   : 7;     /* [22:16] */
		u32 unused2 : 9;     /* [31:23] */
	} fields[2];
	u64 word;
} e2k_ddmcr_t;
#define	DDMCR_reg	word

typedef union {
	struct {
		u64 b0    : 8;
		u64 unus7 : 4;
		u64 b1    : 8;
		u64 unus8 : 4;
		u64 b2    : 8;
		u64 unus9 : 4;
		u64 b3    : 8;
		u64 unu10 : 4;
		u64 unu11 : 1;
		u64 m0    : 1;
		u64 m1    : 1;
		u64 unu12 : 13;
	};
	union {
		struct {
			u64 sprg0 : 1;
			u64 spec0 : 1;
			u64 aprg0 : 1;
			u64 psf0  : 1;
			u64 csf0  : 1;
			u64 cut0  : 1;
			u64 pt0   : 1;
			u64 clw0  : 1;
			u64 unus1 : 4;

			u64 sprg1 : 1;
			u64 spec1 : 1;
			u64 aprg1 : 1;
			u64 psf1  : 1;
			u64 csf1  : 1;
			u64 cut1  : 1;
			u64 pt1   : 1;
			u64 clw1  : 1;
			u64 unus2 : 4;

			u64 sprg2 : 1;
			u64 spec2 : 1;
			u64 aprg2 : 1;
			u64 psf2  : 1;
			u64 csf2  : 1;
			u64 cut2  : 1;
			u64 pt2   : 1;
			u64 clw2  : 1;
			u64 unus3 : 4;

			u64 sprg3 : 1;
			u64 spec3 : 1;
			u64 aprg3 : 1;
			u64 psf3  : 1;
			u64 csf3  : 1;
			u64 cut3  : 1;
			u64 pt3   : 1;
			u64 clw3  : 1;
			u64 unus4 : 4;

			u64 unus5 : 1;
			u64 m0    : 1;	/* [49] */
			u64 m1    : 1;	/* [50] */
			u64 unus6 : 13;
		};
		struct {
			u64 b0    : 8;
			u64 unus7 : 4;
			u64 b1    : 8;
			u64 unus8 : 4;
			u64 b2    : 8;
			u64 unus9 : 4;
			u64 b3    : 8;
			u64 unu10 : 4;
			u64 unu11 : 16;
		};
	} fields;
	u64 word;
} e2k_ddbsr_t;
#define	DDBSR_reg	word

#define E2K_DDBSR_MASK(cp_num) (0xffULL << ((cp_num) * 12))
#define E2K_DDBSR_MASK_ALL_BP 0xff0ff0ff0ffULL

typedef	union {
	struct {
		u64 v0    : 1;
		u64 root0 : 1;
		u64 rw0   : 2;
		u64 lng0  : 3;
		u64 sync0 : 1;
		u64 spec0 : 1;
		u64 ap0   : 1;
		u64 sf0   : 1;
		u64 hw0   : 1;
		u64 t0    : 1;
		u64       : 1;
		u64 v1    : 1;
		u64 root1 : 1;
		u64 rw1   : 2;
		u64 lng1  : 3;
		u64 sync1 : 1;
		u64 spec1 : 1;
		u64 ap1   : 1;
		u64 sf1   : 1;
		u64 hw1   : 1;
		u64 t1    : 1;
		u64       : 1;
		u64 v2    : 1;
		u64 root2 : 1;
		u64 rw2   : 2;
		u64 lng2  : 3;
		u64 sync2 : 1;
		u64 spec2 : 1;
		u64 ap2   : 1;
		u64 sf2   : 1;
		u64 hw2   : 1;
		u64 t2    : 1;
		u64       : 1;
		u64 v3    : 1;
		u64 root3 : 1;
		u64 rw3   : 2;
		u64 lng3  : 3;
		u64 sync3 : 1;
		u64 spec3 : 1;
		u64 ap3   : 1;
		u64 sf3   : 1;
		u64 hw3   : 1;
		u64 t3    : 1;
		u64       : 1;
		u64 gm    : 1;
	};
	u64 word;
} e2k_ddbcr_t;
#define	DDBCR_reg	word

#define E2K_DDBCR_MASK(cp_num) (0x3FFFULL << ((cp_num) * 14))
#endif /* ! __ASSEMBLY__ */

#endif  /* _E2K_MMU_REGS_TYPES_H_ */
