/* $Id: mmu_regs.h,v 1.35 2009/12/10 17:34:00 kravtsunov_e Exp $
 * asm-e2k/mmu_regs.h: E2K MMU structures & registers.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_MMU_REGS_H_
#define	_E2K_MMU_REGS_H_

#include <linux/types.h>

#undef	DEBUG_MR_MODE
#undef	DebugMR
#define	DEBUG_MR_MODE		0	/* MMU registers access */
#define DebugMR(...)		DebugPrint(DEBUG_MR_MODE ,##__VA_ARGS__)

#undef	DEBUG_MCR_MODE
#undef	DebugMCR
#define	DEBUG_MCR_MODE		0	/* MMU CONTEXT registers access */
#define DebugMCR(...)		DebugPrint(DEBUG_MCR_MODE ,##__VA_ARGS__)

#undef	DEBUG_CLW_MODE
#undef	DebugCLW
#define	DEBUG_CLW_MODE		0	/* CLW registers access */
#define DebugCLW(...)		DebugPrint(DEBUG_CLW_MODE ,##__VA_ARGS__)

#undef	DEBUG_TLB_MODE
#undef	DebugTLB
#define	DEBUG_TLB_MODE		0	/* TLB registers access */
#define DebugTLB(...)		DebugPrint(DEBUG_TLB_MODE ,##__VA_ARGS__)

/*
 * MMU registers operations
 */

/* MMU address to access to MMU internal registers */

#ifndef __ASSEMBLY__
typedef	e2k_addr_t			mmu_addr_t;
#define	mmu_addr_val(mmu_addr)		(mmu_addr)
#define	__mmu_addr(mmu_addr_val)	(mmu_addr_val)
#endif /* __ASSEMBLY__ */

#define	_MMU_ADDR_REG_NO_SHIFT		4	/* [ 9: 4] */

#define _MMU_ADDR_REG_NO	0x00000000000003f0	/* # of register */

#define _MMU_CR_NO		0x00	/* Control register */
#define _MMU_CONT_NO		0x01	/* Context register */
#define _MMU_CR3_RG_NO		0x02	/* CR3 register for INTEL only */
#define _MMU_ELB_PTB_NO		0x03	/* ELBRUS page table virtual base */
#define _MMU_ROOT_PTB_NO	0x04	/* Root Page Table Base register */
#define _MMU_TRAP_POINT_NO	0x05	/* Trap Pointer register */
#define _MMU_TRAP_COUNT_NO	0x06	/* Trap Counter register */
#define _MMU_MPT_B_NO		0x07	/* Phys Protection Table Base */
					/* register for INTEL only */
#define _MMU_PCI_L_B_NO		0x08	/* PCI Low Bound register */
					/* for INTEL only */
#define _MMU_US_CL_D_NO		0x09	/* User Stack Clearing Disable */
					/* register */
#define _MMU_PH_H_B_NO		0x0a	/* Phys High Bound register */
					/* for INTEL only */
#define _MMU_WATCH_POINT_NO	0x0b	/* Watch point register */
#define _MMU_MTRR_START_NO	0x10	/* Memory Type Range Register */
					/* (first register) for INTEL only */
#define _MMU_MTRR_PAIRS_END_NO	0x1f	/* Memory Type Range Register */
					/* (mtrr15 - last pairs register) */
					/* for INTEL only */
#define _MMU_MTRR_END_NO	0x30	/* Memory Type Range Register */
					/* (last register) for INTEL only */
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
#define	MMU_ADDR_CR3_RG		MMU_REG_NO_TO_MMU_ADDR(_MMU_CR3_RG_NO)
#define	MMU_ADDR_ELB_PTB	MMU_REG_NO_TO_MMU_ADDR(_MMU_ELB_PTB_NO)
#define	MMU_ADDR_ROOT_PTB	MMU_REG_NO_TO_MMU_ADDR(_MMU_ROOT_PTB_NO)
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

/* MMU internel register contents */

#ifndef __ASSEMBLY__
typedef	unsigned long			mmu_reg_t;
#define	mmu_reg_val(mmu_reg)		(mmu_reg)
#define	__mmu_reg(mmu_reg_val)		(mmu_reg_val)
#endif /* __ASSEMBLY__ */

/*
 * MMU Control Register MMU_CR
 */

#define	_MMU_CR_CD_SHIFT	1
#define	_MMU_CR_IPD_SHIFT	11

#define _MMU_CR_TLB_EN		0x0000000000000001	/* translation enable */
#define _MMU_CR_CD_MASK		0x0000000000000006	/* cache disable bits */
#define _MMU_CR_SET1		0x0000000000000008	/* set #1 enable for */
							/* 4 MB pages */
#define _MMU_CR_SET2		0x0000000000000010	/* set #2 enable for */
							/* 4 MB pages */
#define _MMU_CR_SET3		0x0000000000000020	/* set #3 enable for */
							/* 4 MB pages */
#define _MMU_CR_CR0_PG		0x0000000000000040	/* paging enable for */
							/* second space INTEL */
#define _MMU_CR_CR4_PSE		0x0000000000000080	/* page size 4Mb */
							/* enable for second */
							/* space INTEL */
#define _MMU_CR_CR0_CD		0x0000000000000100	/* cache disable for */
							/* secondary space */
							/* INTEL */
#define _MMU_CR_TLU2_EN		0x0000000000000200	/* TLU enable for */
							/* secondary space */
							/* INTEL */
#define _MMU_CR_LD_MPT		0x0000000000000400	/* memory protection */
							/* table enable for */
							/* LD from secondary */
							/* space INTEL */
#define _MMU_CR_IPD_MASK	0x0000000000000800	/* Instruction */
							/* Prefetch Depth */
#define _MMU_CR_UPT_EN		0x0000000000001000	/* enable UPT */

#define	_MMU_CR_CD_VAL(x)	(((x) << _MMU_CR_CD_SHIFT) & _MMU_CR_CD_MASK)
#define _MMU_CD_EN	_MMU_CR_CD_VAL(0UL)	/* all caches enabled */
#define _MMU_CD_D1_DIS	_MMU_CR_CD_VAL(1UL)	/* DCACHE1 disabled */
#define _MMU_CD_D_DIS	_MMU_CR_CD_VAL(2UL)	/* DCACHE1, DCACHE2 disabled */
#define _MMU_CD_DIS	_MMU_CR_CD_VAL(3UL)	/* DCACHE1, DCACHE2, ECACHE */
						/* disabled */
#define	_MMU_CR_IPD_VAL(x)	(((x) << _MMU_CR_IPD_SHIFT) & _MMU_CR_IPD_MASK)
#define _MMU_IPD_DIS	_MMU_CR_IPD_VAL(0UL)	/* none prefetch */
#define _MMU_IPD_2_LINE	_MMU_CR_IPD_VAL(1UL)	/* 2 line of ICACHE prefetch */

#ifdef	CONFIG_IPD_DISABLE
#define	KERNEL_MMU_IPD	_MMU_IPD_DIS		/* none prefetch */
#else
#define	KERNEL_MMU_IPD	_MMU_IPD_2_LINE		/* 2 line of ICACHE prefetch */
#endif	/* CONFIG_IPD_DISABLE */

#ifndef	CONFIG_SECONDARY_SPACE_SUPPORT
#define	_MMU_CR_SEC_SPACE_EN
#define	_MMU_CR_SEC_SPACE_DIS
#else	/*  CONFIG_SECONDARY_SPACE_SUPPORT */
#define _MMU_CR_SEC_SPACE_EN	(_MMU_CR_CR0_PG | _MMU_CR_TLU2_EN)
#define _MMU_CR_SEC_SPACE_DIS	(_MMU_CR_CR0_CD)
#endif	/* ! CONFIG_SECONDARY_SPACE_SUPPORT */

#define __MMU_CR_KERNEL		(_MMU_CR_TLB_EN | _MMU_CD_EN | KERNEL_MMU_IPD)
#define __MMU_CR_KERNEL_OFF	(_MMU_CD_DIS | _MMU_IPD_DIS)

#ifdef CONFIG_HUGETLB_PAGE
# define _MMU_CR_KERNEL         (__MMU_CR_KERNEL | _MMU_CR_SET3)
#else
# define _MMU_CR_KERNEL (boot_cpu_has(CPU_HWBUG_LARGE_PAGES) ? \
			(__MMU_CR_KERNEL) : (__MMU_CR_KERNEL | _MMU_CR_SET3))
#endif

#define	MMU_CR_KERNEL		__mmu_reg(_MMU_CR_KERNEL)
#define	MMU_CR_KERNEL_OFF	__mmu_reg(__MMU_CR_KERNEL_OFF)

#define	mmu_cr_set_tlb_enable(mmu_reg)	\
		(mmu_reg_val(mmu_reg) | _MMU_CR_TLB_EN)

#define mmu_cr_set_vaddr_enable(mmu_reg)	\
		(mmu_reg_val(mmu_reg) | _MMU_CR_TLB_EN)

#define	mmu_cr_reset_tlb_enable(mmu_reg)	\
		(mmu_reg_val(mmu_reg) & ~(_MMU_CR_TLB_EN))

#define mmu_cr_reset_vaddr_enable(mmu_reg)	\
		(mmu_reg_val(mmu_reg) & ~(_MMU_CR_TLB_EN))

#define mmu_cr_set_large_pages(mmu_reg)	\
		(mmu_reg_val(mmu_reg) | _MMU_CR_SET3)
#define mmu_cr_reset_large_pages(mmu_reg)	\
		(mmu_reg_val(mmu_reg) & ~_MMU_CR_SET3)

/*
 * MMU Context Register MMU_CONT
 */

#define _MMU_CONTEXT		0x0000000000000fff
#define	_MMU_CONTEXT_SIZE	(_MMU_CONTEXT + 1)

#define MMU_CONTEXT(context)	__mmu_reg(context)
#define	MMU_KERNEL_CONTEXT	MMU_CONTEXT(E2K_KERNEL_CONTEXT)

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
 * MMU ELBRUS Page Table virtual Base Register MMU_ELB_PTB
 * The virtual address of the root elbrus page table beginning,
 * aligned to table size
 */

#define _MMU_ELB_PTB		0x0000ff8000000000

#define MMU_ELB_PTB(virt_addr)	__mmu_reg((virt_addr) & _MMU_ELB_PTB)
#define MMU_KERNEL_ELB_PTB	MMU_ELB_PTB(KERNEL_VMLPT_BASE_ADDR)

/*
 * MMU Root Page Table Base register MMU_ROOT_PTB
 * The physical address of the root elbrus page table beginning,
 * aligned to table size
 */

#define _MMU_ROOT_PTB		0x000000fffffff000UL

#define MMU_ROOT_PTB(phys_addr)	__mmu_reg((phys_addr) & _MMU_ROOT_PTB)
#define MMU_KERNEL_ROOT_PTB	MMU_ROOT_PTB(KERNEL_ROOT_PTB_BASE_ADDR)

/*
 * MMU Trap Pointer register MMU_TRAP_POINT
 * The physical address of the beginning of an area, where the attributes
 * of nonexecuted requests to memory are stored in case of the exception
 * arising on it ("cellar")
 */

#define	MMU_ALIGN_TRAP_POINT_BASE	9
#define	MMU_ALIGN_TRAP_POINT_BASE_MASK	((1UL << MMU_ALIGN_TRAP_POINT_BASE) - 1)
#define	MMU_TRAP_POINT_MASK		~MMU_ALIGN_TRAP_POINT_BASE_MASK
#define	MMU_TRAP_CELLAR_MAX_SIZE	64	/* double-words */

#define	_MMU_TRAP_POINT(phys_addr)	((phys_addr) & MMU_TRAP_POINT_MASK)
#define	MMU_TRAP_POINT(phys_addr)	__mmu_reg(_MMU_TRAP_POINT(phys_addr))
#define MMU_KERNEL_TRAP_POINT		MMU_TRAP_POINT(KERNEL_TRAP_CELLAR)

/*
 * MMU Trap Counter register MMU_TRAP_COUNT
 * Number of double-words in the "cellar" of the trap
 */

#define _MMU_TRAP_COUNT_MASK		0x000000000000002f
#define	_MMU_TRAP_COUNT(counter)	(counter & _MMU_TRAP_COUNT_MASK)
#define	MMU_TRAP_COUNT(counter)		__mmu_reg(_MMU_TRAP_COUNT(counter)
#define	MMU_TRAP_COUNT_GET(mmu_reg)	_MMU_TRAP_COUNT(mmu_reg_val(mmu_reg))

#define	mmu_trap_count_get(mmu_reg)	MMU_TRAP_COUNT_GET(mmu_reg)

/*
 * MMU Memory Protection Table Base MMU_MPT_B
 * The base address of Memory Protection Table,
 * aligned to table size
 */

#define _MMU_MPT_B		0x000000fffffff000UL

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

#ifndef __ASSEMBLY__
/*
 * Write MMU register
 */
#define	WRITE_MMU_REG(addr_val, reg_val)	\
		E2K_WRITE_MAS_D((addr_val), (reg_val), MAS_MMU_REG)

/*
 * Read MMU register
 */
#define	READ_MMU_REG(addr_val)	\
		E2K_READ_MAS_D((addr_val), MAS_MMU_REG)

/*
 * Read MMU Control register
 */
#define	read_MMU_CR()		read_MMU_reg(MMU_ADDR_CR)
#define	READ_MMU_CR()	\
		READ_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR_NO))

/*
 * Write MMU Control register
 */
#define	write_MMU_CR(mmu_cr)	write_MMU_reg(MMU_ADDR_CR, mmu_cr)
#define	WRITE_MMU_CR(mmu_cr)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR_NO), \
			mmu_reg_val(mmu_cr))

/*
 * Write MMU Context register
 */
#define	write_MMU_CONT(mmu_cont) \
			write_MMU_reg(MMU_ADDR_CONT, mmu_cont)
#define	WRITE_MMU_CONT(mmu_cont)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CONT_NO), \
			mmu_reg_val(mmu_cont))

/*
 * Write MMU Control Register of secondary space table
 */
#define	write_MMU_CR3_RG(mmu_page_dir) \
			write_MMU_reg(MMU_ADDR_CR3_RG, mmu_page_dir)
#define	WRITE_MMU_CR3_RG(mmu_page_dir)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR3_RG_NO), \
			mmu_reg_val(mmu_page_dir))

#define	get_MMU_CR3_RG()	\
		(unsigned long)mmu_reg_val(read_MMU_reg(MMU_ADDR_CR3_RG))
/*
 * Write MMU ELBRUS page table base register
 */
#define	write_MMU_ELB_PTB(mmu_elb_ptb) \
			write_MMU_reg(MMU_ADDR_ELB_PTB, mmu_elb_ptb)
#define	WRITE_MMU_ELB_PTB(mmu_elb_ptb)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_ELB_PTB_NO), \
			mmu_reg_val(mmu_elb_ptb))

/*
 * Write MMU root page table base register
 */
#define	write_MMU_ROOT_PTB(mmu_root_ptb) \
			write_MMU_reg(MMU_ADDR_ROOT_PTB, mmu_root_ptb)
#define	WRITE_MMU_ROOT_PTB(mmu_root_ptb)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_ROOT_PTB_NO), \
			mmu_reg_val(mmu_root_ptb))

/*
 * Set MMU Trap Point register
 */
#define	write_MMU_TRAP_POINT(trap_cellar)	\
		write_MMU_reg(MMU_ADDR_TRAP_POINT, \
			MMU_TRAP_POINT((e2k_addr_t)trap_cellar))
#define	WRITE_MMU_TRAP_POINT(trap_cellar)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL( \
						_MMU_TRAP_POINT_NO), \
			_MMU_TRAP_POINT((e2k_addr_t)trap_cellar))

/*
 * Set MMU Trap Counter register
 */
#define	write_MMU_TRAP_COUNT(counter)	\
		write_MMU_reg(MMU_ADDR_TRAP_COUNT, \
			(unsigned long)_MMU_TRAP_COUNT(counter))
#define	WRITE_MMU_TRAP_COUNT(counter)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL( \
						_MMU_TRAP_COUNT_NO), \
			(unsigned long)_MMU_TRAP_COUNT(counter))
#define	RESET_MMU_TRAP_COUNT()	WRITE_MMU_TRAP_COUNT(0)

/*
 * Read MMU Trap Counter register
 */
#define	get_MMU_TRAP_COUNT()	\
		(unsigned int)mmu_reg_val(read_MMU_reg(MMU_ADDR_TRAP_COUNT))
#define	READ_MMU_TRAP_COUNT()	\
		(unsigned int)(READ_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL( \
						_MMU_TRAP_COUNT_NO)))

/*
 * Set MMU Memory Protection Table Base register
 */
#define	write_MMU_MPT_B(base)	\
		write_MMU_reg(MMU_ADDR_MPT_B, base)
#define	WRITE_MMU_MPT_B(base)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_MPT_B_NO), \
			mmu_reg_val(base))
#define	get_MMU_MPT_B() \
		read_MMU_reg(MMU_ADDR_MPT_B)

/*
 * Set MMU PCI Low Bound register
 */
#define	write_MMU_PCI_L_B(bound)	\
		write_MMU_reg(MMU_ADDR_PCI_L_B, bound)
#define	WRITE_MMU_PCI_L_B(bound)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_PCI_L_B_NO), \
			mmu_reg_val(bound))

/*
 * Set MMU Phys High Bound register
 */
#define	write_MMU_PH_H_B(bound)	\
		write_MMU_reg(MMU_ADDR_PH_H_B, bound)
#define	WRITE_MMU_PH_H_B(bound)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_PH_H_B_NO), \
			mmu_reg_val(bound))

/*
 * Write User Stack Clean Window Disable register
 */
#define	set_MMU_US_CL_D(val) \
		write_MMU_reg(MMU_ADDR_US_CL_D, val)
#define	WRITE_MMU_US_CL_D(val)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_US_CL_D_NO), \
			mmu_reg_val(val))

/*
 * Read User Stack Clean Window Disable register
 */
#define	get_MMU_US_CL_D() \
		read_MMU_reg(MMU_ADDR_US_CL_D)
#define	READ_MMU_US_CL_D()	\
		(unsigned int)READ_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL( \
							_MMU_US_CL_D_NO))

/*
 * Set Memory Type Range Registers ( MTRRS )
 */
#define	WRITE_MTRR_REG(no, val)	\
		WRITE_MMU_REG(MMU_ADDR_MTRR(no), mmu_reg_val(val))

/*
 * Get Memory Type Range Registers ( MTRRS )
 */
#define	get_MMU_MTRR_REG(no)	\
		(unsigned long)READ_MMU_REG(MMU_ADDR_MTRR(no))

/*
 * TLB (DTLB & ITLB) structure
 */

#define	E3M_TLB_LINES_BITS_NUM		7
#define	E3M_TLB_LINES_NUM		(1 << E2K_TLB_LINES_BITS_NUM)
#define	E3S_TLB_LINES_BITS_NUM		8
#define	E3S_TLB_LINES_NUM		(1 << E3S_TLB_LINES_BITS_NUM)
#define	E2K_TLB_SETS_NUM		4
#define	E2K_TLB_LARGE_PAGE_SET_NO	3	/* large page entries */
						/* occupied this set in each */
						/* line */
#define	E2K_TLB_LINES_BITS_NUM		\
		((IS_MACHINE_E3M) ? E3M_TLB_LINES_BITS_NUM :	\
						E3S_TLB_LINES_BITS_NUM)
#define	E2K_TLB_LINES_NUM		\
		((IS_MACHINE_E3M) ? E3M_TLB_LINES_NUM : E3S_TLB_LINES_NUM)
#define	E2K_MAX_TLB_LINES_NUM		E3S_TLB_LINES_NUM

/*
 * CACHEs (DCACHE & ICACHE) structure
 */

#define	E2K_DCACHE_L1_LINES_BITS_NUM	9
#define	E2K_DCACHE_L1_LINES_NUM		(1 << E2K_DCACHE_L1_LINES_BITS_NUM)
#define	E2K_DCACHE_L1_SETS_BITS_NUM	2
#define	E2K_DCACHE_L1_SETS_NUM		(1 << E2K_DCACHE_L1_SETS_BITS_NUM)

#define	E2K_DCACHE_L2_LINES_BITS_NUM	10
#define	E2K_DCACHE_L2_LINES_NUM		(1 << E2K_DCACHE_L1_LINES_BITS_NUM)
#define	E2K_DCACHE_L2_SETS_BITS_NUM	2
#define	E2K_DCACHE_L2_SETS_NUM		(1 << E2K_DCACHE_L1_SETS_BITS_NUM)

#define	E2K_ICACHE_SETS_NUM		4
#define	E2K_ICACHE_SET_SIZE		256
#define	E2K_ICACHE_LINES_NUM		64

/*
 * CACHEs (DCACHE & ICACHE) registers operations
 */

/* CACHEs (DCACHE & ICACHE) registers access operations address */

typedef	e2k_addr_t	dcache_addr_t;
typedef dcache_addr_t	dcache_l1_addr_t;
typedef dcache_addr_t	dcache_l2_addr_t;


#define dcache_addr_val(dcache_addr)	      (dcache_addr)
#define dcache_l1_addr_val(dcache_l1_addr)    dcache_addr_val(dcache_l1_addr)
#define dcache_l2_addr_val(dcache_l2_addr)    dcache_addr_val(dcache_l2_addr)

#define __dcache_addr(dcache_addr_val)	      (dcache_addr_val)
#define __dcache_l1_addr(dcache_l1_addr_val)  __dcache_addr(dcache_l1_addr_val)
#define __dcache_l2_addr(dcache_l2_addr_val)  __dcache_addr(dcache_l2_addr_val)

#define _E2K_DCACHE_L1_SET		0x00000000C0000000
#define _E2K_DCACHE_L1_TYPE		0x0000000020000000
#define _E2K_DCACHE_L1_LINE		0x0000000000003FE0
#define _E2K_DCACHE_L1_WORD		0x0000000000000018

#define _E2K_DCACHE_L1_SET_SHIFT	30
#define _E2K_DCACHE_L1_TYPE_SHIFT	29
#define _E2K_DCACHE_L1_LINE_SHIFT	5
#define _E2K_DCACHE_L1_WORD_SHIFT	3

#define	DCACHE_L1_VADDR_TO_ADDR(virt_addr)				     \
		((virt_addr) & _E2K_DCACHE_L1_LINE)

#define	dcache_l1_set_set(addr, set)					     \
		(__dcache_l1_addr(					     \
			(dcache_l1_addr_val(addr) & ~_E2K_DCACHE_L1_SET) |   \
			((set) << _E2K_DCACHE_L1_SET_SHIFT) & 		     \
			_E2K_DCACHE_L1_SET))
#define	dcache_l1_get_set(addr)						     \
		(dcache_l1_addr_val(addr) & _E2K_DCACHE_L1_SET)

#define	dcache_l1_set_type(addr, type)					     \
		(__dcache_l1_addr(					     \
			(dcache_l1_addr_val(addr) & ~_E2K_DCACHE_L1_TYPE) |  \
			((type) << _E2K_DCACHE_L1_TYPE_SHIFT) & 	     \
			_E2K_DCACHE_L1_TYPE))
#define	dcache_l1_get_type(addr)					     \
		(dcache_l1_addr_val(addr) & _E2K_DCACHE_L1_TYPE)

#define	dcache_l1_set_line(addr, line)					     \
		(__dcache_l1_addr(					     \
			(dcache_l1_addr_val(addr) & ~_E2K_DCACHE_L1_LINE) |  \
			((line) << _E2K_DCACHE_L1_LINE_SHIFT) & 	     \
			_E2K_DCACHE_L1_LINE))
#define	dcache_l1_get_line(addr)					     \
		(dcache_l1_addr_val(addr) & _E2K_DCACHE_L1_LINE)

#define	dcache_l1_set_word(addr, word)					     \
		(__dcache_l1_addr(					     \
			(dcache_l1_addr_val(addr) & ~_E2K_DCACHE_L1_WORD) |  \
			((word) << _E2K_DCACHE_L1_WORD_SHIFT) & 	     \
			_E2K_DCACHE_L1_WORD))
#define	dcache_l1_get_word(addr)					     \
		(dcache_l1_addr_val(addr) & _E2K_DCACHE_L1_WORD)

#define mk_dcache_l1_addr(virt_addr, set, type, word) 			     \
({									     \
	dcache_l1_addr_t addr;						     \
	addr = __dcache_l1_addr(DCACHE_L1_VADDR_TO_ADDR(virt_addr));	     \
	addr = dcache_l1_set_set(addr, set); 				     \
	addr = dcache_l1_set_type(addr, type);				     \
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
 #define _E2K_DCACHE_L2_BIST_SIG1_REG		    0x00
 #define _E2K_DCACHE_L2_BIST_SIG2_REG		    0x01
 #define _E2K_DCACHE_L2_BISR_CTRL_REG		    0x02
 #define _E2K_DCACHE_L2_CTRL_REG		    0x03
 #define _E2K_DCACHE_L2_ECC_DBG_REG		    0x04
 #define _E2K_DCACHE_L2_ERR_REG			    0x05
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
 * Write L2 registers
 */
#define	WRITE_L2_REG(reg_val, reg_num, bank_num)			     \
		E2K_WRITE_MAS_D(mk_dcache_l2_reg_addr(reg_num, bank_num),   \
					(reg_val), MAS_DCACHE_L2_REG)
#define	WRITE_L2_CNTR(reg_val, bank_num)	\
		WRITE_L2_REG(reg_val, _E2K_DCACHE_L2_CTRL_REG, bank_num)

/*
 * Read L2 registers
 */
#define	READ_L2_REG(reg_num, bank_num)	\
		E2K_READ_MAS_D(mk_dcache_l2_reg_addr(reg_num, bank_num),     \
				MAS_DCACHE_L2_REG)
#define	READ_L2_CNTR(bank_num)	\
		READ_L2_REG(_E2K_DCACHE_L2_CTRL_REG, bank_num)
#define	READ_L2_ERR(bank_num)	\
		READ_L2_REG(_E2K_DCACHE_L2_ERR_REG, bank_num)

/*
 * Read MMU Control register
 */
#define	read_MMU_CR()		read_MMU_reg(MMU_ADDR_CR)
#define	READ_MMU_CR()	\
		READ_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR_NO))

/*
 * DTLB/ITLB registers operations
 */

/* DTLB/ITLB registers access operations address */

typedef	e2k_addr_t		tlb_addr_t;
typedef	tlb_addr_t		dtlb_addr_t;
typedef	tlb_addr_t		itlb_addr_t;

#define	tlb_addr_val(tlb_addr)		(tlb_addr)
#define	dtlb_addr_val(dtlb_addr)	tlb_addr_val(dtlb_addr)
#define	itlb_addr_val(itlb_addr)	tlb_addr_val(itlb_addr)

#define	__tlb_addr(tlb_addr_val)	(tlb_addr_val)
#define	__dtlb_addr(dtlb_addr_val)	__tlb_addr(dtlb_addr_val)
#define	__itlb_addr(itlb_addr_val)	__tlb_addr(itlb_addr_val)

/* Virtual page address translation to TLB line & set */

#define	_PG_4K_TLB_LINE_NUM_SHIFT	12		/* 4K page TLB line # */
#define	_PG_4M_TLB_LINE_NUM_SHIFT	22		/* 4MB 	  --""--      */
#define	_PG_2M_TLB_LINE_NUM_SHIFT	21		/* 2MB 	  --""--      */
#define _E3M_PG_4K_TLB_LINE_NUM	0x000000000007f000	/* 4K page TLB line # */
#define _E3M_PG_4M_TLB_LINE_NUM	0x000000001fc00000	/* 4MB 	  --""--      */
#define _E3S_PG_4K_TLB_LINE_NUM	0x00000000000ff000	/* 4K page TLB line # */
#define _E3S_PG_4M_TLB_LINE_NUM	0x000000003fc00000	/* 4MB 	  --""--      */
#define _E2S_PG_4K_TLB_LINE_NUM	0x00000000000ff000	/* 4K page TLB line # */
#define _E2S_PG_2M_TLB_LINE_NUM	0x000000001fe00000	/* 2MB 	  --""--      */
#define _E8C_PG_4K_TLB_LINE_NUM	_E2S_PG_4K_TLB_LINE_NUM	/* 4K page TLB line # */
#define _E8C_PG_2M_TLB_LINE_NUM	_E2S_PG_2M_TLB_LINE_NUM	/* 2MB	  --""--      */
#define _E1CP_PG_4K_TLB_LINE_NUM	\
				_E2S_PG_4K_TLB_LINE_NUM	/* 4K page TLB line # */
#define _E1CP_PG_2M_TLB_LINE_NUM	\
				_E2S_PG_2M_TLB_LINE_NUM	/* 2MB	  --""--      */
#define _E8C2_PG_4K_TLB_LINE_NUM	\
				_E2S_PG_4K_TLB_LINE_NUM	/* 4K page TLB line # */
#define _E8C2_PG_2M_TLB_LINE_NUM	\
				_E2S_PG_2M_TLB_LINE_NUM	/* 2MB	  --""--      */

#define	E3M_PG_4K_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & _E3M_PG_4K_TLB_LINE_NUM) >> \
					_PG_4K_TLB_LINE_NUM_SHIFT)
#define	E3S_PG_4K_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & _E3S_PG_4K_TLB_LINE_NUM) >> \
					_PG_4K_TLB_LINE_NUM_SHIFT)
#define	E2S_PG_4K_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & _E2S_PG_4K_TLB_LINE_NUM) >> \
					_PG_4K_TLB_LINE_NUM_SHIFT)
#define	E8C_PG_4K_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & _E8C_PG_4K_TLB_LINE_NUM) >> \
					_PG_4K_TLB_LINE_NUM_SHIFT)
#define	E1CP_PG_4K_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & _E1CP_PG_4K_TLB_LINE_NUM) >> \
					_PG_4K_TLB_LINE_NUM_SHIFT)
#define	E8C2_PG_4K_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & _E8C2_PG_4K_TLB_LINE_NUM) >> \
					_PG_4K_TLB_LINE_NUM_SHIFT)

#define	E3M_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & _E3M_PG_4M_TLB_LINE_NUM) >> \
					_PG_4M_TLB_LINE_NUM_SHIFT)
#define	E3S_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & _E3S_PG_4M_TLB_LINE_NUM) >> \
					_PG_4M_TLB_LINE_NUM_SHIFT)
#define	E2S_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & _E2S_PG_2M_TLB_LINE_NUM) >> \
					_PG_2M_TLB_LINE_NUM_SHIFT)
#define	E8C_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & _E8C_PG_2M_TLB_LINE_NUM) >> \
					_PG_2M_TLB_LINE_NUM_SHIFT)
#define	E1CP_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & _E1CP_PG_2M_TLB_LINE_NUM) >> \
					_PG_2M_TLB_LINE_NUM_SHIFT)
#define	E8C2_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & _E8C2_PG_2M_TLB_LINE_NUM) >> \
					_PG_2M_TLB_LINE_NUM_SHIFT)

#define E3M_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page)	\
		((large_page) ? E3M_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) : \
				E3M_PG_4K_TO_TLB_LINE_NUM(virt_addr))
#define E3S_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page)	\
		((large_page) ? E3S_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) : \
				E3S_PG_4K_TO_TLB_LINE_NUM(virt_addr))
#define E2S_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page)	\
		((large_page) ? E2S_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) : \
				E2S_PG_4K_TO_TLB_LINE_NUM(virt_addr))
#define E8C_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page)	\
		((large_page) ? E8C_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) : \
				E8C_PG_4K_TO_TLB_LINE_NUM(virt_addr))
#define E1CP_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page)	\
		((large_page) ? E1CP_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) : \
				E1CP_PG_4K_TO_TLB_LINE_NUM(virt_addr))
#define E8C2_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page)	\
		((large_page) ? E8C2_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) : \
				E8C2_PG_4K_TO_TLB_LINE_NUM(virt_addr))

#define	VADDR_TO_TLB_LINE_NUM(virt_addr, large_page)			 \
({									 \
	u32 ret;							 \
									 \
	if (IS_MACHINE_E3M)						 \
		ret = E3M_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page);	 \
	else if (IS_MACHINE_E2S)					 \
		ret = E2S_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page);	 \
	else if (IS_MACHINE_E8C)					 \
		ret = E8C_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page);	 \
	else if (IS_MACHINE_E1CP)					 \
		ret = E1CP_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page); \
	else if (IS_MACHINE_E8C2)					 \
		ret = E8C2_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page); \
	else								 \
		ret = E3S_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page);	 \
									 \
	ret;								 \
})

#define	BOOT_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page)		 \
({									 \
	u32 ret;							 \
									 \
	if (BOOT_IS_MACHINE_E3M)					 \
		ret = E3M_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page);	 \
	else if (BOOT_IS_MACHINE_E2S)					 \
		ret = E2S_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page);	 \
	else if (BOOT_IS_MACHINE_E8C)					 \
		ret = E8C_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page);	 \
	else if (BOOT_IS_MACHINE_E1CP)					 \
		ret = E1CP_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page); \
	else if (BOOT_IS_MACHINE_E8C2)					 \
		ret = E8C2_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page); \
	else								 \
		ret = E3S_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page);	 \
									 \
	ret;								 \
})

#define	_TLB_ADDR_LINE_NUM_SHIFT	12	/* [18:12] - E3M */
						/* [19:12} - E3S/E2S/E8C/ */
						/*	     E1C+/E8C2 */
#define	_TLB_ADDR_LINE_NUM_SHIFT2	22	/* [18:12] - E3M */
						/* [29:22} - E3S */
#define	_TLB_ADDR_LINE_NUM_SHIFT3	21	/* [28:21] - E2S/E8C/E1C+/ */
						/*	     E8C2 */
#define	_E3M_TLB_ADDR_SET_NUM_SHIFT	19	/* [21:19] */
#define	_E3S_TLB_ADDR_SET_NUM_SHIFT	3	/* [ 4: 3] */
#define	_E2S_TLB_ADDR_SET_NUM_SHIFT	3	/* [ 4: 3] */

#define _TLB_ADDR_TYPE		0x0000000000000007	/* type of operation */
#define _E3M_TLB_ADDR_LINE_NUM	0x000000000007f000	/* number of line */
#define _E3M_TLB_ADDR_SET_NUM	0x0000000000380000	/* number of set in */
							/* a line */
#define _E3M_TLB_ADDR_LINE_NUM2	0x000000001fc00000	/* number of line copy */
#define _E3S_TLB_ADDR_LINE_NUM	0x00000000000ff000	/* number of line */
#define _E3S_TLB_ADDR_SET_NUM	0x0000000000000018	/* number of set in */
							/* a line */
#define _E3S_TLB_ADDR_LINE_NUM2	0x000000003fc00000	/* number of line copy */
#define _E2S_TLB_ADDR_LINE_NUM	0x00000000000ff000	/* number of line */
#define _E2S_TLB_ADDR_SET_NUM	0x0000000000000018	/* number of set in */
							/* a line */
#define _E2S_TLB_ADDR_LINE_NUM2	0x000000001fe00000	/* number of line copy */

#define	_TLB_ADDR_TAG_ACCESS	0x0000000000000000	/* tag access oper. */
							/* type */
#define	_TLB_ADDR_ENTRY_ACCESS	0x0000000000000001	/* entry access oper. */
							/* type */

#define	tlb_addr_set_type(tlb_addr, type)	\
		(__tlb_addr((tlb_addr_val(tlb_addr) & ~_TLB_ADDR_TYPE) | \
		((type) & _TLB_ADDR_TYPE)))
#define	tlb_addr_set_tag_access(tlb_addr)	\
		tlb_addr_set_type(tlb_addr, _TLB_ADDR_TAG_ACCESS)
#define	tlb_addr_set_entry_access(tlb_addr)	\
		tlb_addr_set_type(tlb_addr, _TLB_ADDR_ENTRY_ACCESS)
#define	tlb_addr_tag_access	_TLB_ADDR_TAG_ACCESS
#define	tlb_addr_entry_access	_TLB_ADDR_ENTRY_ACCESS

#define	e3m_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page) \
		(__tlb_addr((tlb_addr_val(tlb_addr) & \
					~(_E3M_TLB_ADDR_LINE_NUM | \
					_E3M_TLB_ADDR_LINE_NUM2)) | \
		(E3M_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page) << \
						_TLB_ADDR_LINE_NUM_SHIFT) | \
		(E3M_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page) << \
						_TLB_ADDR_LINE_NUM_SHIFT2)))
#define	e3m_tlb_addr_set_set_num(tlb_addr, set_num)	\
		(__tlb_addr((tlb_addr_val(tlb_addr) & \
					~_E3M_TLB_ADDR_SET_NUM) | \
		(((set_num) << _E3M_TLB_ADDR_SET_NUM_SHIFT) & \
					_E3M_TLB_ADDR_SET_NUM)))

#define	e3s_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page) \
		(__tlb_addr((tlb_addr_val(tlb_addr) & \
					~(_E3S_TLB_ADDR_LINE_NUM | \
					_E3S_TLB_ADDR_LINE_NUM2)) | \
		(E3S_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page) << \
						_TLB_ADDR_LINE_NUM_SHIFT) | \
		(E3S_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page) << \
						_TLB_ADDR_LINE_NUM_SHIFT2)))
#define	e3s_tlb_addr_set_set_num(tlb_addr, set_num)	\
		(__tlb_addr((tlb_addr_val(tlb_addr) & \
					~_E3S_TLB_ADDR_SET_NUM) | \
		(((set_num) << _E3S_TLB_ADDR_SET_NUM_SHIFT) & \
					_E3S_TLB_ADDR_SET_NUM)))

#define	e2s_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page) \
		(__tlb_addr((tlb_addr_val(tlb_addr) & \
					~(_E2S_TLB_ADDR_LINE_NUM | \
					_E2S_TLB_ADDR_LINE_NUM2)) | \
		(E2S_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page) << \
						_TLB_ADDR_LINE_NUM_SHIFT) | \
		(E2S_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page) << \
						_TLB_ADDR_LINE_NUM_SHIFT3)))
#define	e2s_tlb_addr_set_set_num(tlb_addr, set_num)	\
		(__tlb_addr((tlb_addr_val(tlb_addr) & \
					~_E2S_TLB_ADDR_SET_NUM) | \
		(((set_num) << _E2S_TLB_ADDR_SET_NUM_SHIFT) & \
					_E2S_TLB_ADDR_SET_NUM)))

#define	e8c_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page) \
		e2s_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page)
#define	e8c_tlb_addr_set_set_num(tlb_addr, set_num)	\
		e2s_tlb_addr_set_set_num(tlb_addr, set_num)

#define	e1cp_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page) \
		e2s_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page)
#define	e1cp_tlb_addr_set_set_num(tlb_addr, set_num)	\
		e2s_tlb_addr_set_set_num(tlb_addr, set_num)

#define	e8c2_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page) \
		e2s_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page)
#define	e8c2_tlb_addr_set_set_num(tlb_addr, set_num)	\
		e2s_tlb_addr_set_set_num(tlb_addr, set_num)

#define	tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page)	\
({									\
	u64 ret;							\
									\
	if (IS_MACHINE_E3M)						\
		ret = e3m_tlb_addr_set_vaddr_line_num(tlb_addr,		\
					virt_addr, large_page);		\
	else if (IS_MACHINE_E2S)					\
		ret = e2s_tlb_addr_set_vaddr_line_num(tlb_addr,		\
					virt_addr, large_page);		\
	else if (IS_MACHINE_E8C)					\
		ret = e8c_tlb_addr_set_vaddr_line_num(tlb_addr,		\
					virt_addr, large_page);		\
	else if (IS_MACHINE_E1CP)					\
		ret = e1cp_tlb_addr_set_vaddr_line_num(tlb_addr,	\
					virt_addr, large_page);		\
	else if (IS_MACHINE_E8C2)					\
		ret = e8c2_tlb_addr_set_vaddr_line_num(tlb_addr,	\
					virt_addr, large_page);		\
	else								\
		ret = e3s_tlb_addr_set_vaddr_line_num(tlb_addr,		\
					virt_addr, large_page);		\
									\
	ret;								\
})

#define	boot_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page) \
({									 \
	u64 ret;							 \
									 \
	if (BOOT_IS_MACHINE_E3M)					 \
		ret = e3m_tlb_addr_set_vaddr_line_num(tlb_addr,		 \
					virt_addr, large_page);		 \
	else if (BOOT_IS_MACHINE_E2S)					 \
		ret = e2s_tlb_addr_set_vaddr_line_num(tlb_addr,		 \
					virt_addr, large_page);		 \
	else if (BOOT_IS_MACHINE_E8C)					 \
		ret = e8c_tlb_addr_set_vaddr_line_num(tlb_addr,		 \
					virt_addr, large_page);		 \
	else if (BOOT_IS_MACHINE_E1CP)					 \
		ret = e1cp_tlb_addr_set_vaddr_line_num(tlb_addr,	 \
					virt_addr, large_page);		 \
	else if (BOOT_IS_MACHINE_E8C2)					 \
		ret = e8c2_tlb_addr_set_vaddr_line_num(tlb_addr,	 \
					virt_addr, large_page);		 \
	else								 \
		ret = e3s_tlb_addr_set_vaddr_line_num(tlb_addr,		 \
					virt_addr, large_page);		 \
									 \
	ret;								 \
})

#define	tlb_addr_set_set_num(tlb_addr, set_num)				\
({									\
	u64 ret;							\
									\
	if (IS_MACHINE_E3M)						\
		ret = e3m_tlb_addr_set_set_num(tlb_addr, set_num);	\
	else if (IS_MACHINE_E2S)					\
		ret = e2s_tlb_addr_set_set_num(tlb_addr, set_num);	\
	else if (IS_MACHINE_E8C)					\
		ret = e8c_tlb_addr_set_set_num(tlb_addr, set_num);	\
	else if (IS_MACHINE_E1CP)					\
		ret = e1cp_tlb_addr_set_set_num(tlb_addr, set_num);	\
	else if (IS_MACHINE_E8C2)					\
		ret = e8c2_tlb_addr_set_set_num(tlb_addr, set_num);	\
	else								\
		ret = e3s_tlb_addr_set_set_num(tlb_addr, set_num);	\
									\
	ret;								\
})

#define	boot_tlb_addr_set_set_num(tlb_addr, set_num)			\
({									\
	u64 ret;							\
									\
	if (BOOT_IS_MACHINE_E3M)					\
		ret = e3m_tlb_addr_set_set_num(tlb_addr, set_num);	\
	else if (BOOT_IS_MACHINE_E2S)					\
		ret = e2s_tlb_addr_set_set_num(tlb_addr, set_num);	\
	else if (BOOT_IS_MACHINE_E8C)					\
		ret = e8c_tlb_addr_set_set_num(tlb_addr, set_num);	\
	else if (BOOT_IS_MACHINE_E1CP)					\
		ret = e1cp_tlb_addr_set_set_num(tlb_addr, set_num);	\
	else if (BOOT_IS_MACHINE_E8C2)					\
		ret = e8c2_tlb_addr_set_set_num(tlb_addr, set_num);	\
	else								\
		ret = e3s_tlb_addr_set_set_num(tlb_addr, set_num);	\
									\
	ret;								\
})

/* DTLB/ITLB tag structure */

typedef	e2k_addr_t		tlb_tag_t;
typedef	tlb_tag_t		dtlb_tag_t;
typedef	tlb_tag_t		itlb_tag_t;

#define	tlb_tag_val(tlb_tag)		(tlb_tag)
#define	dtlb_tag_val(dtlb_tag)		tlb_tag_val(dtlb_tag)
#define	itlb_tag_val(itlb_tag)		tlb_tag_val(itlb_tag)

#define	__tlb_tag(tlb_tag_val)		(tlb_tag_val)
#define	__dtlb_tag(dtlb_tag_val)	__tlb_tag(dtlb_tag_val)
#define	__itlb_tag(dtlb_tag_val)	__tlb_tag(itlb_tag_val)

#define	_TLB_TAG_VA_TAG_SHIFT		7	/* [35: 7] */
#define	_TLB_TAG_CONTEXT_SHIFT		36	/* [47:36] */

#define _TLB_TAG_VA_TAG		0x0000000fffffff80	/* tag of virtual */
							/* address [47:19] */
							/* [18:12] - line # */
#define _TLB_TAG_CONTEXT	0x0000fff000000000	/* context # */
#define _TLB_TAG_ROOT		0x0001000000000000	/* should be 0 */
#define _TLB_TAG_PHYS		0x0002000000000000	/* should be 0 */
#define _TLB_TAG_G		0x0004000000000000	/* global page */
#define _TLB_TAG_USED		0x0008000000000000	/* used flag */
#define _TLB_TAG_VALID		0x0010000000000000	/* valid bit */

#define	TLB_VADDR_TO_VA_TAG(virt_addr)	\
		((((virt_addr) >> PAGE_SHIFT) & _TLB_TAG_VA_TAG) << \
		_TLB_TAG_VA_TAG_SHIFT)

#define _TLB_TAG_KERNEL_IMAGE		(_TLB_TAG_VALID | _TLB_TAG_USED | \
		((long)E2K_KERNEL_CONTEXT << _TLB_TAG_CONTEXT_SHIFT))
#define	_TLB_KERNEL_SWITCHING_IMAGE	_TLB_TAG_KERNEL_IMAGE
#define	_TLB_KERNEL_US_STACK		(_TLB_TAG_VALID | _TLB_TAG_USED | \
		((long)E2K_KERNEL_CONTEXT << _TLB_TAG_CONTEXT_SHIFT))

#define	TLB_KERNEL_SWITCHING_TEXT	__tlb_tag(_TLB_KERNEL_SWITCHING_IMAGE)
#define	TLB_KERNEL_SWITCHING_DATA	__tlb_tag(_TLB_KERNEL_SWITCHING_IMAGE)
#define	TLB_KERNEL_SWITCHING_US_STACK	__tlb_tag(_TLB_KERNEL_US_STACK)

#define	tlb_tag_get_va_tag(tlb_tag)	\
		(tlb_tag_val(tlb_tag) & _TLB_TAG_VA_TAG)
#define	tlb_tag_set_va_tag(tlb_tag, va_page)	\
		(__tlb_tag((tlb_tag_val(tlb_tag) & ~_TLB_TAG_VA_TAG) | \
		((va_page) & _TLB_TAG_VA_TAG)))
#define	tlb_tag_set_vaddr_va_tag(tlb_tag, virt_addr)	\
		(__tlb_tag((tlb_tag_val(tlb_tag) & ~_TLB_TAG_VA_TAG) | \
		TLB_VADDR_TO_VA_TAG(virt_addr)))

#define	tlb_tag_get_context(tlb_tag)	\
		(tlb_tag_val(tlb_tag) & _TLB_TAG_CONTEXT)
#define	tlb_tag_set_context(tlb_tag, context)	\
		(__tlb_tag((tlb_tag_val(tlb_tag) & ~_TLB_TAG_CONTEXT) | \
		((context) << _TLB_TAG_CONTEXT_SHIFT) & _TLB_TAG_CONTEXT))

/*
 * This takes a virtual page address and protection bits to make
 * TLB tag: tlb_tag_t
 */
#define mk_tlb_tag_vaddr(virt_addr, tag_pgprot) \
	(__tlb_tag(TLB_VADDR_TO_VA_TAG(virt_addr) | tlb_tag_val(tag_pgprot)))

/* DTLB/ITLB entry structure is the same as PTE structure of page tables */

/*
 * ICACHE/DTLB/ITLB line flush operations
 */

/* ICACHE/DTLB/ITLB line flush operations address */

typedef	e2k_addr_t			flush_op_t;

#define	flush_op_val(flush_op)		(flush_op)

#define	__flush_op(flush_op_val)	(flush_op_val)

#define _FLUSH_OP_TYPE			0x0000000000000007	/* type of */
								/* operation */
#define	_FLUSH_ICACHE_LINE_USER_OP	0x0000000000000000
#define	_FLUSH_TLB_PAGE_SYS_OP		0x0000000000000001
#define	_FLUSH_ICACHE_LINE_SYS_OP	0x0000000000000002

#define	flush_op_get_type(flush_op)	\
		(flush_op_val(flush_op) & _FLUSH_OP_TYPE)
#define	flush_op_set_type(flush_op, type)	\
		(__flush_op((flush_op_val(flush_op) & ~_FLUSH_OP_TYPE) | \
		((type) & _FLUSH_OP_TYPE)))
#define	flush_op_set_icache_line_user(flush_op)	\
		flush_op_set_type(flush_op, _FLUSH_ICACHE_LINE_USER_OP)
#define	flush_op_set_icache_line_sys(flush_op)	\
		flush_op_set_type(flush_op, _FLUSH_ICACHE_LINE_SYS_OP)
#define	flush_op_set_tlb_page_sys(flush_op)	\
		flush_op_set_type(flush_op, _FLUSH_TLB_PAGE_SYS_OP)
#define	_flush_op_icache_line_user	(long)_FLUSH_ICACHE_LINE_USER_OP
#define	_flush_op_icache_line_sys	(long)_FLUSH_ICACHE_LINE_SYS_OP
#define	_flush_op_tlb_page_sys		(long)_FLUSH_TLB_PAGE_SYS_OP
#define	flush_op_icache_line_user	__flush_op(_flush_op_icache_line_user)
#define	flush_op_icache_line_sys	__flush_op(_flush_op_icache_line_sys)
#define	flush_op_tlb_page_sys		__flush_op(_flush_op_tlb_page_sys)

/* ICACHE/DTLB/ITLB line flush extended virtual address structure */

typedef	e2k_addr_t			flush_addr_t;

#define	flush_addr_val(flush_addr)	(flush_addr)

#define	__flush_addr(flush_addr_val)	(flush_addr_val)

#define	_FLUSH_ADDR_CONTEXT_SHIFT	50	/* [61:50] */

#define _FLUSH_ADDR_VA		0x0000ffffffffffff	/* virtual address */
							/* [47: 0] */
#define _FLUSH_ADDR_CONTEXT	0x3ffc000000000000	/* context # */
#define _FLUSH_ADDR_ROOT	0x4000000000000000	/* should be 0 */
#define _FLUSH_ADDR_PHYS	0x8000000000000000	/* should be 0 */

#define	FLUSH_VADDR_TO_VA(virt_addr)	((virt_addr) & _FLUSH_ADDR_VA)

#define _FLUSH_ADDR_KERNEL(virt_addr)	(FLUSH_VADDR_TO_VA(virt_addr) | \
		((long)E2K_KERNEL_CONTEXT << _FLUSH_ADDR_CONTEXT_SHIFT))

#define	FLUSH_ADDR_KERNEL(virt_addr) \
		__flush_addr(_FLUSH_ADDR_KERNEL(virt_addr))

#define	flush_addr_get_va(flush_addr)	\
		(flush_addr_val(flush_addr) & _FLUSH_ADDR_VA)
#define	flush_addr_set_va(flush_addr, virt_addr)	\
		(__flush_addr((flush_addr_val(flush_addr) & ~_FLUSH_ADDR_VA) | \
		((va_page) & _FLUSH_ADDR_VA)))

#define	flush_addr_get_context(flush_addr)	\
		(flush_addr_val(flush_addr) & _FLUSH_ADDR_CONTEXT)
#define	flush_addr_set_context(flush_addr, context)	\
		(__flush_addr((flush_addr_val(flush_addr) & \
		~_FLUSH_ADDR_CONTEXT) | \
		((long)(context) << _FLUSH_ADDR_CONTEXT_SHIFT) & \
		_FLUSH_ADDR_CONTEXT))
#define	_flush_addr_make_sys(virt_addr, context, root)			\
({									\
	e2k_addr_t __addr_val = FLUSH_VADDR_TO_VA(virt_addr);		\
	__addr_val |= (((long)(context) <<				\
			_FLUSH_ADDR_CONTEXT_SHIFT) &			\
				_FLUSH_ADDR_CONTEXT);			\
	if (root)							\
		__addr_val |= _FLUSH_ADDR_ROOT;				\
	__addr_val;							\
})
#define	_flush_addr_make_user(virt_addr) \
		FLUSH_VADDR_TO_VA(virt_addr)
#define	flush_addr_make_sys(virt_addr, context) \
		__flush_addr(_flush_addr_make_sys(virt_addr, context, 0))
#define	flush_addr_make_user(virt_addr) \
		__flush_addr(_flush_addr_make_user(virt_addr))
#define	flush_addr_make_ss(virt_addr, context) \
		__flush_addr(_flush_addr_make_sys(virt_addr, context, 1))

/*
 * CACHE(s) flush operations
 */

/* CACHE(s) flush operations address */

#define	_FLUSH_INVALIDATE_CACHE_ALL_OP	0x0000000000000000
#define	_FLUSH_WRITE_BACK_CACHE_ALL_OP	0x0000000000000001

#define	flush_op_set_invalidate_cache_all(flush_op)	\
		flush_op_set_type(flush_op, _FLUSH_INVALIDATE_CACHE_ALL_OP)
#define	flush_op_set_write_back_cache_all(flush_op)	\
		flush_op_set_type(flush_op, _FLUSH_WRITE_BACK_CACHE_ALL_OP)
#define	_flush_op_invalidate_cache_all	(long)_FLUSH_INVALIDATE_CACHE_ALL_OP
#define	_flush_op_write_back_cache_all	(long)_FLUSH_WRITE_BACK_CACHE_ALL_OP
#define	flush_op_invalidate_cache_all \
		__flush_op(_flush_op_invalidate_cache_all)
#define	flush_op_write_back_cache_all \
		__flush_op(_flush_op_write_back_cache_all)

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
#define	_flush_op_icache_all		(long)_FLUSH_ICACHE_ALL_OP
#define	_flush_op_tlb_all		(long)_FLUSH_TLB_ALL_OP
#define	flush_op_icache_all		__flush_op(_flush_op_icache_all)
#define	flush_op_tlb_all		__flush_op(_flush_op_tlb_all)

#endif /* __ASSEMBLY__ */

/*
 * TLB address probe operations , TLB Entry_probe operations
 */

/* Virtual address for TLB address probe & Entry probe operations */
#ifndef __ASSEMBLY__
typedef	e2k_addr_t			probe_addr_t;

#define	probe_addr_val(probe_addr)	(probe_addr)

#define	__probe_addr(probe_addr_val)	(probe_addr_val)
#endif /* __ASSEMBLY__ */

#define _PROBE_ADDR_VA		0x0000ffffffffffff	/* virtual address */
							/* [47: 0] */

/* Result of TLB Entry probe operation */
#ifndef __ASSEMBLY__
typedef	unsigned long			probe_entry_t;

#define	probe_entry_val(probe_entry)	(probe_entry)

#define	__probe_entry(probe_entry_val)	(probe_entry_val)
#endif /* __ASSEMBLY__ */

#define DTLB_ENTRY_VVA		0x10000000000		/* DTLB entry VVA bit */
							/* [40] */
#define DTLB_ENTRY_PHA		0xfffffff000		/* DTLB entry phys */
							/* address [39:12] */

#define	DTLB_EP_RES		0x0001ffffffffffffUL	/* EP normal result */
							/* [48: 0] */

#ifndef __ASSEMBLY__
/*
 * Get Entry probe for virtual address
 */
#define	ENTRY_PROBE_MMU_OP(addr_val)	\
		E2K_READ_MAS_D((addr_val), MAS_ENTRY_PROBE)

#define	GET_MMU_DTLB_ENTRY(virt_addr)	\
		(unsigned long)ENTRY_PROBE_MMU_OP(probe_addr_val(virt_addr))
#endif /* __ASSEMBLY__ */

/*
 * MU address to access to CLW internal registers
 */

#ifndef __ASSEMBLY__
typedef	e2k_addr_t			clw_addr_t;
#define	clw_addr_val(clw_addr)		(clw_addr)
#define	__clw_addr(clw_addr_val)	(clw_addr_val)
#endif /* __ASSEMBLY__ */

#define CLW_ADDR_REG_NO	0x0000000000000fff	/* # of register */

#define US_CL_B_NO		0x024	/* User stack bottom to clean */
#define US_CL_UP_NO		0x124	/* User stack up to clean */
#define US_CL_M0_NO		0x004	/* User stack bit-mask [0:63] */
#define US_CL_M1_NO		0x084	/* User stack bit-mask [64:127] */
#define US_CL_M2_NO		0x104	/* User stack bit-mask [128:195] */
#define US_CL_M3_NO		0x184	/* User stack bit-mask [196:255] */

#define	_CLW_REG_NO_TO_MU_ADDR_VAL(reg_no)	\
		((reg_no) & CLW_ADDR_REG_NO)
#define	CLW_REG_NO_TO_MU_ADDR(reg_no)	\
		__clw_addr(_CLW_REG_NO_TO_MU_ADDR_VAL(reg_no))
#define	CLW_REG_NO_FROM_MU_ADDR(clw_addr) \
		(clw_addr_val(clw_addr) & CLW_ADDR_REG_NO)

#define	MU_ADDR_US_CL_B		CLW_REG_NO_TO_MU_ADDR(US_CL_B_NO)
#define	MU_ADDR_US_CL_UP	CLW_REG_NO_TO_MU_ADDR(US_CL_UP_NO)
#define	MU_ADDR_US_CL_M0	CLW_REG_NO_TO_MU_ADDR(US_CL_M0_NO)
#define	MU_ADDR_US_CL_M1	CLW_REG_NO_TO_MU_ADDR(US_CL_M1_NO)
#define	MU_ADDR_US_CL_M2	CLW_REG_NO_TO_MU_ADDR(US_CL_M2_NO)
#define	MU_ADDR_US_CL_M3	CLW_REG_NO_TO_MU_ADDR(US_CL_M3_NO)

/* CLW internel register contents */

#ifndef __ASSEMBLY__
typedef	unsigned long			clw_reg_t;
#define	clw_reg_val(clw_reg)		(clw_reg)
#define	__clw_reg(clw_reg_val)		(clw_reg_val)
#endif /* __ASSEMBLY__ */

#ifndef __ASSEMBLY__

/*
 * User Stack Window clean bit-mask structure
 */

#define	CLW_MASK_WORD_NUM	 4	/* number of words in bit-mask */
#define	CLW_BITS_PER_MASK_WORD	64	/* number of bits in one bit-mask word */
#define	CLW_BYTES_PER_BIT	32	/* one bit describes 32 bytes of stack */
					/* area */
#define	CLW_BYTES_PER_MASK		/* number of bytes in full bit-mask */ \
		CLW_BYTES_PER_BIT * CLW_MASK_WORD_NUM * CLW_BITS_PER_MASK_WORD
/*
 * Read CLW register
 */
#define	READ_CLW_REG(clw_addr)	\
		E2K_READ_MAS_D_5(clw_addr_val(clw_addr), MAS_CLW_REG)

/*
 * Read CLW bottom register
 */
#define	read_US_CL_B()	read_CLW_reg(MU_ADDR_US_CL_B)
#define	READ_US_CL_B()	READ_CLW_REG(MU_ADDR_US_CL_B)

/*
 * Read CLW up register
 */
#define	read_US_CL_UP()	read_CLW_reg(MU_ADDR_US_CL_UP)
#define	READ_US_CL_UP()	READ_CLW_REG(MU_ADDR_US_CL_UP)

/*
 * Read CLW bit-mask registers
 */
#define	read_US_CL_M0() read_CLW_reg(MU_ADDR_US_CL_M0)
#define	READ_US_CL_M0()	READ_CLW_REG(MU_ADDR_US_CL_M0)
#define	read_US_CL_M1() read_CLW_reg(MU_ADDR_US_CL_M1)
#define	READ_US_CL_M1()	READ_CLW_REG(MU_ADDR_US_CL_M1)
#define	read_US_CL_M2() read_CLW_reg(MU_ADDR_US_CL_M2)
#define	READ_US_CL_M2()	READ_CLW_REG(MU_ADDR_US_CL_M2)
#define	read_US_CL_M3() read_CLW_reg(MU_ADDR_US_CL_M3)
#define	READ_US_CL_M3()	READ_CLW_REG(MU_ADDR_US_CL_M3)

#endif /* __ASSEMBLY__ */

#endif  /* _E2K_MMU_REGS_H_ */
