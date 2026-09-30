/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * native E2K MMU structures & registers.
 */

#ifndef	_E2K_NATIVE_MMU_REGS_ACCESS_H_
#define	_E2K_NATIVE_MMU_REGS_ACCESS_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/irqflags.h>
#include <asm/e2k_api.h>
#include <asm/e2k.h>
#include <asm/debug_print.h>
#endif /* __ASSEMBLY__ */

#include <asm/mmu_regs_types.h>
#include <asm/mas.h>
#include <asm/native_dcache_regs_access.h>


#undef	DEBUG_MR_MODE
#undef	DebugMR
#define	DEBUG_MR_MODE		0	/* MMU registers access */
#define DebugMR(...)		DebugPrint(DEBUG_MR_MODE, ##__VA_ARGS__)


#ifndef __ASSEMBLY__

/*
 * Write/read MMU register
 */
#define	NATIVE_WRITE_MMU_REG(addr_val, reg_val) \
do { \
	asm volatile (MMURW_WAIT_ASYNC_TLB ::: "memory"); \
	NATIVE_WRITE_MAS_D((addr_val), (reg_val), MAS_MMU_REG); \
} while (0)

#define	NATIVE_READ_MMU_REG(addr_val)					\
		NATIVE_READ_MAS_D((addr_val), MAS_MMU_REG)
#define	NATIVE_WRITE_MMU_CR(x)		NATIVE_SET_MMUREG(mmu_cr, AW(x))
#define	NATIVE_WRITE_MMU_TRAP_POINT(x)	NATIVE_SET_MMUREG(trap_point, (x))
#define	NATIVE_READ_MMU_TRAP_POINT()	NATIVE_GET_MMUREG(trap_point)
#define	NATIVE_WRITE_MMU_US_CL_D(x)	NATIVE_SET_MMUREG(us_cl_d, (x))
#define	NATIVE_READ_MMU_US_CL_D()	NATIVE_GET_MMUREG(us_cl_d)
#define	NATIVE_WRITE_MMU_OS_PPTB_REG_VALUE(mmu_phys_ptb)	\
		NATIVE_SET_MMUREG_ISET(6, os_pptb, (mmu_phys_ptb))
#define	NATIVE_READ_MMU_OS_PPTB_REG_VALUE()	\
		NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_PPTB_NO))
#define	NATIVE_WRITE_MMU_OS_VPTB_REG_VALUE(mmu_virt_ptb)	\
		NATIVE_SET_MMUREG_ISET(6, os_vptb, (mmu_virt_ptb))
#define	NATIVE_READ_MMU_OS_VPTB_REG_VALUE()	\
		NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_VPTB_NO))
#define	NATIVE_WRITE_MMU_OS_VAB_REG_VALUE(kernel_offset)	\
		NATIVE_SET_MMUREG_ISET(6, os_vab, (kernel_offset))
#define	NATIVE_READ_MMU_OS_VAB_REG_VALUE()	\
		NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_VAB_NO))

#define	BOOT_NATIVE_WRITE_MMU_REG(addr_val, reg_val)			\
		NATIVE_WRITE_MMU_REG(addr_val, reg_val)
#define	BOOT_NATIVE_READ_MMU_REG(addr_val)				\
		NATIVE_READ_MMU_REG(addr_val)

#define	BOOT_NATIVE_WRITE_MMU_CR(x)		NATIVE_SET_MMUREG(mmu_cr, (x))
#define	BOOT_NATIVE_WRITE_MMU_TRAP_POINT(x)	NATIVE_SET_MMUREG(trap_point, (x))
#define	BOOT_NATIVE_READ_MMU_TRAP_POINT()	NATIVE_GET_MMUREG(trap_point)
#define	BOOT_NATIVE_WRITE_MMU_OS_PPTB_REG_VALUE(mmu_phys_ptb)	\
		BOOT_NATIVE_WRITE_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_PPTB_NO), \
			mmu_reg_val(mmu_phys_ptb))
#define	BOOT_NATIVE_READ_MMU_OS_PPTB_REG_VALUE()	\
		BOOT_NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_PPTB_NO))
#define	BOOT_NATIVE_WRITE_MMU_OS_VPTB_REG_VALUE(mmu_virt_ptb)	\
		BOOT_NATIVE_WRITE_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_VPTB_NO), \
			mmu_reg_val(mmu_virt_ptb))
#define	BOOT_NATIVE_READ_MMU_OS_VPTB_REG_VALUE()	\
		BOOT_NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_VPTB_NO))
#define	BOOT_NATIVE_WRITE_MMU_OS_VAB_REG_VALUE(kernel_offset)	\
		BOOT_NATIVE_WRITE_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_VAB_NO), \
			mmu_reg_val(kernel_offset))
#define	BOOT_NATIVE_READ_MMU_OS_VAB_REG_VALUE()	\
		BOOT_NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_VAB_NO))

#define	NATIVE_WRITE_MMU_MTRR_DEFTYPE_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr32, (reg_val))
#define	NATIVE_READ_MMU_MTRR_DEFTYPE_REG()	\
			NATIVE_GET_MMUREG(mtrr32)
#define	NATIVE_WRITE_MMU_MTRR_FIX_64K_00000_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr16, (reg_val))
#define	NATIVE_READ_MMU_MTRR_FIX_64K_00000_REG()	\
			NATIVE_GET_MMUREG(mtrr16)
#define	NATIVE_WRITE_MMU_MTRR_FIX_16K_80000_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr17, (reg_val))
#define	NATIVE_READ_MMU_MTRR_FIX_16K_80000_REG()	\
			NATIVE_GET_MMUREG(mtrr17)
#define	NATIVE_WRITE_MMU_MTRR_FIX_16K_A0000_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr18, (reg_val))
#define	NATIVE_READ_MMU_MTRR_FIX_16K_A0000_REG()	\
			NATIVE_GET_MMUREG(mtrr18)
#define	NATIVE_WRITE_MMU_MTRR_FIX_4K_C0000_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr19, (reg_val))
#define	NATIVE_READ_MMU_MTRR_FIX_4K_C0000_REG()	\
			NATIVE_GET_MMUREG(mtrr19)
#define	NATIVE_WRITE_MMU_MTRR_FIX_4K_C8000_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr20, (reg_val))
#define	NATIVE_READ_MMU_MTRR_FIX_4K_C8000_REG()	\
			NATIVE_GET_MMUREG(mtrr20)
#define	NATIVE_WRITE_MMU_MTRR_FIX_4K_D0000_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr21, (reg_val))
#define	NATIVE_READ_MMU_MTRR_FIX_4K_D0000_REG()	\
			NATIVE_GET_MMUREG(mtrr21)
#define	NATIVE_WRITE_MMU_MTRR_FIX_4K_D8000_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr22, (reg_val))
#define	NATIVE_READ_MMU_MTRR_FIX_4K_D8000_REG()	\
			NATIVE_GET_MMUREG(mtrr22)
#define	NATIVE_WRITE_MMU_MTRR_FIX_4K_E0000_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr23, (reg_val))
#define	NATIVE_READ_MMU_MTRR_FIX_4K_E0000_REG()	\
			NATIVE_GET_MMUREG(mtrr23)
#define	NATIVE_WRITE_MMU_MTRR_FIX_4K_E8000_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr24, (reg_val))
#define	NATIVE_READ_MMU_MTRR_FIX_4K_E8000_REG()	\
			NATIVE_GET_MMUREG(mtrr24)
#define	NATIVE_WRITE_MMU_MTRR_FIX_4K_F0000_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr25, (reg_val))
#define	NATIVE_READ_MMU_MTRR_FIX_4K_F0000_REG()	\
			NATIVE_GET_MMUREG(mtrr25)
#define	NATIVE_WRITE_MMU_MTRR_FIX_4K_F8000_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr26, (reg_val))
#define	NATIVE_READ_MMU_MTRR_FIX_4K_F8000_REG()	\
			NATIVE_GET_MMUREG(mtrr26)
#define	NATIVE_WRITE_MMU_MTRR_PHYSBASE0_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr0, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSBASE0_REG()	\
			NATIVE_GET_MMUREG(mtrr0)
#define	NATIVE_WRITE_MMU_MTRR_PHYSBASE1_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr1, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSBASE1_REG()	\
			NATIVE_GET_MMUREG(mtrr1)
#define	NATIVE_WRITE_MMU_MTRR_PHYSBASE2_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr2, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSBASE2_REG()	\
			NATIVE_GET_MMUREG(mtrr2)
#define	NATIVE_WRITE_MMU_MTRR_PHYSBASE3_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr3, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSBASE3_REG()	\
			NATIVE_GET_MMUREG(mtrr3)
#define	NATIVE_WRITE_MMU_MTRR_PHYSBASE4_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr4, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSBASE4_REG()	\
			NATIVE_GET_MMUREG(mtrr4)
#define	NATIVE_WRITE_MMU_MTRR_PHYSBASE5_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr5, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSBASE5_REG()	\
			NATIVE_GET_MMUREG(mtrr5)
#define	NATIVE_WRITE_MMU_MTRR_PHYSBASE6_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr6, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSBASE6_REG()	\
			NATIVE_GET_MMUREG(mtrr6)
#define	NATIVE_WRITE_MMU_MTRR_PHYSBASE7_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr7, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSBASE7_REG()	\
			NATIVE_GET_MMUREG(mtrr7)
#define	NATIVE_WRITE_MMU_MTRR_PHYSMASK0_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr8, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSMASK0_REG()	\
			NATIVE_GET_MMUREG(mtrr8)
#define	NATIVE_WRITE_MMU_MTRR_PHYSMASK1_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr9, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSMASK1_REG()	\
			NATIVE_GET_MMUREG(mtrr9)
#define	NATIVE_WRITE_MMU_MTRR_PHYSMASK2_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr10, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSMASK2_REG()	\
			NATIVE_GET_MMUREG(mtrr10)
#define	NATIVE_WRITE_MMU_MTRR_PHYSMASK3_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr11, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSMASK3_REG()	\
			NATIVE_GET_MMUREG(mtrr11)
#define	NATIVE_WRITE_MMU_MTRR_PHYSMASK4_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr12, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSMASK4_REG()	\
			NATIVE_GET_MMUREG(mtrr12)
#define	NATIVE_WRITE_MMU_MTRR_PHYSMASK5_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr13, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSMASK5_REG()	\
			NATIVE_GET_MMUREG(mtrr13)
#define	NATIVE_WRITE_MMU_MTRR_PHYSMASK6_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr14, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSMASK6_REG()	\
			NATIVE_GET_MMUREG(mtrr14)
#define	NATIVE_WRITE_MMU_MTRR_PHYSMASK7_REG(reg_val)	\
			NATIVE_SET_MMUREG_ISET(6, mtrr15, (reg_val))
#define	NATIVE_READ_MMU_MTRR_PHYSMASK7_REG()	\
			NATIVE_GET_MMUREG(mtrr15)

/*
 * Write/read Data TLB register
 */
#define	NATIVE_WRITE_DTLB_REG(tlb_addr, tlb_value)			\
		NATIVE_WRITE_MAS_D((tlb_addr), (tlb_value), MAS_DTLB_REG)

#define	NATIVE_READ_DTLB_REG(tlb_addr)					\
		NATIVE_READ_MAS_D((tlb_addr), MAS_DTLB_REG)

/*
 * Flush TLB page/entry
 */
#define	NATIVE_FLUSH_TLB_ENTRY(flush_op, addr)				\
		NATIVE_WRITE_MAS_D((flush_op), (addr), MAS_TLB_PAGE_FLUSH)

/*
 * Flush ICACHE line
 */
#define	NATIVE_FLUSH_ICACHE_LINE(flush_op, addr)			\
		NATIVE_WRITE_MAS_D((flush_op), (addr), MAS_ICACHE_LINE_FLUSH)

/*
 * Flush and invalidate or write back CACHE(s) (invalidate all caches
 * of the processor)
 */

#define	NATIVE_FLUSH_CACHE_L12(flush_op)				\
		NATIVE_WRITE_MAS_D((flush_op), (0), MAS_CACHE_FLUSH)

static inline void
native_write_back_CACHE_L12(void)
{
	unsigned long flags;

	DebugMR("Flush : Write back all CACHEs (op 0x%lx)\n",
		flush_op_write_back_cache_L12);
	raw_all_irq_save(flags);
	E2K_WAIT_MA;
	NATIVE_FLUSH_CACHE_L12(flush_op_write_back_cache_L12);
	E2K_WAIT_FLUSH;
	raw_all_irq_restore(flags);
}

/*
 * Flush TLB (invalidate all TLBs of the processor)
 */

#define	NATIVE_FLUSH_TLB_ALL(flush_op)					\
		NATIVE_WRITE_MAS_D((flush_op), (0), MAS_TLB_FLUSH)

static inline void
native_flush_TLB_all(void)
{
	unsigned long flags;

	DebugMR("Flush all TLBs (op 0x%lx)\n", flush_op_tlb_all);
	raw_all_irq_save(flags);
#ifdef CONFIG_AAU_IN_KERNEL
	NATIVE_CLEAR_APB();
	E2K_NOP(1);
	__E2K_WAIT(_st_c|_all_e);
#else
	__E2K_WAIT(_st_c);
#endif
	NATIVE_FLUSH_TLB_ALL(flush_op_tlb_all);
	__E2K_WAIT(_fl_c | _ma_c);
	raw_all_irq_restore(flags);
}

/*
 * Flush ICACHE (invalidate instruction caches of the processor)
 */

#define	NATIVE_FLUSH_ICACHE_ALL(flush_op)				\
		NATIVE_WRITE_MAS_D((flush_op), (0), MAS_ICACHE_FLUSH)

static inline void
native_flush_ICACHE_all(void)
{
	DebugMR("Flush all ICACHE op 0x%lx\n", flush_op_icache_all);
	E2K_WAIT_ST;
	NATIVE_FLUSH_ICACHE_ALL(flush_op_icache_all);
	E2K_WAIT_FLUSH;
	E2K_FLUSH_PIPELINE();
}

/*
 * Get Entry probe for virtual address
 */
#define	NATIVE_ENTRY_PROBE_MMU_OP(addr_val)	\
		NATIVE_READ_MAS_D((addr_val), MAS_ENTRY_PROBE)

/*
 * Get physical address for virtual address
 */
#define	NATIVE_ADDRESS_PROBE_MMU_OP(addr_val)	\
		NATIVE_READ_MAS_D((addr_val), MAS_VA_PROBE)

/*
 * Read CLW register
 */
#define	NATIVE_READ_CLW_REG(clw_addr)	\
		NATIVE_READ_MAS_D_5((clw_addr), MAS_CLW_REG)

/*
 * Write CLW register
 */
#define	NATIVE_WRITE_CLW_REG(clw_addr, val)	\
		NATIVE_WRITE_MAS_D((clw_addr), (val), MAS_CLW_REG)

/*
 * native MMU DEBUG registers access
 */
#define	NATIVE_READ_DDBAR0_REG_VALUE()	\
		NATIVE_GET_MMUREG(ddbar0)
#define	NATIVE_READ_DDBAR1_REG_VALUE()	\
		NATIVE_GET_MMUREG(ddbar1)
#define	NATIVE_READ_DDBAR2_REG_VALUE()	\
		NATIVE_GET_MMUREG(ddbar2)
#define	NATIVE_READ_DDBAR3_REG_VALUE()	\
		NATIVE_GET_MMUREG(ddbar3)
#define	NATIVE_READ_DDBCR_REG_VALUE()	\
		NATIVE_GET_MMUREG(ddbcr)
#define	NATIVE_READ_DDBSR_REG_VALUE()	\
		NATIVE_GET_MMUREG(ddbsr)
#define	NATIVE_READ_DDMAR0_REG_VALUE()	\
		NATIVE_GET_MMUREG(ddmar0)
#define	NATIVE_READ_DDMAR1_REG_VALUE()	\
		NATIVE_GET_MMUREG(ddmar1)
#define	NATIVE_READ_DDMCR_REG_VALUE()	\
		NATIVE_GET_MMUREG(ddmcr)
#define	NATIVE_WRITE_DDBAR0_REG_VALUE(value)	\
		NATIVE_SET_MMUREG(ddbar0, value)
#define	NATIVE_WRITE_DDBAR1_REG_VALUE(value)	\
		NATIVE_SET_MMUREG(ddbar1, value)
#define	NATIVE_WRITE_DDBAR2_REG_VALUE(value)	\
		NATIVE_SET_MMUREG(ddbar2, value)
#define	NATIVE_WRITE_DDBAR3_REG_VALUE(value)	\
		NATIVE_SET_MMUREG(ddbar3, value)
#define	NATIVE_WRITE_DDBCR_REG_VALUE(value)	\
		NATIVE_SET_MMUREG(ddbcr, value)
#define	NATIVE_WRITE_DDBSR_REG_VALUE(value)	\
		NATIVE_SET_MMUREG(ddbsr, value)
#define	NATIVE_WRITE_DDMAR0_REG_VALUE(value)	\
		NATIVE_SET_MMUREG(ddmar0, value)
#define	NATIVE_WRITE_DDMAR1_REG_VALUE(value)	\
		NATIVE_SET_MMUREG(ddmar1, value)
/* 4/6 cycles delay guarantess that all counting
 * is stopped and %ddbsr is updated accordingly. */
#define	NATIVE_WRITE_DDMCR_REG_VALUE(value)	\
		NATIVE_SET_MMUREG_ISET_V5_V6(7, ddmcr, value, 3, 4)

#define	NATIVE_READ_DDBAR0_REG()	\
		NATIVE_READ_DDBAR0_REG_VALUE()
#define	NATIVE_READ_DDBAR1_REG()	\
		NATIVE_READ_DDBAR1_REG_VALUE()
#define	NATIVE_READ_DDBAR2_REG()	\
		NATIVE_READ_DDBAR2_REG_VALUE()
#define	NATIVE_READ_DDBAR3_REG()	\
		NATIVE_READ_DDBAR3_REG_VALUE()
#define	NATIVE_READ_DDBCR_REG()	\
({ \
	e2k_ddbcr_t ddbcr; \
 \
	ddbcr.DDBCR_reg = NATIVE_READ_DDBCR_REG_VALUE(); \
	ddbcr; \
})
#define	NATIVE_READ_DDBSR_REG()	\
({ \
	e2k_ddbsr_t ddbsr; \
 \
	ddbsr.DDBSR_reg = NATIVE_READ_DDBSR_REG_VALUE(); \
	ddbsr; \
})
#define	NATIVE_READ_DDMAR0_REG()	\
		NATIVE_READ_DDMAR0_REG_VALUE()
#define	NATIVE_READ_DDMAR1_REG()	\
		NATIVE_READ_DDMAR1_REG_VALUE()
#define	NATIVE_READ_DDMCR_REG()	\
({ \
	e2k_ddmcr_t ddmcr; \
 \
	ddmcr.DDMCR_reg = NATIVE_READ_DDMCR_REG_VALUE(); \
	ddmcr; \
})
#define	NATIVE_WRITE_DDBAR0_REG(value)	\
		NATIVE_WRITE_DDBAR0_REG_VALUE(value)
#define	NATIVE_WRITE_DDBAR1_REG(value)	\
		NATIVE_WRITE_DDBAR1_REG_VALUE(value)
#define	NATIVE_WRITE_DDBAR2_REG(value)	\
		NATIVE_WRITE_DDBAR2_REG_VALUE(value)
#define	NATIVE_WRITE_DDBAR3_REG(value)	\
		NATIVE_WRITE_DDBAR3_REG_VALUE(value)
#define	NATIVE_WRITE_DDBCR_REG(value)	\
		NATIVE_WRITE_DDBCR_REG_VALUE(value.DDBCR_reg)
#define	NATIVE_WRITE_DDBSR_REG(value)	\
		NATIVE_WRITE_DDBSR_REG_VALUE(value.DDBSR_reg)
#define	NATIVE_WRITE_DDMAR0_REG(value)	\
		NATIVE_WRITE_DDMAR0_REG_VALUE(value)
#define	NATIVE_WRITE_DDMAR1_REG(value)	\
		NATIVE_WRITE_DDMAR1_REG_VALUE(value)
#define	NATIVE_WRITE_DDMCR_REG(value)	\
		NATIVE_WRITE_DDMCR_REG_VALUE(value.DDMCR_reg)

#endif /* ! __ASSEMBLY__ */

#endif  /* _E2K_NATIVE_MMU_REGS_ACCESS_H_ */
