/*
 * native E2K MMU structures & registers.
 *
 * Copyright 2014 Salavat S. Guiliazov (atic@mcst.ru)
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
#define	NATIVE_WRITE_MMU_REG(addr_val, reg_val)				\
		NATIVE_WRITE_MAS_D((addr_val), (reg_val), MAS_MMU_REG)

#define	NATIVE_READ_MMU_REG(addr_val)					\
		NATIVE_READ_MAS_D((addr_val), MAS_MMU_REG)
#define	NATIVE_WRITE_MMU_CR(mmu_cr)					\
		NATIVE_WRITE_MMU_REG(					\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR_NO),	\
			mmu_reg_val(mmu_cr))
#define	NATIVE_WRITE_MMU_TRAP_POINT(mmu_tc)				\
		NATIVE_WRITE_MMU_REG(					\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_TRAP_POINT_NO), \
			mmu_reg_val(mmu_tc))
#define	NATIVE_READ_MMU_TRAP_POINT()	\
		NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_TRAP_POINT_NO))
#define	NATIVE_WRITE_MMU_OS_PPTB_REG_VALUE(mmu_phys_ptb)	\
		NATIVE_WRITE_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_PPTB_NO), \
			mmu_reg_val(mmu_phys_ptb))
#define	NATIVE_READ_MMU_OS_PPTB_REG_VALUE()	\
		NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_PPTB_NO))
#define	NATIVE_WRITE_MMU_OS_VPTB_REG_VALUE(mmu_virt_ptb)	\
		NATIVE_WRITE_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_VPTB_NO), \
			mmu_reg_val(mmu_virt_ptb))
#define	NATIVE_READ_MMU_OS_VPTB_REG_VALUE()	\
		NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_VPTB_NO))
#define	NATIVE_WRITE_MMU_OS_VAB_REG_VALUE(kernel_offset)	\
		NATIVE_WRITE_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_VAB_NO), \
			mmu_reg_val(kernel_offset))
#define	NATIVE_READ_MMU_OS_VAB_REG_VALUE()	\
		NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_OS_VAB_NO))

#define	BOOT_NATIVE_WRITE_MMU_REG(addr_val, reg_val)			\
		NATIVE_WRITE_MMU_REG(addr_val, reg_val)
#define	BOOT_NATIVE_READ_MMU_REG(addr_val)				\
		NATIVE_READ_MMU_REG(addr_val)

#define	BOOT_NATIVE_WRITE_MMU_CR(mmu_cr)				\
		BOOT_NATIVE_WRITE_MMU_REG(				\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR_NO),	\
			mmu_reg_val(mmu_cr))
#define	BOOT_NATIVE_WRITE_MMU_TRAP_POINT(mmu_tc)			\
		BOOT_NATIVE_WRITE_MMU_REG(				\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_TRAP_POINT_NO), \
			mmu_reg_val(mmu_tc))
#define	BOOT_NATIVE_READ_MMU_TRAP_POINT()	\
		BOOT_NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_TRAP_POINT_NO))
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
native_invalidate_CACHE_L12(void)
{
	int invalidate_supported;
	unsigned long flags;

	DebugMR("Flush : Invalidate all CACHEs (op 0x%lx)\n",
		_flush_op_invalidate_cache_L12);

	/* Invalidate operation was removed in E2S */
	invalidate_supported = NATIVE_IS_MACHINE_ES2;

	raw_all_irq_save(flags);
	E2K_WAIT_MA;
	if (invalidate_supported)
		NATIVE_FLUSH_CACHE_L12(_flush_op_invalidate_cache_L12);
	else
		NATIVE_FLUSH_CACHE_L12(_flush_op_write_back_cache_L12);
	E2K_WAIT_FLUSH;
	raw_all_irq_restore(flags);
}

static inline void
native_write_back_CACHE_L12(void)
{
	unsigned long flags;

	DebugMR("Flush : Write back all CACHEs (op 0x%lx)\n",
		_flush_op_write_back_cache_L12);
	raw_all_irq_save(flags);
	E2K_WAIT_MA;
	NATIVE_FLUSH_CACHE_L12(_flush_op_write_back_cache_L12);
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

	DebugMR("Flush all TLBs (op 0x%lx)\n", _flush_op_tlb_all);
	raw_all_irq_save(flags);
	E2K_WAIT_ST;
	NATIVE_FLUSH_TLB_ALL(_flush_op_tlb_all);
	E2K_WAIT(_fl_c | _ma_c);
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
	DebugMR("Flush all ICACHE op 0x%lx\n", _flush_op_icache_all);
	E2K_WAIT_ST;
	NATIVE_FLUSH_ICACHE_ALL(_flush_op_icache_all);
	E2K_WAIT_FLUSH;
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
 * native MMU DEBUG registers access
 */
#define	NATIVE_READ_MMU_DEBUG_REG(reg_mnemonic)	\
		NATIVE_GET_MMUREG(reg_mnemonic)
#define	NATIVE_WRITE_MMU_DEBUG_REG(reg_mnemonic, reg_value)	\
		NATIVE_SET_MMUREG(reg_mnemonic, reg_value)
#define	NATIVE_READ_DDBAR0_REG_VALUE()	\
		NATIVE_READ_MMU_DEBUG_REG(ddbar0)
#define	NATIVE_READ_DDBAR1_REG_VALUE()	\
		NATIVE_READ_MMU_DEBUG_REG(ddbar1)
#define	NATIVE_READ_DDBAR2_REG_VALUE()	\
		NATIVE_READ_MMU_DEBUG_REG(ddbar2)
#define	NATIVE_READ_DDBAR3_REG_VALUE()	\
		NATIVE_READ_MMU_DEBUG_REG(ddbar3)
#define	NATIVE_READ_DDBCR_REG_VALUE()	\
		NATIVE_READ_MMU_DEBUG_REG(ddbcr)
#define	NATIVE_READ_DDBSR_REG_VALUE()	\
		NATIVE_READ_MMU_DEBUG_REG(ddbsr)
#define	NATIVE_READ_DDMAR0_REG_VALUE()	\
		NATIVE_READ_MMU_DEBUG_REG(ddmar0)
#define	NATIVE_READ_DDMAR1_REG_VALUE()	\
		NATIVE_READ_MMU_DEBUG_REG(ddmar1)
#define	NATIVE_READ_DDMCR_REG_VALUE()	\
		NATIVE_READ_MMU_DEBUG_REG(ddmcr)
#define	NATIVE_WRITE_DDBAR0_REG_VALUE(value)	\
		NATIVE_WRITE_MMU_DEBUG_REG(ddbar0, value)
#define	NATIVE_WRITE_DDBAR1_REG_VALUE(value)	\
		NATIVE_WRITE_MMU_DEBUG_REG(ddbar1, value)
#define	NATIVE_WRITE_DDBAR2_REG_VALUE(value)	\
		NATIVE_WRITE_MMU_DEBUG_REG(ddbar2, value)
#define	NATIVE_WRITE_DDBAR3_REG_VALUE(value)	\
		NATIVE_WRITE_MMU_DEBUG_REG(ddbar3, value)
#define	NATIVE_WRITE_DDBCR_REG_VALUE(value)	\
		NATIVE_WRITE_MMU_DEBUG_REG(ddbcr, value)
#define	NATIVE_WRITE_DDBSR_REG_VALUE(value)	\
		NATIVE_WRITE_MMU_DEBUG_REG(ddbsr, value)
#define	NATIVE_WRITE_DDMAR0_REG_VALUE(value)	\
		NATIVE_WRITE_MMU_DEBUG_REG(ddmar0, value)
#define	NATIVE_WRITE_DDMAR1_REG_VALUE(value)	\
		NATIVE_WRITE_MMU_DEBUG_REG(ddmar1, value)
#define	NATIVE_WRITE_DDMCR_REG_VALUE(value)	\
		NATIVE_WRITE_MMU_DEBUG_REG(ddmcr, value)

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
