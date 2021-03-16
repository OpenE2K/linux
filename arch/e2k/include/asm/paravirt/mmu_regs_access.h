/*
 * E2K MMU registers access paravirtualization
 *
 * Copyright 2017 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_PARAVIRT_MMU_REGS_ACCESS_H_
#define	_E2K_PARAVIRT_MMU_REGS_ACCESS_H_

#ifndef __ASSEMBLY__

#include <linux/types.h>
#include <asm/paravirt/pv_ops.h>

/*
 * Write/read MMU register
 */
#ifdef	CONFIG_KVM_GUEST
#include <asm/kvm/mmu_regs_access.h>

static inline void
PV_WRITE_MMU_REG(mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	pv_mmu_ops.write_mmu_reg(mmu_addr, mmu_reg);
}

static inline mmu_reg_t
PV_READ_MMU_REG(mmu_addr_t mmu_addr)
{
	return pv_mmu_ops.read_mmu_reg(mmu_addr);
}

static inline void PV_WRITE_MMU_OS_PPTB_REG(mmu_reg_t reg_val)
{
	PV_WRITE_MMU_REG(MMU_ADDR_OS_PPTB, reg_val);
}
static inline unsigned long PV_READ_MMU_OS_PPTB_REG(void)
{
	return mmu_reg_val(PV_READ_MMU_REG(MMU_ADDR_OS_PPTB));
}
static inline void PV_WRITE_MMU_OS_VPTB_REG(mmu_reg_t reg_val)
{
	PV_WRITE_MMU_REG(MMU_ADDR_OS_VPTB, reg_val);
}
static inline unsigned long PV_READ_MMU_OS_VPTB_REG(void)
{
	return mmu_reg_val(PV_READ_MMU_REG(MMU_ADDR_OS_VPTB));
}
static inline void PV_WRITE_MMU_OS_VAB_REG(mmu_reg_t reg_val)
{
	PV_WRITE_MMU_REG(MMU_ADDR_OS_VAB, reg_val);
}
static inline unsigned long PV_READ_MMU_OS_VAB_REG(void)
{
	return mmu_reg_val(PV_READ_MMU_REG(MMU_ADDR_OS_VAB));
}

static inline void
BOOT_PV_WRITE_MMU_REG(mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	BOOT_PARAVIRT_WRITE_MMU_REG(mmu_addr, mmu_reg);
}

static inline mmu_reg_t
BOOT_PV_READ_MMU_REG(mmu_addr_t mmu_addr)
{
	return BOOT_PARAVIRT_READ_MMU_REG(mmu_addr);
}

static inline void BOOT_PV_WRITE_MMU_OS_PPTB_REG(mmu_reg_t reg_val)
{
	BOOT_PV_WRITE_MMU_REG(MMU_ADDR_OS_PPTB, reg_val);
}
static inline unsigned long BOOT_PV_READ_MMU_OS_PPTB_REG(void)
{
	return mmu_reg_val(BOOT_PV_READ_MMU_REG(MMU_ADDR_OS_PPTB));
}
static inline void BOOT_PV_WRITE_MMU_OS_VPTB_REG(mmu_reg_t reg_val)
{
	BOOT_PV_WRITE_MMU_REG(MMU_ADDR_OS_VPTB, reg_val);
}
static inline unsigned long BOOT_PV_READ_MMU_OS_VPTB_REG(void)
{
	return mmu_reg_val(BOOT_PV_READ_MMU_REG(MMU_ADDR_OS_VPTB));
}
static inline void BOOT_PV_WRITE_MMU_OS_VAB_REG(mmu_reg_t reg_val)
{
	BOOT_PV_WRITE_MMU_REG(MMU_ADDR_OS_VAB, reg_val);
}
static inline unsigned long BOOT_PV_READ_MMU_OS_VAB_REG(void)
{
	return mmu_reg_val(BOOT_PV_READ_MMU_REG(MMU_ADDR_OS_VAB));
}

/*
 * Write/read Data TLB register
 */

static inline void
PV_WRITE_DTLB_REG(tlb_addr_t tlb_addr, mmu_reg_t mmu_reg)
{
	pv_mmu_ops.write_dtlb_reg(tlb_addr, mmu_reg);
}

static inline mmu_reg_t
PV_READ_DTLB_REG(tlb_addr_t tlb_addr)
{
	return pv_mmu_ops.read_dtlb_reg(tlb_addr);
}

/*
 * Flush TLB page/entry
 */

static inline void
PV_FLUSH_TLB_ENTRY(flush_op_t flush_op, flush_addr_t flush_addr)
{
	pv_mmu_ops.flush_tlb_entry(flush_op, flush_addr);
}

/*
 * Flush DCACHE line
 */

static inline void
PV_FLUSH_DCACHE_LINE(e2k_addr_t virt_addr)
{
	pv_mmu_ops.flush_dcache_line(virt_addr);
}

/*
 * Clear DCACHE L1 set
 */
static inline void
PV_CLEAR_DCACHE_L1_SET(e2k_addr_t virt_addr, unsigned long set)
{
	pv_mmu_ops.clear_dcache_l1_set(virt_addr, set);
}

/*
 * Write/read DCACHE L2 registers
 */
static inline void
PV_WRITE_L2_REG(unsigned long reg_val, int reg_num, int bank_num)
{
	pv_mmu_ops.write_dcache_l2_reg(reg_val, reg_num, bank_num);
}
static inline unsigned long
PV_READ_L2_REG(int reg_num, int bank_num)
{
	return pv_mmu_ops.read_dcache_l2_reg(reg_num, bank_num);
}

/*
 * Flush ICACHE line
 */
static inline void
PV_FLUSH_ICACHE_LINE(flush_op_t flush_op, flush_addr_t flush_addr)
{
	pv_mmu_ops.flush_icache_line(flush_op, flush_addr);
}

/*
 * Flush and invalidate or write back CACHE(s) (invalidate all caches
 * of the processor)
 */
static inline void
PV_FLUSH_CACHE_L12(flush_op_t flush_op)
{
	pv_mmu_ops.flush_cache_all(flush_op);
}

/*
 * Flush TLB (invalidate all TLBs of the processor)
 */
static inline void
PV_FLUSH_TLB_ALL(flush_op_t flush_op)
{
	pv_mmu_ops.do_flush_tlb_all(flush_op);
}

/*
 * Flush ICACHE (invalidate instruction caches of the processor)
 */
static inline void
PV_FLUSH_ICACHE_ALL(flush_op_t flush_op)
{
	pv_mmu_ops.flush_icache_all(flush_op);
}

/*
 * Get Entry probe for virtual address
 */
static inline probe_entry_t
PV_ENTRY_PROBE_MMU_OP(e2k_addr_t virt_addr)
{
	return pv_mmu_ops.entry_probe_mmu_op(virt_addr);
}

/*
 * Get physical address for virtual address
 */
static inline probe_entry_t
PV_ADDRESS_PROBE_MMU_OP(e2k_addr_t virt_addr)
{
	return pv_mmu_ops.address_probe_mmu_op(virt_addr);
}

/*
 * Read CLW register
 */
static inline clw_reg_t
PV_READ_CLW_REG(clw_addr_t clw_addr)
{
	return pv_mmu_ops.read_clw_reg(clw_addr);
}

/*
 * MMU DEBUG registers access
 */
static inline void
PV_WRITE_MMU_DEBUG_REG_VALUE(int reg_no, mmu_reg_t mmu_reg)
{
	pv_mmu_ops.write_mmu_debug_reg(reg_no, mmu_reg);
}
static inline mmu_reg_t
PV_READ_MMU_DEBUG_REG_VALUE(int reg_no)
{
	return pv_mmu_ops.read_mmu_debug_reg(reg_no);
}

static inline mmu_reg_t
PV_READ_DDBAR0_REG_VALUE(void)
{
	return PV_READ_MMU_DEBUG_REG_VALUE(MMU_DDBAR0_REG_NO);
}
static inline mmu_reg_t
PV_READ_DDBAR1_REG_VALUE(void)
{
	return PV_READ_MMU_DEBUG_REG_VALUE(MMU_DDBAR1_REG_NO);
}
static inline mmu_reg_t
PV_READ_DDBAR2_REG_VALUE(void)
{
	return PV_READ_MMU_DEBUG_REG_VALUE(MMU_DDBAR2_REG_NO);
}
static inline mmu_reg_t
PV_READ_DDBAR3_REG_VALUE(void)
{
	return PV_READ_MMU_DEBUG_REG_VALUE(MMU_DDBAR3_REG_NO);
}
static inline mmu_reg_t
PV_READ_DDBCR_REG_VALUE(void)
{
	return PV_READ_MMU_DEBUG_REG_VALUE(MMU_DDBCR_REG_NO);
}
static inline mmu_reg_t
PV_READ_DDBSR_REG_VALUE(void)
{
	return PV_READ_MMU_DEBUG_REG_VALUE(MMU_DDBSR_REG_NO);
}
static inline mmu_reg_t
PV_READ_DDMAR0_REG_VALUE(void)
{
	return PV_READ_MMU_DEBUG_REG_VALUE(MMU_DDMAR0_REG_NO);
}
static inline mmu_reg_t
PV_READ_DDMAR1_REG_VALUE(void)
{
	return PV_READ_MMU_DEBUG_REG_VALUE(MMU_DDMAR1_REG_NO);
}
static inline mmu_reg_t
PV_READ_DDMCR_REG_VALUE(void)
{
	return PV_READ_MMU_DEBUG_REG_VALUE(MMU_DDMCR_REG_NO);
}
static inline void
PV_WRITE_DDBAR0_REG_VALUE(mmu_reg_t mmu_reg)
{
	PV_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDBAR0_REG_NO, mmu_reg);
}
static inline void
PV_WRITE_DDBAR1_REG_VALUE(mmu_reg_t mmu_reg)
{
	PV_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDBAR1_REG_NO, mmu_reg);
}
static inline void
PV_WRITE_DDBAR2_REG_VALUE(mmu_reg_t mmu_reg)
{
	PV_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDBAR2_REG_NO, mmu_reg);
}
static inline void
PV_WRITE_DDBAR3_REG_VALUE(mmu_reg_t mmu_reg)
{
	PV_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDBAR3_REG_NO, mmu_reg);
}
static inline void
PV_WRITE_DDBCR_REG_VALUE(mmu_reg_t mmu_reg)
{
	PV_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDBCR_REG_NO, mmu_reg);
}
static inline void
PV_WRITE_DDBSR_REG_VALUE(mmu_reg_t mmu_reg)
{
	PV_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDBSR_REG_NO, mmu_reg);
}
static inline void
PV_WRITE_DDMAR0_REG_VALUE(mmu_reg_t mmu_reg)
{
	PV_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDMAR0_REG_NO, mmu_reg);
}
static inline void
PV_WRITE_DDMAR1_REG_VALUE(mmu_reg_t mmu_reg)
{
	PV_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDMAR1_REG_NO, mmu_reg);
}
static inline void
PV_WRITE_DDMCR_REG_VALUE(mmu_reg_t mmu_reg)
{
	PV_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDMCR_REG_NO, mmu_reg);
}
#else	/* ! CONFIG_KVM_GUEST */
 #error "Unknown virtualization type"
#endif	/* CONFIG_KVM_GUEST */

#ifdef	CONFIG_PARAVIRT_GUEST
/* It is paravirtualized host and guest kernel */

static inline void WRITE_MMU_REG(mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	PV_WRITE_MMU_REG(mmu_addr, mmu_reg);
}

static inline mmu_reg_t READ_MMU_REG(mmu_addr_t mmu_addr)
{
	return (mmu_reg_t)PV_READ_MMU_REG(mmu_addr);
}

static inline void WRITE_MMU_OS_PPTB(mmu_reg_t reg_val)
{
	PV_WRITE_MMU_OS_PPTB_REG(reg_val);
}
static inline unsigned long READ_MMU_OS_PPTB(void)
{
	return PV_READ_MMU_OS_PPTB_REG();
}
static inline void WRITE_MMU_OS_VPTB(mmu_reg_t reg_val)
{
	PV_WRITE_MMU_OS_VPTB_REG(reg_val);
}
static inline unsigned long READ_MMU_OS_VPTB(void)
{
	return PV_READ_MMU_OS_VPTB_REG();
}
static inline void WRITE_MMU_OS_VAB(mmu_reg_t reg_val)
{
	PV_WRITE_MMU_OS_VAB_REG(reg_val);
}
static inline unsigned long READ_MMU_OS_VAB(void)
{
	return PV_READ_MMU_OS_VAB_REG();
}

static inline void
BOOT_WRITE_MMU_REG(mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	BOOT_PV_WRITE_MMU_REG(mmu_addr, mmu_reg);
}

static inline mmu_reg_t
BOOT_READ_MMU_REG(mmu_addr_t mmu_addr)
{
	return BOOT_PV_READ_MMU_REG(mmu_addr);
}

static inline void BOOT_WRITE_MMU_OS_PPTB(mmu_reg_t reg_val)
{
	BOOT_PV_WRITE_MMU_OS_PPTB_REG(reg_val);
}
static inline unsigned long BOOT_READ_MMU_OS_PPTB(void)
{
	return BOOT_PV_READ_MMU_OS_PPTB_REG();
}
static inline void BOOT_WRITE_MMU_OS_VPTB(mmu_reg_t reg_val)
{
	BOOT_PV_WRITE_MMU_OS_VPTB_REG(reg_val);
}
static inline unsigned long BOOT_READ_MMU_OS_VPTB(void)
{
	return BOOT_PV_READ_MMU_OS_VPTB_REG();
}
static inline void BOOT_WRITE_MMU_OS_VAB(mmu_reg_t reg_val)
{
	BOOT_PV_WRITE_MMU_OS_VAB_REG(reg_val);
}
static inline unsigned long BOOT_READ_MMU_OS_VAB(void)
{
	return BOOT_PV_READ_MMU_OS_VAB_REG();
}

/*
 * Write/read Data TLB register
 */

static inline void
WRITE_DTLB_REG(tlb_addr_t tlb_addr, mmu_reg_t mmu_reg)
{
	PV_WRITE_DTLB_REG(tlb_addr, mmu_reg);
}

static inline mmu_reg_t
READ_DTLB_REG(tlb_addr_t tlb_addr)
{
	return PV_READ_DTLB_REG(tlb_addr);
}

/*
 * Flush TLB page/entry
 */

static inline void
FLUSH_TLB_ENTRY(flush_op_t flush_op, flush_addr_t flush_addr)
{
	PV_FLUSH_TLB_ENTRY(flush_op, flush_addr);
}

/*
 * Flush DCACHE line
 */

static inline void FLUSH_DCACHE_LINE(e2k_addr_t virt_addr)
{
	PV_FLUSH_DCACHE_LINE(virt_addr);
}
static inline void FLUSH_DCACHE_LINE_OFFSET(e2k_addr_t virt_addr, size_t offset)
{
	PV_FLUSH_DCACHE_LINE(virt_addr + offset);
}

/*
 * Clear DCACHE L1 set
 */
static inline void
CLEAR_DCACHE_L1_SET(e2k_addr_t virt_addr, unsigned long set)
{
	PV_CLEAR_DCACHE_L1_SET(virt_addr, set);
}

/*
 * Write/read DCACHE L2 registers
 */
static inline void
WRITE_L2_REG(unsigned long reg_val, int reg_num, int bank_num)
{
	PV_WRITE_L2_REG(reg_val, reg_num, bank_num);
}
static inline unsigned long
READ_L2_REG(int reg_num, int bank_num)
{
	return PV_READ_L2_REG(reg_num, bank_num);
}

/*
 * Flush ICACHE line
 */

static inline void
FLUSH_ICACHE_LINE(flush_op_t flush_op, flush_addr_t flush_addr)
{
	PV_FLUSH_ICACHE_LINE(flush_op, flush_addr);
}

/*
 * Flush and invalidate or write back CACHE(s) (invalidate all caches
 * of the processor)
 */

static inline void
FLUSH_CACHE_L12(flush_op_t flush_op)
{
	PV_FLUSH_CACHE_L12(flush_op);
}

/*
 * Flush TLB (invalidate all TLBs of the processor)
 */

static inline void
FLUSH_TLB_ALL(flush_op_t flush_op)
{
	PV_FLUSH_TLB_ALL(flush_op);
}

/*
 * Flush ICACHE (invalidate instruction caches of the processor)
 */

static inline void
FLUSH_ICACHE_ALL(flush_op_t flush_op)
{
	PV_FLUSH_ICACHE_ALL(flush_op);
}

/*
 * Get Entry probe for virtual address
 */

static inline probe_entry_t
ENTRY_PROBE_MMU_OP(e2k_addr_t virt_addr)
{
	return PV_ENTRY_PROBE_MMU_OP(virt_addr);
}

/*
 * Get physical address for virtual address
 */

static inline probe_entry_t
ADDRESS_PROBE_MMU_OP(e2k_addr_t virt_addr)
{
	return PV_ADDRESS_PROBE_MMU_OP(virt_addr);
}

/*
 * Read CLW register
 */

static inline clw_reg_t
READ_CLW_REG(clw_addr_t clw_addr)
{
	return PV_READ_CLW_REG(clw_addr);
}

/*
 * KVM MMU DEBUG registers access
 */
static inline mmu_reg_t
READ_DDBAR0_REG_VALUE(void)
{
	return PV_READ_DDBAR0_REG_VALUE();
}
static inline mmu_reg_t
READ_DDBAR1_REG_VALUE(void)
{
	return PV_READ_DDBAR1_REG_VALUE();
}
static inline mmu_reg_t
READ_DDBAR2_REG_VALUE(void)
{
	return PV_READ_DDBAR2_REG_VALUE();
}
static inline mmu_reg_t
READ_DDBAR3_REG_VALUE(void)
{
	return PV_READ_DDBAR3_REG_VALUE();
}
static inline mmu_reg_t
READ_DDBCR_REG_VALUE(void)
{
	return PV_READ_DDBCR_REG_VALUE();
}
static inline mmu_reg_t
READ_DDBSR_REG_VALUE(void)
{
	return PV_READ_DDBSR_REG_VALUE();
}
static inline mmu_reg_t
READ_DDMAR0_REG_VALUE(void)
{
	return PV_READ_DDMAR0_REG_VALUE();
}
static inline mmu_reg_t
READ_DDMAR1_REG_VALUE(void)
{
	return PV_READ_DDMAR1_REG_VALUE();
}
static inline mmu_reg_t
READ_DDMCR_REG_VALUE(void)
{
	return PV_READ_DDMCR_REG_VALUE();
}
static inline void
WRITE_DDBAR0_REG_VALUE(mmu_reg_t value)
{
	PV_WRITE_DDBAR0_REG_VALUE(value);
}
static inline void
WRITE_DDBAR1_REG_VALUE(mmu_reg_t value)
{
	PV_WRITE_DDBAR1_REG_VALUE(value);
}
static inline void
WRITE_DDBAR2_REG_VALUE(mmu_reg_t value)
{
	PV_WRITE_DDBAR2_REG_VALUE(value);
}
static inline void
WRITE_DDBAR3_REG_VALUE(mmu_reg_t value)
{
	PV_WRITE_DDBAR3_REG_VALUE(value);
}
static inline void
WRITE_DDBCR_REG_VALUE(mmu_reg_t value)
{
	PV_WRITE_DDBCR_REG_VALUE(value);
}
static inline void
WRITE_DDBSR_REG_VALUE(mmu_reg_t value)
{
	PV_WRITE_DDBSR_REG_VALUE(value);
}
static inline void
WRITE_DDMAR0_REG_VALUE(mmu_reg_t value)
{
	PV_WRITE_DDMAR0_REG_VALUE(value);
}
static inline void
WRITE_DDMAR1_REG_VALUE(mmu_reg_t value)
{
	PV_WRITE_DDMAR1_REG_VALUE(value);
}
static inline void
WRITE_DDMCR_REG_VALUE(mmu_reg_t value)
{
	PV_WRITE_DDMCR_REG_VALUE(value);
}

#endif	/* CONFIG_PARAVIRT_GUEST */

#endif /* ! __ASSEMBLY__ */

#endif	/* _E2K_PARAVIRT_MMU_REGS_ACCESS_H_ */
