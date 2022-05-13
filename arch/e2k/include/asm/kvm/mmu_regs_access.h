/*
 * E2K MMU registers access virtualization for KVM guest
 *
 * Copyright 2011 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_KVM_MMU_REGS_ACCESS_H_
#define	_E2K_KVM_MMU_REGS_ACCESS_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <linux/kernel.h>
#include <asm/e2k_api.h>
#include <asm/p2v/boot_head.h>
#include <asm/mmu_regs_types.h>
#include <asm/mas.h>
#include <asm/tlb_regs_types.h>
#include <asm/kvm/guest.h>
#include <asm/kvm/guest/cacheflush.h>

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

/*
 * Basic functions accessing MMU on guest.
 */
#define	GUEST_MMU_REGS_BASE	(offsetof(kvm_vcpu_state_t, mmu) +	\
				offsetof(kvm_mmu_state_t, regs))
#define	GUEST_MMU_REG(reg_no)	(GUEST_MMU_REGS_BASE +			\
				((reg_no) * sizeof(mmu_reg_t)))
#define	GUEST_GET_MMU_REG(reg_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_MMU_REG(reg_no))
#define	GUEST_SET_MMU_REG(reg_no, value)				\
		E2K_STORE_GUEST_VCPU_STATE_D(GUEST_MMU_REG(reg_no), value)
#define	GUEST_TRAP_CELLAR_BASE	(offsetof(kvm_vcpu_state_t, mmu) +	\
				offsetof(kvm_mmu_state_t, tcellar))
#define	GUEST_TC_ENTRY(tc_no)	(GUEST_TRAP_CELLAR_BASE +		\
				((tc_no) * sizeof(trap_cellar_t)))
#define	GUEST_GET_TC_ADDRESS(tc_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_TC_ENTRY(tc_no) +	\
				offsetof(trap_cellar_t, address))
#define	GUEST_GET_TC_CONDITION(tc_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_TC_ENTRY(tc_no) +	\
				offsetof(trap_cellar_t, condition))
#define	GUEST_GET_TC_DATA(tc_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_TC_ENTRY(tc_no) +	\
				offsetof(trap_cellar_t, data))
#define	GUEST_MMU_DEBUG_REGS_BASE					\
				(offsetof(kvm_vcpu_state_t, mmu) +	\
				offsetof(kvm_mmu_state_t, debug_regs))
#define	GUEST_MMU_DEBUG_REG(reg_no)					\
				(GUEST_MMU_DEBUG_REGS_BASE +		\
				((reg_no) * sizeof(mmu_reg_t)))
#define	GUEST_GET_MMU_DEBUG_REG(reg_no)					\
		E2K_LOAD_GUEST_VCPU_STATE_D(GUEST_MMU_DEBUG_REG(reg_no))
#define	GUEST_SET_MMU_DEBUG_REG(reg_no, value)				\
		E2K_STORE_GUEST_VCPU_STATE_D(GUEST_MMU_DEBUG_REG(reg_no), value)

/*
 * Write/read MMU register
 */
static inline void KVM_WRITE_MMU_REG(mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	unsigned long mmu_reg_no = MMU_REG_NO_FROM_MMU_ADDR(mmu_addr);

	GUEST_SET_MMU_REG(mmu_reg_no, mmu_reg);
	if (IS_HV_GM())
		NATIVE_WRITE_MMU_REG(mmu_addr, mmu_reg);
}

static inline mmu_reg_t KVM_READ_MMU_REG(mmu_addr_t mmu_addr)
{
	unsigned long mmu_reg_no = MMU_REG_NO_FROM_MMU_ADDR(mmu_addr);

	if (likely(IS_HV_GM())) {
		return (mmu_reg_t)NATIVE_READ_MMU_REG(mmu_addr);
	} else {
		return (mmu_reg_t)GUEST_GET_MMU_REG(mmu_reg_no);
	}
}
static inline void BOOT_KVM_WRITE_MMU_REG(mmu_addr_t mmu_addr,
						mmu_reg_t mmu_reg)
{
	unsigned long mmu_reg_no = MMU_REG_NO_FROM_MMU_ADDR(mmu_addr);

	GUEST_SET_MMU_REG(mmu_reg_no, mmu_reg);
	if (BOOT_IS_HV_GM())
		NATIVE_WRITE_MMU_REG(mmu_addr, mmu_reg);
}

static inline mmu_reg_t BOOT_KVM_READ_MMU_REG(mmu_addr_t mmu_addr)
{
	unsigned long mmu_reg_no = MMU_REG_NO_FROM_MMU_ADDR(mmu_addr);

	if (likely(BOOT_IS_HV_GM())) {
		return (mmu_reg_t)NATIVE_READ_MMU_REG(mmu_addr);
	} else {
		return (mmu_reg_t)GUEST_GET_MMU_REG(mmu_reg_no);
	}
}

static inline void KVM_WRITE_MMU_OS_PPTB_REG(mmu_reg_t reg_val)
{
	KVM_WRITE_MMU_REG(MMU_ADDR_OS_PPTB, reg_val);
}
static inline unsigned long KVM_READ_MMU_OS_PPTB_REG(void)
{
	return mmu_reg_val(KVM_READ_MMU_REG(MMU_ADDR_OS_PPTB));
}
static inline void KVM_WRITE_MMU_OS_VPTB_REG(mmu_reg_t reg_val)
{
	KVM_WRITE_MMU_REG(MMU_ADDR_OS_VPTB, reg_val);
}
static inline unsigned long KVM_READ_MMU_OS_VPTB_REG(void)
{
	return mmu_reg_val(KVM_READ_MMU_REG(MMU_ADDR_OS_VPTB));
}
static inline void KVM_WRITE_MMU_OS_VAB_REG(mmu_reg_t reg_val)
{
	KVM_WRITE_MMU_REG(MMU_ADDR_OS_VAB, reg_val);
}
static inline unsigned long KVM_READ_MMU_OS_VAB_REG(void)
{
	return mmu_reg_val(KVM_READ_MMU_REG(MMU_ADDR_OS_VAB));
}
static inline void KVM_WRITE_MMU_PID_REG(mmu_reg_t reg_val)
{
	KVM_WRITE_MMU_REG(MMU_ADDR_PID, reg_val);
	if (IS_HV_GM()) {
		/* FIXME: guest should fully control own PTs including */
		/* all hardware MMU registers, but it is not so now, */
		/* for example PT roots and context registers are controled */
		/* by hypervisor as for paravirtualized kernels */
		native_flush_TLB_all();
	}
}
static inline unsigned long KVM_READ_MMU_PID_REG(void)
{
	return mmu_reg_val(KVM_READ_MMU_REG(MMU_ADDR_PID));
}

static inline void BOOT_KVM_WRITE_MMU_OS_PPTB_REG(mmu_reg_t reg_val)
{
	BOOT_KVM_WRITE_MMU_REG(MMU_ADDR_OS_PPTB, reg_val);
}
static inline unsigned long BOOT_KVM_READ_MMU_OS_PPTB_REG(void)
{
	return mmu_reg_val(BOOT_KVM_READ_MMU_REG(MMU_ADDR_OS_PPTB));
}
static inline void BOOT_KVM_WRITE_MMU_OS_VPTB_REG(mmu_reg_t reg_val)
{
	BOOT_KVM_WRITE_MMU_REG(MMU_ADDR_OS_VPTB, reg_val);
}
static inline unsigned long BOOT_KVM_READ_MMU_OS_VPTB_REG(void)
{
	return mmu_reg_val(BOOT_KVM_READ_MMU_REG(MMU_ADDR_OS_VPTB));
}
static inline void BOOT_KVM_WRITE_MMU_OS_VAB_REG(mmu_reg_t reg_val)
{
	BOOT_KVM_WRITE_MMU_REG(MMU_ADDR_OS_VAB, reg_val);
}
static inline unsigned long BOOT_KVM_READ_MMU_OS_VAB_REG(void)
{
	return mmu_reg_val(BOOT_KVM_READ_MMU_REG(MMU_ADDR_OS_VAB));
}
static inline void BOOT_KVM_WRITE_MMU_PID_REG(mmu_reg_t reg_val)
{
	BOOT_KVM_WRITE_MMU_REG(MMU_ADDR_PID, reg_val);
	if (BOOT_IS_HV_GM()) {
		/* FIXME: guest should fully control own PTs including */
		/* all hardware MMU registers, but it is not so now, */
		/* for example PT roots and context registers are controled */
		/* by hypervisor as for paravirtualized kernels */
		NATIVE_FLUSH_TLB_ALL(flush_op_tlb_all);
	}
}
static inline unsigned long BOOT_KVM_READ_MMU_PID_REG(void)
{
	return mmu_reg_val(BOOT_KVM_READ_MMU_REG(MMU_ADDR_PID));
}

static inline unsigned int KVM_READ_MMU_TRAP_COUNT(void)
{
	return mmu_reg_val(KVM_READ_MMU_REG(MMU_ADDR_TRAP_COUNT));
}

static inline void KVM_RESET_MMU_TRAP_COUNT(void)
{
	KVM_WRITE_MMU_REG(MMU_ADDR_TRAP_COUNT, 0);
}

static inline void BOOT_KVM_RESET_MMU_TRAP_COUNT(void)
{
	BOOT_KVM_WRITE_MMU_REG(MMU_ADDR_TRAP_COUNT, 0);
}

static inline unsigned long KVM_READ_TC_ADDRESS(int tc_no)
{
	return GUEST_GET_TC_ADDRESS(tc_no);
}

static inline tc_cond_t KVM_READ_TC_CONDITION(int tc_no)
{
	return (tc_cond_t)(u64)GUEST_GET_TC_CONDITION(tc_no);
}

static inline unsigned long KVM_READ_TC_DATA(int tc_no)
{
	/* FIXME: data has tag, so here should be load tagged value */
	return GUEST_GET_TC_DATA(tc_no);
}

/*
 * Write/read Data TLB register
 */

static inline void KVM_WRITE_DTLB_REG(tlb_addr_t tlb_addr, mmu_reg_t mmu_reg)
{
	if (IS_HV_GM()) {
		NATIVE_WRITE_DTLB_REG(tlb_addr, mmu_reg);
	} else {
		panic("KVM_WRITE_DTLB_REG() is not yet implemented\n");
	}
}

static inline mmu_reg_t KVM_READ_DTLB_REG(tlb_addr_t tlb_addr)
{
	if (IS_HV_GM()) {
		return NATIVE_READ_DTLB_REG(tlb_addr);
	} else {
		return kvm_read_dtlb_reg(tlb_addr);
	}
}

/*
 * Flush TLB page/entry
 */

static inline void
KVM_FLUSH_TLB_ENTRY(flush_op_t flush_op, flush_addr_t flush_addr)
{
	if (unlikely(flush_addr_get_pid(flush_addr) == E2K_KERNEL_CONTEXT)) {
		pr_warn("%s(): CPU #%d try to flush %s addr 0x%llx pid 0x%03llx\n",
			__func__, smp_processor_id(),
			(flush_op_get_type(flush_op) == FLUSH_TLB_PAGE_OP) ?
				"TLB page" : "???",
			FLUSH_VADDR_TO_VA(flush_addr),
			flush_addr_get_pid(flush_addr));
	}
}

/*
 * Flush DCACHE line
 */

static inline void
KVM_FLUSH_DCACHE_LINE(e2k_addr_t virt_addr)
{
	if (IS_HV_GM()) {
		/*
		 * Prevent putting privilidged instruction strd from
		 * NATIVE_FLUSH_DCACHE_LINE under predicate IS_HV_GM().
		 * Even with false value of predicate it can cause priv.
		 * action exception in guest kernel.
		 */
		E2K_CMD_SEPARATOR;
		NATIVE_FLUSH_DCACHE_LINE(virt_addr);
	} else {
		kvm_flush_dcache_line(virt_addr);
	}
}

/*
 * Read DCACHE L1 fault_reg register
 */
static inline u64
KVM_READ_L1_FAULT_REG(void)
{
	if (IS_HV_GM()) {
		return NATIVE_READ_L1_FAULT_REG();
	} else {
		return kvm_read_dcache_l1_fault_reg();
	}
}

/*
 * Clear DCACHE L1 set
 */
static inline void
KVM_CLEAR_DCACHE_L1_SET(e2k_addr_t virt_addr, unsigned long set)
{
	if (IS_HV_GM()) {
		NATIVE_CLEAR_DCACHE_L1_SET(virt_addr, set);
	} else {
		kvm_clear_dcache_l1_set(virt_addr, set);
	}
}

/*
 * Write/read DCACHE L2 registers
 */
static inline void
KVM_WRITE_DCACHE_L2_REG(unsigned long reg_val, int reg_num, int bank_num)
{
	if (IS_HV_GM()) {
		NATIVE_WRITE_L2_REG(reg_val, reg_num, bank_num);
	} else {
		kvm_write_dcache_l2_reg(reg_val, reg_num, bank_num);
	}
}
static inline unsigned long
KVM_READ_DCACHE_L2_REG(int reg_num, int bank_num)
{
	if (IS_HV_GM()) {
		return NATIVE_READ_L2_REG(reg_num, bank_num);
	} else {
		return kvm_read_dcache_l2_reg(reg_num, bank_num);
	}
}

/*
 * Flush ICACHE line
 */

static inline void
KVM_FLUSH_ICACHE_LINE(flush_op_t flush_op, flush_addr_t flush_addr)
{
	if (IS_HV_GM()) {
		NATIVE_FLUSH_ICACHE_LINE(flush_op, flush_addr);
	} else {
		/* any switch to guest kernel now flush all TLB and caches */
		/* so precise flushing can be not implemented */
		pr_debug("KVM_FLUSH_ICACHE_LINE() is not yet implemented\n");
	}
}

/*
 * Flush and invalidate or write back CACHE(s) (invalidate all caches
 * of the processor)
 */

static inline void
KVM_FLUSH_CACHE_L12(flush_op_t flush_op)
{
	if (IS_HV_GM()) {
		native_write_back_CACHE_L12();
	} else {
		panic("KVM_FLUSH_CACHE_L12() is not yet implemented\n");
	}
}

/*
 * Flush TLB (invalidate all TLBs of the processor)
 */

static inline void
KVM_FLUSH_TLB_ALL(flush_op_t flush_op)
{
	pr_warn_once("%s(): try to flush all TLB : op 0x%lx\n",
		__func__, flush_op);
}

/*
 * Flush ICACHE (invalidate instruction caches of the processor)
 */

static inline void
KVM_FLUSH_ICACHE_ALL(flush_op_t flush_op)
{
	if (IS_HV_GM()) {
		native_flush_ICACHE_all();
	} else {
		/* panic("KVM_FLUSH_ICACHE_ALL() is not yet implemented\n"); */
	}
}

/*
 * Get Entry probe for virtual address
 */

static inline probe_entry_t
KVM_ENTRY_PROBE_MMU_OP(e2k_addr_t virt_addr)
{
	if (IS_HV_GM()) {
		return NATIVE_ENTRY_PROBE_MMU_OP(virt_addr);
	} else {
		return kvm_mmu_entry_probe(virt_addr);
	}
}

/*
 * Get physical address for virtual address
 */

static inline probe_entry_t
KVM_ADDRESS_PROBE_MMU_OP(e2k_addr_t virt_addr)
{
	if (IS_HV_GM()) {
		return NATIVE_ADDRESS_PROBE_MMU_OP(virt_addr);
	} else {
		return kvm_mmu_address_probe(virt_addr);
	}
}

/*
 * Read CLW register
 */

static inline clw_reg_t
KVM_READ_CLW_REG(clw_addr_t clw_addr)
{
	panic("KVM_READ_CLW_REG() is not yet implemented\n");
	return -1;
}

/*
 * Write CLW register
 */

static inline void
KVM_WRITE_CLW_REG(clw_addr_t clw_addr, clw_reg_t val)
{
	panic("KVM_WRITE_CLW_REG() is not yet implemented\n");
}

/*
 * KVM MMU DEBUG registers access
 */
static inline mmu_reg_t
KVM_READ_MMU_DEBUG_REG_VALUE(int reg_no)
{
	return GUEST_GET_MMU_DEBUG_REG(reg_no);
}
static inline void
KVM_WRITE_MMU_DEBUG_REG_VALUE(int reg_no, mmu_reg_t value)
{
	GUEST_SET_MMU_DEBUG_REG(reg_no, value);
}
static inline mmu_reg_t
KVM_READ_DDBAR0_REG_VALUE(void)
{
	return KVM_READ_MMU_DEBUG_REG_VALUE(MMU_DDBAR0_REG_NO);
}
static inline mmu_reg_t
KVM_READ_DDBAR1_REG_VALUE(void)
{
	return KVM_READ_MMU_DEBUG_REG_VALUE(MMU_DDBAR1_REG_NO);
}
static inline mmu_reg_t
KVM_READ_DDBAR2_REG_VALUE(void)
{
	return KVM_READ_MMU_DEBUG_REG_VALUE(MMU_DDBAR2_REG_NO);
}
static inline mmu_reg_t
KVM_READ_DDBAR3_REG_VALUE(void)
{
	return KVM_READ_MMU_DEBUG_REG_VALUE(MMU_DDBAR3_REG_NO);
}
static inline mmu_reg_t
KVM_READ_DDBCR_REG_VALUE(void)
{
	return KVM_READ_MMU_DEBUG_REG_VALUE(MMU_DDBCR_REG_NO);
}
static inline mmu_reg_t
KVM_READ_DDBSR_REG_VALUE(void)
{
	return KVM_READ_MMU_DEBUG_REG_VALUE(MMU_DDBSR_REG_NO);
}
static inline mmu_reg_t
KVM_READ_DDMAR0_REG_VALUE(void)
{
	return KVM_READ_MMU_DEBUG_REG_VALUE(MMU_DDMAR0_REG_NO);
}
static inline mmu_reg_t
KVM_READ_DDMAR1_REG_VALUE(void)
{
	return KVM_READ_MMU_DEBUG_REG_VALUE(MMU_DDMAR1_REG_NO);
}
static inline mmu_reg_t
KVM_READ_DDMCR_REG_VALUE(void)
{
	return KVM_READ_MMU_DEBUG_REG_VALUE(MMU_DDMCR_REG_NO);
}
static inline void
KVM_WRITE_DDBAR0_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDBAR0_REG_NO, value);
}
static inline void
KVM_WRITE_DDBAR1_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDBAR1_REG_NO, value);
}
static inline void
KVM_WRITE_DDBAR2_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDBAR2_REG_NO, value);
}
static inline void
KVM_WRITE_DDBAR3_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDBAR3_REG_NO, value);
}
static inline void
KVM_WRITE_DDBCR_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDBCR_REG_NO, value);
}
static inline void
KVM_WRITE_DDBSR_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDBSR_REG_NO, value);
}
static inline void
KVM_WRITE_DDMAR0_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDMAR0_REG_NO, value);
}
static inline void
KVM_WRITE_DDMAR1_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDMAR1_REG_NO, value);
}
static inline void
KVM_WRITE_DDMCR_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_MMU_DEBUG_REG_VALUE(MMU_DDMCR_REG_NO, value);
}

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* It is pure kvm kernel without paravirtualization based on pv_ops */

static inline void WRITE_MMU_REG(mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	KVM_WRITE_MMU_REG(mmu_addr, mmu_reg);
}

static inline mmu_reg_t READ_MMU_REG(mmu_addr_t mmu_addr)
{
	return (mmu_reg_t)KVM_READ_MMU_REG(mmu_addr);
}

#define	BOOT_WRITE_MMU_REG(addr_val, reg_val)	\
		BOOT_KVM_WRITE_MMU_REG(addr_val, reg_val)
#define	BOOT_READ_MMU_REG(addr_val)		\
		BOOT_KVM_READ_MMU_REG(addr_val)

static inline void WRITE_MMU_OS_PPTB(mmu_reg_t reg_val)
{
	KVM_WRITE_MMU_OS_PPTB_REG(reg_val);
}
static inline unsigned long READ_MMU_OS_PPTB(void)
{
	return KVM_READ_MMU_OS_PPTB_REG();
}
static inline void WRITE_MMU_OS_VPTB(mmu_reg_t reg_val)
{
	KVM_WRITE_MMU_OS_VPTB_REG(reg_val);
}
static inline unsigned long READ_MMU_OS_VPTB(void)
{
	return KVM_READ_MMU_OS_VPTB_REG();
}
static inline void WRITE_MMU_OS_VAB(mmu_reg_t reg_val)
{
	KVM_WRITE_MMU_OS_VAB_REG(reg_val);
}
static inline unsigned long READ_MMU_OS_VAB(void)
{
	return KVM_READ_MMU_OS_VAB_REG();
}
static inline void WRITE_MMU_PID(mmu_reg_t reg_val)
{
	KVM_WRITE_MMU_PID_REG(reg_val);
}
static inline unsigned long READ_MMU_PID(void)
{
	return KVM_READ_MMU_PID_REG();
}

static inline void BOOT_WRITE_MMU_OS_PPTB(mmu_reg_t reg_val)
{
	BOOT_KVM_WRITE_MMU_OS_PPTB_REG(reg_val);
}
static inline unsigned long BOOT_READ_MMU_OS_PPTB(void)
{
	return BOOT_KVM_READ_MMU_OS_PPTB_REG();
}
static inline void BOOT_WRITE_MMU_OS_VPTB(mmu_reg_t reg_val)
{
	BOOT_KVM_WRITE_MMU_OS_VPTB_REG(reg_val);
}
static inline unsigned long BOOT_READ_MMU_OS_VPTB(void)
{
	return BOOT_KVM_READ_MMU_OS_VPTB_REG();
}
static inline void BOOT_WRITE_MMU_OS_VAB(mmu_reg_t reg_val)
{
	BOOT_KVM_WRITE_MMU_OS_VAB_REG(reg_val);
}
static inline unsigned long BOOT_READ_MMU_OS_VAB(void)
{
	return BOOT_KVM_READ_MMU_OS_VAB_REG();
}
static inline void BOOT_WRITE_MMU_PID(mmu_reg_t reg_val)
{
	BOOT_KVM_WRITE_MMU_PID_REG(reg_val);
}
static inline unsigned long BOOT_READ_MMU_PID(void)
{
	return BOOT_KVM_READ_MMU_PID_REG();
}

/*
 * Write/read Data TLB register
 */

static inline void WRITE_DTLB_REG(tlb_addr_t tlb_addr, mmu_reg_t mmu_reg)
{
	KVM_WRITE_DTLB_REG(tlb_addr, mmu_reg);
}

static inline mmu_reg_t READ_DTLB_REG(tlb_addr_t tlb_addr)
{
	return KVM_READ_DTLB_REG(tlb_addr);
}

/*
 * Flush TLB page/entry
 */

static inline void
FLUSH_TLB_ENTRY(flush_op_t flush_op, flush_addr_t flush_addr)
{
	KVM_FLUSH_TLB_ENTRY(flush_op, flush_addr);
}

/*
 * Flush DCACHE line
 */

static inline void FLUSH_DCACHE_LINE(e2k_addr_t virt_addr)
{
	KVM_FLUSH_DCACHE_LINE(virt_addr);
}
static inline void FLUSH_DCACHE_LINE_OFFSET(e2k_addr_t virt_addr, size_t offset)
{
	KVM_FLUSH_DCACHE_LINE(virt_addr + offset);
}

/*
 * Read DCACHE L1 fault_reg register
 */
static inline u64
READ_L1_FAULT_REG(void)
{
	return KVM_READ_L1_FAULT_REG();
}

/*
 * Clear DCACHE L1 set
 */
static inline void
CLEAR_DCACHE_L1_SET(e2k_addr_t virt_addr, unsigned long set)
{
	KVM_CLEAR_DCACHE_L1_SET(virt_addr, set);
}

/*
 * Write/read DCACHE L2 registers
 */
static inline void
WRITE_L2_REG(unsigned long reg_val, int reg_num, int bank_num)
{
	KVM_WRITE_DCACHE_L2_REG(reg_val, reg_num, bank_num);
}
static inline unsigned long
READ_L2_REG(int reg_num, int bank_num)
{
	return KVM_READ_DCACHE_L2_REG(reg_num, bank_num);
}

/*
 * Flush ICACHE line
 */

static inline void
FLUSH_ICACHE_LINE(flush_op_t flush_op, flush_addr_t flush_addr)
{
	KVM_FLUSH_ICACHE_LINE(flush_op, flush_addr);
}

/*
 * Flush and invalidate or write back CACHE(s) (invalidate all caches
 * of the processor)
 */

static inline void
FLUSH_CACHE_L12(flush_op_t flush_op)
{
	KVM_FLUSH_CACHE_L12(flush_op);
}

/*
 * Flush TLB (invalidate all TLBs of the processor)
 */

static inline void
FLUSH_TLB_ALL(flush_op_t flush_op)
{
	KVM_FLUSH_TLB_ALL(flush_op);
}

/*
 * Flush ICACHE (invalidate instruction caches of the processor)
 */

static inline void
FLUSH_ICACHE_ALL(flush_op_t flush_op)
{
	KVM_FLUSH_ICACHE_ALL(flush_op);
}

/*
 * Get Entry probe for virtual address
 */

static inline probe_entry_t
ENTRY_PROBE_MMU_OP(e2k_addr_t virt_addr)
{
	return KVM_ENTRY_PROBE_MMU_OP(virt_addr);
}

/*
 * Get physical address for virtual address
 */

static inline probe_entry_t
ADDRESS_PROBE_MMU_OP(e2k_addr_t virt_addr)
{
	return KVM_ADDRESS_PROBE_MMU_OP(virt_addr);
}

/*
 * Read CLW register
 */

static inline clw_reg_t
READ_CLW_REG(clw_addr_t clw_addr)
{
	return KVM_READ_CLW_REG(clw_addr);
}

/*
 * Write CLW register
 */

static inline void
WRITE_CLW_REG(clw_addr_t clw_addr, clw_reg_t val)
{
	KVM_WRITE_CLW_REG(clw_addr, val);
}

/*
 * KVM MMU DEBUG registers access
 */
static inline mmu_reg_t
READ_DDBAR0_REG_VALUE(void)
{
	return KVM_READ_DDBAR0_REG_VALUE();
}
static inline mmu_reg_t
READ_DDBAR1_REG_VALUE(void)
{
	return KVM_READ_DDBAR1_REG_VALUE();
}
static inline mmu_reg_t
READ_DDBAR2_REG_VALUE(void)
{
	return KVM_READ_DDBAR2_REG_VALUE();
}
static inline mmu_reg_t
READ_DDBAR3_REG_VALUE(void)
{
	return KVM_READ_DDBAR3_REG_VALUE();
}
static inline mmu_reg_t
READ_DDBCR_REG_VALUE(void)
{
	return KVM_READ_DDBCR_REG_VALUE();
}
static inline mmu_reg_t
READ_DDBSR_REG_VALUE(void)
{
	return KVM_READ_DDBSR_REG_VALUE();
}
static inline mmu_reg_t
READ_DDMAR0_REG_VALUE(void)
{
	return KVM_READ_DDMAR0_REG_VALUE();
}
static inline mmu_reg_t
READ_DDMAR1_REG_VALUE(void)
{
	return KVM_READ_DDMAR1_REG_VALUE();
}
static inline mmu_reg_t
READ_DDMCR_REG_VALUE(void)
{
	return KVM_READ_DDMCR_REG_VALUE();
}
static inline void
WRITE_DDBAR0_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_DDBAR0_REG_VALUE(value);
}
static inline void
WRITE_DDBAR1_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_DDBAR1_REG_VALUE(value);
}
static inline void
WRITE_DDBAR2_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_DDBAR2_REG_VALUE(value);
}
static inline void
WRITE_DDBAR3_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_DDBAR3_REG_VALUE(value);
}
static inline void
WRITE_DDBCR_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_DDBCR_REG_VALUE(value);
}
static inline void
WRITE_DDBSR_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_DDBSR_REG_VALUE(value);
}
static inline void
WRITE_DDMAR0_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_DDMAR0_REG_VALUE(value);
}
static inline void
WRITE_DDMAR1_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_DDMAR1_REG_VALUE(value);
}
static inline void
WRITE_DDMCR_REG_VALUE(mmu_reg_t value)
{
	KVM_WRITE_DDMCR_REG_VALUE(value);
}

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#endif /* ! __ASSEMBLY__ */

#endif	/* _E2K_KVM_MMU_REGS_ACCESS_H_ */
