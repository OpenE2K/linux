/*
 * asm-e2k/mmu_regs_access.h: E2K MMU structures & registers.
 *
 * Copyright 2014 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_MMU_REGS_ACCESS_H_
#define	_E2K_MMU_REGS_ACCESS_H_

#ifndef __ASSEMBLY__
#include <linux/types.h>
#include <asm/e2k_api.h>
#endif /* __ASSEMBLY__ */

#include <asm/mmu_regs_types.h>
#include <asm/mas.h>

#include <asm/native_mmu_regs_access.h>

extern unsigned long native_read_MMU_OS_PPTB_reg_value(void);
extern void native_write_MMU_OS_PPTB_reg_value(unsigned long value);
extern unsigned long native_read_MMU_OS_VPTB_reg_value(void);
extern void native_write_MMU_OS_VPTB_reg_value(unsigned long value);
extern unsigned long native_read_MMU_OS_VAB_reg_value(void);
extern void native_write_MMU_OS_VAB_reg_value(unsigned long value);

extern unsigned long boot_native_read_MMU_OS_PPTB_reg_value(void);
extern void boot_native_write_MMU_OS_PPTB_reg_value(unsigned long value);
extern unsigned long boot_native_read_MMU_OS_VPTB_reg_value(void);
extern void boot_native_write_MMU_OS_VPTB_reg_value(unsigned long value);
extern unsigned long boot_native_read_MMU_OS_VAB_reg_value(void);
extern void boot_native_write_MMU_OS_VAB_reg_value(unsigned long value);

#define	NATIVE_WRITE_MMU_OS_PPTB_REG(reg_val)				\
		native_write_MMU_OS_PPTB_reg_value(reg_val)
#define	NATIVE_READ_MMU_OS_PPTB_REG()					\
		native_read_MMU_OS_PPTB_reg_value()
#define	NATIVE_WRITE_MMU_OS_VPTB_REG(reg_val)				\
		native_write_MMU_OS_VPTB_reg_value(reg_val)
#define	NATIVE_READ_MMU_OS_VPTB_REG()					\
		native_read_MMU_OS_VPTB_reg_value()
#define	NATIVE_WRITE_MMU_OS_VAB_REG(reg_val)				\
		native_write_MMU_OS_VAB_reg_value(reg_val)
#define	NATIVE_READ_MMU_OS_VAB_REG()					\
		native_read_MMU_OS_VAB_reg_value()
#define	NATIVE_READ_MMU_PID_REG()					\
		NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_PID_NO))
#define	NATIVE_WRITE_MMU_PID_REG(reg_val)				\
		NATIVE_WRITE_MMU_REG( \
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_PID_NO),	\
			mmu_reg_val(reg_val))
#define	NATIVE_READ_MMU_U_PPTB_REG()					\
		NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_U_PPTB_NO))
#define	NATIVE_WRITE_MMU_U_PPTB_REG(reg_val)				\
		NATIVE_WRITE_MMU_REG( \
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_U_PPTB_NO),	\
			mmu_reg_val(reg_val))
#define	NATIVE_READ_MMU_U_VPTB_REG()					\
		NATIVE_READ_MMU_REG(	\
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_U_VPTB_NO))
#define	NATIVE_WRITE_MMU_U_VPTB_REG(reg_val)				\
		NATIVE_WRITE_MMU_REG( \
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_U_VPTB_NO),	\
			mmu_reg_val(reg_val))

#define	BOOT_NATIVE_WRITE_MMU_OS_PPTB_REG(reg_val)			\
		boot_native_write_MMU_OS_PPTB_reg_value(reg_val)
#define	BOOT_NATIVE_READ_MMU_OS_PPTB_REG()				\
		boot_native_read_MMU_OS_PPTB_reg_value()
#define	BOOT_NATIVE_WRITE_MMU_OS_VPTB_REG(reg_val)			\
		boot_native_write_MMU_OS_VPTB_reg_value(reg_val)
#define	BOOT_NATIVE_READ_MMU_OS_VPTB_REG()				\
		boot_native_read_MMU_OS_VPTB_reg_value()
#define	BOOT_NATIVE_WRITE_MMU_OS_VAB_REG(reg_val)			\
		boot_native_write_MMU_OS_VAB_reg_value(reg_val)
#define	BOOT_NATIVE_READ_MMU_OS_VAB_REG()				\
		boot_native_read_MMU_OS_VAB_reg_value()
#define	BOOT_NATIVE_WRITE_MMU_PID_REG(reg_val)				\
		NATIVE_WRITE_MMU_PID_REG(reg_val)
#define	BOOT_NATIVE_READ_MMU_PID_REG()					\
		NATIVE_READ_MMU_PID_REG()

#ifdef	CONFIG_KVM_GUEST_KERNEL
/* it is native guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/mmu_regs_access.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/mmu_regs_access.h>
#else	/* ! CONFIG_KVM_GUEST_KERNEL && ! CONFIG_PARAVIRT_GUEST */
/* it is native kernel without any virtualization */
/* or host kernel with virtualization support */

/*
 * MMU registers operations
 */

#ifndef __ASSEMBLY__
/*
 * Write/read MMU register
 */
#define	WRITE_MMU_REG(addr_val, reg_val)				\
		NATIVE_WRITE_MMU_REG(addr_val, reg_val)
#define	READ_MMU_REG(addr_val)						\
		NATIVE_READ_MMU_REG(addr_val)

#define	BOOT_WRITE_MMU_REG(addr_val, reg_val)				\
		BOOT_NATIVE_WRITE_MMU_REG(addr_val, reg_val)
#define	BOOT_READ_MMU_REG(addr_val)					\
		BOOT_NATIVE_READ_MMU_REG(addr_val)

#define	WRITE_MMU_OS_PPTB(reg_val)					\
		NATIVE_WRITE_MMU_OS_PPTB_REG(reg_val)
#define	READ_MMU_OS_PPTB()						\
		NATIVE_READ_MMU_OS_PPTB_REG()
#define	WRITE_MMU_OS_VPTB(reg_val)					\
		NATIVE_WRITE_MMU_OS_VPTB_REG(reg_val)
#define	READ_MMU_OS_VPTB()						\
		NATIVE_READ_MMU_OS_VPTB_REG()
#define	WRITE_MMU_OS_VAB(reg_val)					\
		NATIVE_WRITE_MMU_OS_VAB_REG(reg_val)
#define	READ_MMU_OS_VAB()						\
		NATIVE_READ_MMU_OS_VAB_REG()
#define	WRITE_MMU_PID(reg_val)						\
		NATIVE_WRITE_MMU_PID_REG(reg_val)
#define	READ_MMU_PID()							\
		NATIVE_READ_MMU_PID_REG()

#define	BOOT_WRITE_MMU_OS_PPTB(reg_val)					\
		BOOT_NATIVE_WRITE_MMU_OS_PPTB_REG(reg_val)
#define	BOOT_READ_MMU_OS_PPTB()						\
		BOOT_NATIVE_READ_MMU_OS_PPTB_REG()
#define	BOOT_WRITE_MMU_OS_VPTB(reg_val)					\
		BOOT_NATIVE_WRITE_MMU_OS_VPTB_REG(reg_val)
#define	BOOT_READ_MMU_OS_VPTB()						\
		BOOT_NATIVE_READ_MMU_OS_VPTB_REG()
#define	BOOT_WRITE_MMU_OS_VAB(reg_val)					\
		BOOT_NATIVE_WRITE_MMU_OS_VAB_REG(reg_val)
#define	BOOT_READ_MMU_OS_VAB()						\
		BOOT_NATIVE_READ_MMU_OS_VAB_REG()
#define	BOOT_WRITE_MMU_PID(reg_val)					\
		BOOT_NATIVE_WRITE_MMU_PID_REG(reg_val)
#define	BOOT_READ_MMU_PID()						\
		BOOT_NATIVE_READ_MMU_PID_REG()

/*
 * Write/read Data TLB register
 */
#define	WRITE_DTLB_REG(tlb_addr, tlb_value)				\
		NATIVE_WRITE_DTLB_REG(tlb_addr, tlb_value)

#define	READ_DTLB_REG(tlb_addr)						\
		NATIVE_READ_DTLB_REG(tlb_addr)

/*
 * Flush TLB page/entry
 */
#define	FLUSH_TLB_ENTRY(flush_op, addr)					\
		NATIVE_FLUSH_TLB_ENTRY(flush_op, addr)

/*
 * Flush DCACHE line
 */
#define	FLUSH_DCACHE_LINE(virt_addr)					\
		NATIVE_FLUSH_DCACHE_LINE(virt_addr)
#define	FLUSH_DCACHE_LINE_OFFSET(virt_addr, offset) \
		NATIVE_FLUSH_DCACHE_LINE_OFFSET((virt_addr), (offset))

/*
 * Clear DCACHE L1 set
 */
#define	CLEAR_DCACHE_L1_SET(virt_addr, set)				\
		NATIVE_CLEAR_DCACHE_L1_SET(virt_addr, set)

/*
 * Write DCACHE L2 registers
 */
#define	WRITE_L2_REG(reg_val, reg_num, bank_num)			\
		NATIVE_WRITE_L2_REG(reg_val, reg_num, bank_num)

/*
 * Read DCACHE L2 registers
 */
#define	READ_L2_REG(reg_num, bank_num)					\
		NATIVE_READ_L2_REG(reg_num, bank_num)

/*
 * Flush ICACHE line
 */
#define	FLUSH_ICACHE_LINE(flush_op, addr)				\
		NATIVE_FLUSH_ICACHE_LINE(flush_op, addr)

/*
 * Flush and invalidate or write back L1/L2 CACHE(s)
 */
#define	FLUSH_CACHE_L12(flush_op)					\
		native_write_back_CACHE_L12()

/*
 * Flush TLB (invalidate all TLBs of the processor)
 */
#define	FLUSH_TLB_ALL(flush_op)						\
		native_flush_TLB_all()

/*
 * Flush ICACHE (invalidate instruction caches of the processor)
 */
#define	FLUSH_ICACHE_ALL(flush_op)					\
		native_flush_ICACHE_all()

/*
 * Get Entry probe for virtual address
 */
#define	ENTRY_PROBE_MMU_OP(addr_val)					\
		NATIVE_ENTRY_PROBE_MMU_OP(addr_val)

/*
 * Get physical address for virtual address
 */
#define	ADDRESS_PROBE_MMU_OP(addr_val)					\
		NATIVE_ADDRESS_PROBE_MMU_OP(addr_val)

/*
 * Read CLW register
 */
#define	READ_CLW_REG(clw_addr)						\
		NATIVE_READ_CLW_REG(clw_addr)

/*
 * Write CLW register
 */
#define	WRITE_CLW_REG(clw_addr, val)						\
		NATIVE_WRITE_CLW_REG(clw_addr, val)

/*
 * MMU DEBUG registers access
 */
#define	READ_DDBAR0_REG_VALUE()		NATIVE_READ_DDBAR0_REG_VALUE()
#define	READ_DDBAR1_REG_VALUE()		NATIVE_READ_DDBAR1_REG_VALUE()
#define	READ_DDBAR2_REG_VALUE()		NATIVE_READ_DDBAR2_REG_VALUE()
#define	READ_DDBAR3_REG_VALUE()		NATIVE_READ_DDBAR3_REG_VALUE()
#define	READ_DDBCR_REG_VALUE()		NATIVE_READ_DDBCR_REG_VALUE()
#define	READ_DDBSR_REG_VALUE()		NATIVE_READ_DDBSR_REG_VALUE()
#define	READ_DDMAR0_REG_VALUE()		NATIVE_READ_DDMAR0_REG_VALUE()
#define	READ_DDMAR1_REG_VALUE()		NATIVE_READ_DDMAR1_REG_VALUE()
#define	READ_DDMCR_REG_VALUE()		NATIVE_READ_DDMCR_REG_VALUE()
#define	WRITE_DDBAR0_REG_VALUE(value)	NATIVE_WRITE_DDBAR0_REG_VALUE(value)
#define	WRITE_DDBAR1_REG_VALUE(value)	NATIVE_WRITE_DDBAR1_REG_VALUE(value)
#define	WRITE_DDBAR2_REG_VALUE(value)	NATIVE_WRITE_DDBAR2_REG_VALUE(value)
#define	WRITE_DDBAR3_REG_VALUE(value)	NATIVE_WRITE_DDBAR3_REG_VALUE(value)
#define	WRITE_DDBCR_REG_VALUE(value)	NATIVE_WRITE_DDBCR_REG_VALUE(value)
#define	WRITE_DDBSR_REG_VALUE(value)	NATIVE_WRITE_DDBSR_REG_VALUE(value)
#define	WRITE_DDMAR0_REG_VALUE(value)	NATIVE_WRITE_DDMAR0_REG_VALUE(value)
#define	WRITE_DDMAR1_REG_VALUE(value)	NATIVE_WRITE_DDMAR1_REG_VALUE(value)
#define	WRITE_DDMCR_REG_VALUE(value)	NATIVE_WRITE_DDMCR_REG_VALUE(value)

#endif /* ! __ASSEMBLY__ */

#endif	/* CONFIG_KVM_GUEST_KERNEL */

#ifndef __ASSEMBLY__

#define	READ_DDBAR0_REG()	\
		READ_DDBAR0_REG_VALUE()
#define	READ_DDBAR1_REG()	\
		READ_DDBAR1_REG_VALUE()
#define	READ_DDBAR2_REG()	\
		READ_DDBAR2_REG_VALUE()
#define	READ_DDBAR3_REG()	\
		READ_DDBAR3_REG_VALUE()
#define	READ_DDBCR_REG()	\
({ \
	e2k_ddbcr_t ddbcr; \
 \
	ddbcr.DDBCR_reg = READ_DDBCR_REG_VALUE(); \
	ddbcr; \
})
#define	READ_DDBSR_REG()	\
({ \
	e2k_ddbsr_t ddbsr; \
 \
	ddbsr.DDBSR_reg = READ_DDBSR_REG_VALUE(); \
	ddbsr; \
})
#define	READ_DDMAR0_REG()	\
		READ_DDMAR0_REG_VALUE()
#define	READ_DDMAR1_REG()	\
		READ_DDMAR1_REG_VALUE()
#define	READ_DDMCR_REG()	\
({ \
	e2k_ddmcr_t ddmcr; \
 \
	ddmcr.DDMCR_reg = READ_DDMCR_REG_VALUE(); \
	ddmcr; \
})
#define	WRITE_DDBAR0_REG(value)	\
		WRITE_DDBAR0_REG_VALUE(value)
#define	WRITE_DDBAR1_REG(value)	\
		WRITE_DDBAR1_REG_VALUE(value)
#define	WRITE_DDBAR2_REG(value)	\
		WRITE_DDBAR2_REG_VALUE(value)
#define	WRITE_DDBAR3_REG(value)	\
		WRITE_DDBAR3_REG_VALUE(value)
#define	WRITE_DDBCR_REG(value)	\
		WRITE_DDBCR_REG_VALUE(value.DDBCR_reg)
#define	WRITE_DDBSR_REG(value)	\
		WRITE_DDBSR_REG_VALUE(value.DDBSR_reg)
#define	WRITE_DDMAR0_REG(value)	\
		WRITE_DDMAR0_REG_VALUE(value)
#define	WRITE_DDMAR1_REG(value)	\
		WRITE_DDMAR1_REG_VALUE(value)
#define	WRITE_DDMCR_REG(value)	\
		WRITE_DDMCR_REG_VALUE(value.DDMCR_reg)

#endif /* ! __ASSEMBLY__ */

#endif  /* _E2K_MMU_REGS_ACCESS_H_ */
