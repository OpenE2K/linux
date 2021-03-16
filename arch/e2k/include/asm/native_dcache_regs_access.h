/*
 * native E2K MMU structures & registers.
 *
 * Copyright 2014 Salavat S. Guiliazov (atic@mcst.ru)
 */

#ifndef	_E2K_NATIVE_DCACHE_REGS_ACCESS_H_
#define	_E2K_NATIVE_DCACHE_REGS_ACCESS_H_

#ifndef __ASSEMBLY__
#include <asm/e2k_api.h>

#endif /* __ASSEMBLY__ */

#include <asm/mas.h>
#include <asm/mmu_types.h>

#ifndef __ASSEMBLY__

/*
 * Flush DCACHE line
 */
static inline void NATIVE_FLUSH_DCACHE_LINE(unsigned long addr)
{
	ldst_rec_op_t opc = {
		.fmt = 4,
		.mas = MAS_DCACHE_LINE_FLUSH,
		.prot = 1
	};

	NATIVE_RECOVERY_STORE(addr, 0x0, AW(opc), 2);
}

static inline void NATIVE_FLUSH_DCACHE_LINE_OFFSET(unsigned long addr, size_t offset)
{
	ldst_rec_op_t opc = {
		.fmt = 4,
		.mas = MAS_DCACHE_LINE_FLUSH,
		.prot = 1
	};

	NATIVE_RECOVERY_STORE(addr, 0x0, AW(opc) | offset, 2);
}

/* This can be used in non-privileged mode (e.g. guest kernel) but
 * must not be used on user addresses (this does not have .prot = 1) */
#define NATIVE_FLUSH_DCACHE_LINE_UNPRIV(virt_addr) \
	NATIVE_WRITE_MAS_D((virt_addr), 0, MAS_DCACHE_LINE_FLUSH)


/*
 * Clear DCACHE L1 set
 */
#define	NATIVE_CLEAR_DCACHE_L1_SET(virt_addr, set)			\
		NATIVE_WRITE_MAS_D(					\
			mk_dcache_l1_addr((virt_addr), set, 1, 0),	\
			0, MAS_DCACHE_L1_REG)

/*
 * Write DCACHE L2 registers
 */
#define	NATIVE_WRITE_L2_REG(reg_val, reg_num, bank_num)			\
		NATIVE_WRITE_MAS_D(					\
			mk_dcache_l2_reg_addr(reg_num, bank_num),	\
			(reg_val),					\
			MAS_DCACHE_L2_REG)

/*
 * Read DCACHE L2 registers
 */
#define	NATIVE_READ_L2_REG(reg_num, bank_num)				\
		NATIVE_READ_MAS_D(					\
			mk_dcache_l2_reg_addr(reg_num, bank_num),	\
			MAS_DCACHE_L2_REG)

#endif /* ! __ASSEMBLY__ */

#endif  /* _E2K_NATIVE_MMU_REGS_ACCESS_H_ */
