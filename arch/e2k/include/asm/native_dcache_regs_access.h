/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * native E2K MMU structures & registers.
 */

#ifndef	_E2K_NATIVE_DCACHE_REGS_ACCESS_H_
#define	_E2K_NATIVE_DCACHE_REGS_ACCESS_H_

#include <asm/e2k_api.h>
#include <asm/mas.h>
#include <asm/mmu_types.h>

/*
 * Flush DCACHE line
 */
static inline void NATIVE_FLUSH_DCACHE_LINE(unsigned long addr)
{
	ldst_rec_op_t opc = {
		.fmt = 4,
		.mas = MAS_CACHE_LINE_FLUSH,
		.prot = 1
	};

	NATIVE_RECOVERY_STORE(addr, 0x0, AW(opc), 2);
}

static inline void NATIVE_FLUSH_DCACHE_LINE_OFFSET(unsigned long addr, size_t offset)
{
	ldst_rec_op_t opc = {
		.fmt = 4,
		.mas = MAS_CACHE_LINE_FLUSH,
		.prot = 1
	};

	NATIVE_RECOVERY_STORE(addr, 0x0, AW(opc) | offset, 2);
}

/* This can be used in non-privileged mode (e.g. guest kernel) but
 * must not be used on user addresses (this does not have .prot = 1) */
#define NATIVE_FLUSH_DCACHE_LINE_UNPRIV(virt_addr) \
	NATIVE_WRITE_MAS_D((virt_addr), 0, MAS_CACHE_LINE_FLUSH)

/*
 * Read DCACHE L1 fault_reg register
 */
#define	NATIVE_READ_L1_FAULT_REG() \
	NATIVE_READ_MAS_D(mk_dcache_l1_addr(0, 0, 0, 1, 0), \
			  MAS_DCACHE_L1_REG)

#define NATIVE_WRITE_L1_FAULT_REG(val) \
	NATIVE_WRITE_MAS_D_CH(mk_dcache_l1_addr(0, 0, 0, 1, 0),\
			      (val), MAS_DCACHE_L1_REG, 2)

/*
 * Write DCACHE L2 registers
 */
#define	NATIVE_WRITE_L2_REG(value, reg, bank) \
do { \
	E2K_WAIT_MA; \
	NATIVE_WRITE_MAS_D(mk_dcache_l2_addr((reg), (bank)), (value), MAS_DCACHE_L2_REG); \
	E2K_WAIT_MA; \
} while (0)

/*
 * Read DCACHE L2 registers
 */
#define	NATIVE_READ_L2_REG(reg, bank) \
({ \
	E2K_WAIT_MA; \
	u64 value_rlg_ = NATIVE_READ_MAS_D(mk_dcache_l2_addr((reg), (bank)), MAS_DCACHE_L2_REG); \
	E2K_WAIT_MA; \
	value_rlg_; \
})

#endif  /* _E2K_NATIVE_MMU_REGS_ACCESS_H_ */
