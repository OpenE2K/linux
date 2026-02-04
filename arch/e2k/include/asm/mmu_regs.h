/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * MMU structures & registers.
 */

#ifndef	_E2K_MMU_REGS_H_
#define	_E2K_MMU_REGS_H_

#ifndef __ASSEMBLY__
#include <linux/linkage.h>
#include <linux/types.h>
#endif /* __ASSEMBLY__ */

#include <asm/p2v/boot_head.h>
#include <asm/debug_print.h>
#include <asm/system.h>
#include <asm/mmu_regs_types.h>
#include <asm/mmu_regs_access.h>


/*
 * MMU registers operations
 */

#ifndef __ASSEMBLY__
/*
 * Write MMU register
 */
static	inline	void
write_MMU_reg(mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	WRITE_MMU_REG(mmu_addr_val(mmu_addr), mmu_reg_val(mmu_reg));
}

/*
 * Read MMU register
 */

static	inline	mmu_reg_t
read_MMU_reg(mmu_addr_t mmu_addr)
{
	return __mmu_reg(READ_MMU_REG(mmu_addr_val(mmu_addr)));
}

/*
 * Read MMU Control register
 */
static inline e2k_mmu_cr_t get_MMU_CR(void)
{
	e2k_mmu_cr_t mmu_cr = {
		.word = READ_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR_NO))
	};
	return mmu_cr;
}

/*
 * Write MMU Control register
 */
static inline void set_MMU_CR(e2k_mmu_cr_t mmu_cr)
{
	NATIVE_SET_MMUREG(mmu_cr, AW(mmu_cr));
}

/*
 * Write MMU Context register
 */
#define	write_MMU_CONT(mmu_cont) \
			WRITE_MMU_PID(mmu_cont)
#define	WRITE_MMU_CONT(mmu_cont)	\
		WRITE_MMU_PID(mmu_reg_val(mmu_cont))
#define	BOOT_WRITE_MMU_CONT(mmu_cont)	\
		BOOT_WRITE_MMU_PID(mmu_reg_val(mmu_cont))

/*
 * MMU root page table physical base register
 */
#define	READ_MMU_U_PPTB()		NATIVE_GET_MMUREG(root_ptb)


/*
 * Read MMU Trap Counter register
 */
#define	NATIVE_READ_MMU_TRAP_COUNT()	\
		((unsigned int)(NATIVE_READ_MMU_REG(			\
					_MMU_REG_NO_TO_MMU_ADDR_VAL(	\
						_MMU_TRAP_COUNT_NO))))
#define	READ_MMU_TRAP_COUNT()	\
		((unsigned int)(READ_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL( \
						_MMU_TRAP_COUNT_NO))))
static inline	unsigned int
native_read_MMU_TRAP_COUNT(void)
{
	return NATIVE_READ_MMU_TRAP_COUNT();
}
static inline	unsigned int
read_MMU_TRAP_COUNT(void)
{
	return READ_MMU_TRAP_COUNT();
}

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
static inline	void
set_MMU_MPT_B(unsigned long base)
{
	WRITE_MMU_MPT_B(base);
}

/*
 * Set MMU PCI Low Bound register
 */
#define	write_MMU_PCI_L_B(bound)	\
		write_MMU_reg(MMU_ADDR_PCI_L_B, bound)
#define	WRITE_MMU_PCI_L_B(bound)	\
		WRITE_MMU_REG( \
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_PCI_L_B_NO), \
			mmu_reg_val(bound))
static inline	void
set_MMU_PCI_L_B(unsigned long bound)
{
	WRITE_MMU_PCI_L_B(bound);
}

/*
 * Set MMU Phys High Bound register
 */
#define	write_MMU_PH_H_B(bound)	\
		write_MMU_reg(MMU_ADDR_PH_H_B, bound)
#define	WRITE_MMU_PH_H_B(bound)	\
		WRITE_MMU_REG( \
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_PH_H_B_NO), \
			mmu_reg_val(bound))
static inline	void
set_MMU_PH_H_B(unsigned long bound)
{
	WRITE_MMU_PH_H_B(bound);
}

/*
 * Write User Stack Clean Window Disable register
 */
#define	set_MMU_US_CL_D(val) \
		write_MMU_reg(MMU_ADDR_US_CL_D, val)
#define	WRITE_MMU_US_CL_D(val)	\
		WRITE_MMU_REG( \
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_US_CL_D_NO), \
			mmu_reg_val(val))
static inline	void
write_MMU_US_CL_D(unsigned int disable_flag)
{
	WRITE_MMU_US_CL_D(disable_flag);
}

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

static inline	void
set_MMU_MTRR_REG(unsigned long no, long long value)
{
	WRITE_MTRR_REG(no, value);
}

/*
 * Get Memory Type Range Registers ( MTRRS )
 */
#define	get_MMU_MTRR_REG(no)	\
		(unsigned long)READ_MMU_REG(MMU_ADDR_MTRR(no))

static inline	unsigned int
read_MMU_US_CL_D(void)
{
	return (unsigned int)READ_MMU_US_CL_D();
}


/*
 * Flush TLB page
 */
static inline void
____flush_TLB_page(flush_op_t flush_op, flush_addr_t flush_addr)
{
	FLUSH_TLB_ENTRY(flush_op, flush_addr);
	if (cpu_has(CPU_HWBUG_TLB_FLUSH_L1D))
		__E2K_WAIT(_fl_c);
}

#define flush_TLB_page_begin()	do { } while (0)
#define flush_TLB_page_end()	__E2K_WAIT(_fl_c)

static inline void __flush_TLB_page_tlu_cache(unsigned long virt_addr,
		unsigned long context, u64 type)
{
	u64 va_tag = (virt_addr >> (9 * type + 12));
	____flush_TLB_page(FLUSH_TLB_PAGE_TLU_CACHE_OP,
			(va_tag << 21) | (context << 50) | type);
}


static inline void
__flush_TLB_page(e2k_addr_t virt_addr, unsigned long context)
{
	____flush_TLB_page(FLUSH_TLB_PAGE_OP, flush_addr_make_sys(virt_addr, context));
}

static inline void
flush_TLB_page(e2k_addr_t virt_addr, unsigned long context)
{
	flush_TLB_page_begin();
	__flush_TLB_page(virt_addr, context);
	flush_TLB_page_end();
}

static inline void
__flush_TLB_kernel_page(e2k_addr_t virt_addr)
{
	__flush_TLB_page(virt_addr, E2K_KERNEL_CONTEXT);
}

static inline	void
flush_TLB_kernel_page(e2k_addr_t virt_addr)
{
	flush_TLB_page_begin();
	__flush_TLB_kernel_page(virt_addr);
	flush_TLB_page_end();
}

static inline void
__flush_TLB_ss_page(e2k_addr_t virt_addr, unsigned long context)
{
	____flush_TLB_page(FLUSH_TLB_PAGE_OP, flush_addr_make_ss(virt_addr, context));
}

static inline	void
flush_TLB_ss_page(e2k_addr_t virt_addr, unsigned long context)
{
	flush_TLB_page_begin();
	__flush_TLB_ss_page(virt_addr, context);
	flush_TLB_page_end();
}

/*
 * Flush DCACHE line
 */
#define flush_DCACHE_line_begin() \
do { \
	E2K_WAIT_ST; \
} while (0)

#define flush_DCACHE_line_end(code_modified) \
do { \
	if (code_modified) { \
		E2K_WAIT(_fl_c); \
		if (!cpu_has(CPU_FEAT_ISET_V7)) { \
			asm volatile ("{disp %%ctpr1, 0f} {ct %%ctpr1} 0:" ::: "ctpr1", "memory"); \
		} \
	} else { \
		E2K_WAIT(_fl_c | _fl_c_mode); \
	} \
} while (0)

static inline void __flush_DCACHE_line(e2k_addr_t virt_addr)
{
	FLUSH_DCACHE_LINE(virt_addr);
}
static inline void __flush_DCACHE_line_offset(e2k_addr_t virt_addr, size_t offset)
{
	FLUSH_DCACHE_LINE_OFFSET(virt_addr, offset);
}
static inline	void
flush_DCACHE_line(e2k_addr_t virt_addr)
{
	flush_DCACHE_line_begin();
	__flush_DCACHE_line(virt_addr);
	flush_DCACHE_line_end(false);
}

/*
 * Clear DCACHE L1 set
 */
static inline void
clear_DCACHE_L1_set(e2k_addr_t virt_addr, unsigned long set)
{
	E2K_WAIT_ALL;
	CLEAR_DCACHE_L1_SET(virt_addr, set);
	E2K_WAIT_ST;
}

/*
 * Clear DCACHE L1 line
 */
static inline void
clear_DCACHE_L1_line(e2k_addr_t virt_addr)
{
	unsigned long set;
	for (set = 0; set < E2K_DCACHE_L1_SETS_NUM; set++)
		clear_DCACHE_L1_set(virt_addr, set);
}
/*
 * Write DCACHE L2 registers
 */
static inline void
native_write_DCACHE_L2_reg(unsigned long reg_val, int reg_num, int bank_num)
{
	__E2K_WAIT_ALL;
	NATIVE_WRITE_L2_REG(reg_val, reg_num, bank_num);
	__E2K_WAIT_ALL;
}
static inline void
native_write_DCACHE_L2_CNTR_reg(unsigned long reg_val, int bank_num)
{
	native_write_DCACHE_L2_reg(reg_val, _E2K_DCACHE_L2_CTRL_REG, bank_num);
}
static inline void
write_DCACHE_L2_reg(unsigned long reg_val, int reg_num, int bank_num)
{
	WRITE_L2_REG(reg_val, reg_num, bank_num);
}
static inline void
write_DCACHE_L2_CNTR_reg(unsigned long reg_val, int bank_num)
{
	write_DCACHE_L2_reg(reg_val, _E2K_DCACHE_L2_CTRL_REG, bank_num);
}

static inline void
write_DCACHE_L2_ERR_reg(int bank_num, u64 val)
{
	write_DCACHE_L2_reg(val, _E2K_DCACHE_L2_ERR_REG, bank_num);
}


static inline void
clear_DCACHE_L2_CNT_ERR1_reg(int bank_num)
{
	write_DCACHE_L2_reg(0, _E2K_DCACHE_L2_CNT_ERR1_REG, bank_num);
}
static inline void
clear_DCACHE_L2_CNT_ERR2_reg(int bank_num)
{
	write_DCACHE_L2_reg(0, _E2K_DCACHE_L2_CNT_ERR2_REG, bank_num);
}

/*
 * Read DCACHE L2 registers
 */
static inline unsigned long
native_read_DCACHE_L2_reg(int reg_num, int bank_num)
{
	return NATIVE_READ_L2_REG(reg_num, bank_num);
}
static inline unsigned long
native_read_DCACHE_L2_CNTR_reg(int bank_num)
{
	return native_read_DCACHE_L2_reg(_E2K_DCACHE_L2_CTRL_REG, bank_num);
}
static inline unsigned long
native_read_DCACHE_L2_ERR_reg(int bank_num)
{
	return native_read_DCACHE_L2_reg(_E2K_DCACHE_L2_ERR_REG, bank_num);
}
static inline unsigned long
read_DCACHE_L2_reg(int reg_num, int bank_num)
{
	return READ_L2_REG(reg_num, bank_num);
}
static inline unsigned long
read_DCACHE_L2_CNTR_reg(int bank_num)
{
	return read_DCACHE_L2_reg(_E2K_DCACHE_L2_CTRL_REG, bank_num);
}
static inline unsigned long
read_DCACHE_L2_ERR_reg(int bank_num)
{
	return read_DCACHE_L2_reg(_E2K_DCACHE_L2_ERR_REG, bank_num);
}


static inline unsigned long
read_DCACHE_L2_CNT_ERR1_reg(int bank_num)
{
	return read_DCACHE_L2_reg(_E2K_DCACHE_L2_CNT_ERR1_REG, bank_num);
}
static inline unsigned long
read_DCACHE_L2_CNT_ERR2_reg(int bank_num)
{
	return read_DCACHE_L2_reg(_E2K_DCACHE_L2_CNT_ERR2_REG, bank_num);
}

/*
 * Flush ICACHE line
 */
static inline	void
__flush_ICACHE_line(flush_op_t flush_op, flush_addr_t flush_addr)
{
	FLUSH_ICACHE_LINE(flush_op, flush_addr);
}

#define flush_ICACHE_line_begin()
#define flush_ICACHE_line_end() \
do { \
	E2K_WAIT_FLUSH; \
} while (0)

static inline void
__flush_ICACHE_line_user(e2k_addr_t virt_addr)
{
	__flush_ICACHE_line(FLUSH_ICACHE_LINE_USER_OP, flush_addr_make_user(virt_addr));
}

static inline	void
flush_ICACHE_line_user(e2k_addr_t virt_addr)
{
	flush_ICACHE_line_begin();
	__flush_ICACHE_line_user(virt_addr);
	flush_ICACHE_line_end();
}

static inline void
__flush_ICACHE_line_sys(e2k_addr_t virt_addr, unsigned long context)
{
	__flush_ICACHE_line(FLUSH_ICACHE_LINE_SYS_OP, flush_addr_make_sys(virt_addr, context));
}

static	inline	void
flush_ICACHE_line_sys(e2k_addr_t virt_addr, unsigned long context)
{
	flush_ICACHE_line_begin();
	__flush_ICACHE_line_sys(virt_addr, context);
	flush_ICACHE_line_end();
}

static	inline	void
flush_ICACHE_kernel_line(e2k_addr_t virt_addr)
{
	flush_ICACHE_line_sys(virt_addr, E2K_KERNEL_CONTEXT);
}

/*
 * Flush and write back CACHE(s) (write back and invalidate all caches
 * of the processor)
 * Flush cache is the same as write back
 */

static inline void
native_raw_write_back_CACHE_L12(void)
{
	__E2K_WAIT(_ma_c);
	NATIVE_FLUSH_CACHE_L12(flush_op_write_back_cache_L12);
	__E2K_WAIT(_fl_c | _ma_c);
}

static inline void
write_back_CACHE_L12(void)
{
	FLUSH_CACHE_L12(flush_op_write_back_cache_L12);
}

/*
 * Flush TLB (invalidate all TLBs of the processor)
 */

static inline void
native_raw_flush_TLB_all(void)
{
	__E2K_WAIT(_st_c);
	NATIVE_FLUSH_TLB_ALL(flush_op_tlb_all);
	__E2K_WAIT(_fl_c | _ma_c);
}

static inline void
flush_TLB_all(void)
{
	FLUSH_TLB_ALL(flush_op_tlb_all);
}

/*
 * Flush ICACHE (invalidate instruction caches of the processor)
 */
static inline void
flush_ICACHE_all(void)
{
	FLUSH_ICACHE_ALL(flush_op_icache_all);
}

/*
 * Read CLW register
 */

static	inline	clw_reg_t
read_CLW_reg(clw_addr_t clw_addr)
{
	return READ_CLW_REG(clw_addr);
}

static	inline	clw_reg_t
native_read_CLW_reg(clw_addr_t clw_addr)
{
	return NATIVE_READ_CLW_REG(clw_addr);
}

/*
 * Write CLW register
 */

static	inline	void
write_CLW_reg(clw_addr_t clw_addr, clw_reg_t val)
{
	WRITE_CLW_REG(clw_addr, val);
}

#endif /* ! __ASSEMBLY__ */

#endif  /* _E2K_MMU_REGS_H_ */
