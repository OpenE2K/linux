/*
 * MMU structures & registers.
 *
 * Copyright 2001 Salavat S. Guiliazov (atic@mcst.ru)
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

#undef	DEBUG_MR_MODE
#undef	DebugMR
#define	DEBUG_MR_MODE		0	/* MMU registers access */
#define DebugMR(...)		DebugPrint(DEBUG_MR_MODE, ##__VA_ARGS__)

#undef	DEBUG_MCR_MODE
#undef	DebugMCR
#define	DEBUG_MCR_MODE		0	/* MMU CONTEXT registers access */
#define DebugMCR(...)		DebugPrint(DEBUG_MCR_MODE, ##__VA_ARGS__)

#undef	DEBUG_CLW_MODE
#undef	DebugCLW
#define	DEBUG_CLW_MODE		0	/* CLW registers access */
#define DebugCLW(...)		DebugPrint(DEBUG_CLW_MODE, ##__VA_ARGS__)

#undef	DEBUG_TLB_MODE
#undef	DebugTLB
#define	DEBUG_TLB_MODE		0	/* TLB registers access */
#define DebugTLB(...)		DebugPrint(DEBUG_TLB_MODE, ##__VA_ARGS__)

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
	DebugMR("Write MMU reg 0x%lx value 0x%llx\n",
		MMU_REG_NO_FROM_MMU_ADDR(mmu_addr), mmu_reg_val(mmu_reg));
	WRITE_MMU_REG(mmu_addr_val(mmu_addr), mmu_reg_val(mmu_reg));
}

static	inline	void
boot_write_MMU_reg(mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	BOOT_WRITE_MMU_REG(mmu_addr_val(mmu_addr), mmu_reg_val(mmu_reg));
}

/*
 * Read MMU register
 */

static	inline	mmu_reg_t
read_MMU_reg(mmu_addr_t mmu_addr)
{
	DebugMR("Read MMU reg 0x%lx\n",
		MMU_REG_NO_FROM_MMU_ADDR(mmu_addr));
	return __mmu_reg(READ_MMU_REG(mmu_addr_val(mmu_addr)));
}

static	inline	mmu_reg_t
boot_read_MMU_reg(mmu_addr_t mmu_addr)
{
	return __mmu_reg(BOOT_READ_MMU_REG(mmu_addr_val(mmu_addr)));
}

/*
 * Read MMU Control register
 */
#define	read_MMU_CR()	read_MMU_reg(MMU_ADDR_CR)
#define	READ_MMU_CR()	\
	READ_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR_NO))
static inline	unsigned long
get_MMU_CR(void)
{
	unsigned long mmu_cr;

	DebugMR("Get MMU Control Register\n");
	mmu_cr = READ_MMU_CR();
	DebugMR("MMU Control Register state : 0x%lx\n", mmu_cr);
	return mmu_cr;
}

/*
 * Write MMU Control register
 */
#define	write_MMU_CR(mmu_cr)	write_MMU_reg(MMU_ADDR_CR, mmu_cr)
#define	WRITE_MMU_CR(mmu_cr)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR_NO), \
			mmu_reg_val(mmu_cr))
static inline	void
set_MMU_CR(unsigned long mmu_cr)
{
	DebugMR("Set MMU Control Register to 0x%lx\n", mmu_cr);
	WRITE_MMU_CR(mmu_cr);
	DebugMR("Read MMU Control Register : 0x%llx\n",
		READ_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR_NO)));
}
#define	BOOT_WRITE_MMU_CR(mmu_cr)	\
		BOOT_WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR_NO), \
			mmu_reg_val(mmu_cr))
static inline	void
boot_set_MMU_CR(unsigned long mmu_cr)
{
	BOOT_WRITE_MMU_CR(mmu_cr);
}

/*
 * Write MMU Context register
 */
#define	write_MMU_CONT(mmu_cont) \
			WRITE_MMU_PID(mmu_cont)
#define	WRITE_MMU_CONT(mmu_cont)	\
		WRITE_MMU_PID(mmu_reg_val(mmu_cont))
static inline	void
set_MMU_CONT(unsigned long context)
{
	DebugMCR("Set MMU CONTEXT register to 0x%lx\n", context);
	WRITE_MMU_PID(context);
}
#define	BOOT_WRITE_MMU_CONT(mmu_cont)	\
		BOOT_WRITE_MMU_PID(mmu_reg_val(mmu_cont))
static inline	void
boot_set_MMU_CONT(unsigned long context)
{
	BOOT_WRITE_MMU_CONT(context);
}

/*
 * Write MMU Control Register of secondary space table
 */
#define	write_MMU_CR3_RG(mmu_page_dir) \
			write_MMU_reg(MMU_ADDR_CR3_RG, mmu_page_dir)
#define	WRITE_MMU_CR3_RG(mmu_page_dir)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR3_RG_NO), \
			mmu_reg_val(mmu_page_dir))
static inline	void
set_MMU_CR3_RG(unsigned long mmu_page_dir)
{
	DebugMR("Set MMU INTEL page table base register to 0x%lx\n",
		mmu_page_dir);
	WRITE_MMU_CR3_RG(mmu_page_dir);
}

#define	get_MMU_CR3_RG()	\
		(unsigned long)mmu_reg_val(read_MMU_reg(MMU_ADDR_CR3_RG))
/*
 * Write MMU page tables virtual base register
 */
#define	WRITE_MMU_U_VPTB(mmu_virt_ptb)	\
		WRITE_MMU_REG( \
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_U_VPTB_NO), \
			mmu_reg_val(mmu_virt_ptb))
static inline	void
set_MMU_U_VPTB(unsigned long mmu_virt_ptb)
{
	DebugMR("Set MMU page table virtual base register to 0x%lx\n",
		mmu_virt_ptb);
	WRITE_MMU_U_VPTB(mmu_virt_ptb);
}
#define	BOOT_WRITE_MMU_U_VPTB(mmu_virt_ptb)	\
		BOOT_WRITE_MMU_REG( \
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_U_VPTB_NO), \
			mmu_reg_val(mmu_virt_ptb))
static inline	void
boot_set_MMU_U_VPTB(unsigned long mmu_virt_ptb)
{
	BOOT_WRITE_MMU_U_VPTB(mmu_virt_ptb);
}

static inline	void
set_MMU_OS_VPTB(unsigned long mmu_virt_ptb)
{
	DebugMR("Set MMU OS page table virtual base register to 0x%lx\n",
		mmu_virt_ptb);
	WRITE_MMU_OS_VPTB(mmu_virt_ptb);
}
static inline	void
boot_set_MMU_OS_VPTB(unsigned long mmu_virt_ptb)
{
	BOOT_WRITE_MMU_OS_VPTB(mmu_virt_ptb);
}

/*
 * Write/read MMU root page table physical base register
 */
#define	WRITE_MMU_U_PPTB(mmu_phys_ptb)	\
		WRITE_MMU_REG( \
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_U_PPTB_NO), \
			mmu_reg_val(mmu_phys_ptb))
#define	READ_MMU_U_PPTB()	\
		READ_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_U_PPTB_NO))
static inline	void
set_MMU_U_PPTB(unsigned long mmu_phys_ptb)
{
	DebugMR("Set MMU USER page table physical base register to 0x%lx\n",
		mmu_phys_ptb);
	WRITE_MMU_U_PPTB(mmu_phys_ptb);
}
#define	BOOT_WRITE_MMU_U_PPTB(mmu_phys_ptb)	\
		BOOT_WRITE_MMU_REG( \
			_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_U_PPTB_NO), \
			mmu_reg_val(mmu_phys_ptb))
static inline	void
boot_set_MMU_U_PPTB(unsigned long mmu_phys_ptb)
{
	BOOT_WRITE_MMU_U_PPTB(mmu_phys_ptb);
}
static inline unsigned long
get_MMU_U_PPTB(void)
{
	return READ_MMU_U_PPTB();
}

static inline	void
set_MMU_OS_PPTB(unsigned long mmu_phys_ptb)
{
	DebugMR("Set MMU OS root page table physical base register to 0x%lx\n",
		mmu_phys_ptb);
	WRITE_MMU_OS_PPTB(mmu_phys_ptb);
}
static inline	void
boot_set_MMU_OS_PPTB(unsigned long mmu_phys_ptb)
{
	BOOT_WRITE_MMU_OS_PPTB(mmu_phys_ptb);
}

/*
 * Read MMU Trap Point register
 */
#define	read_MMU_TRAP_POINT()	read_MMU_reg(MMU_ADDR_TRAP_POINT)
#define	READ_MMU_TRAP_POINT()	\
		READ_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL( \
						_MMU_TRAP_POINT_NO))

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
static inline	void
set_MMU_TRAP_POINT(void *trap_cellar)
{
	DebugMR("Set MMU Trap Point register to %px\n", trap_cellar);
	WRITE_MMU_TRAP_POINT(trap_cellar);
}
#define	BOOT_WRITE_MMU_TRAP_POINT(trap_cellar)	\
		BOOT_WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL( \
						_MMU_TRAP_POINT_NO), \
			_MMU_TRAP_POINT((e2k_addr_t)trap_cellar))
static inline	void
boot_set_MMU_TRAP_POINT(void *trap_cellar)
{
	BOOT_WRITE_MMU_TRAP_POINT(trap_cellar);
}

/*
 * Set MMU Trap Counter register
 */
#define	NATIVE_WRITE_MMU_TRAP_COUNT(counter)	\
		NATIVE_WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL( \
						_MMU_TRAP_COUNT_NO), \
			(unsigned long)_MMU_TRAP_COUNT(counter))
#define	write_MMU_TRAP_COUNT(counter)	\
		write_MMU_reg(MMU_ADDR_TRAP_COUNT, \
			(unsigned long)_MMU_TRAP_COUNT(counter))
#define	WRITE_MMU_TRAP_COUNT(counter)	\
		WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL( \
						_MMU_TRAP_COUNT_NO), \
			(unsigned long)_MMU_TRAP_COUNT(counter))
#define	RESET_MMU_TRAP_COUNT()	WRITE_MMU_TRAP_COUNT(0)
static inline	void
set_MMU_TRAP_COUNT(unsigned int counter)
{
	DebugMR("Set MMU Trap Counter register to %d\n", counter);
	WRITE_MMU_TRAP_COUNT(counter);
}
static inline	void
reset_MMU_TRAP_COUNT(void)
{
	RESET_MMU_TRAP_COUNT();
}
#define	BOOT_WRITE_MMU_TRAP_COUNT(counter)	\
		BOOT_WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL( \
						_MMU_TRAP_COUNT_NO), \
			(unsigned long)_MMU_TRAP_COUNT(counter))
#define	BOOT_RESET_MMU_TRAP_COUNT()	BOOT_WRITE_MMU_TRAP_COUNT(0)
static inline	void
boot_reset_MMU_TRAP_COUNT(void)
{
	BOOT_RESET_MMU_TRAP_COUNT();
}

/*
 * Read MMU Trap Counter register
 */
#define	NATIVE_get_MMU_TRAP_COUNT()	\
		((unsigned int)mmu_reg_val(native_read_MMU_reg(	\
						MMU_ADDR_TRAP_COUNT)))
#define	NATIVE_READ_MMU_TRAP_COUNT()	\
		((unsigned int)(NATIVE_READ_MMU_REG(			\
					_MMU_REG_NO_TO_MMU_ADDR_VAL(	\
						_MMU_TRAP_COUNT_NO))))
#define	get_MMU_TRAP_COUNT()	\
		((unsigned int)mmu_reg_val(read_MMU_reg(MMU_ADDR_TRAP_COUNT)))
#define	READ_MMU_TRAP_COUNT()	\
		((unsigned int)(READ_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL( \
						_MMU_TRAP_COUNT_NO))))
static inline	unsigned int
native_read_MMU_TRAP_COUNT(void)
{
	DebugMR("Read MMU Trap Counter register\n");
	return NATIVE_READ_MMU_TRAP_COUNT();
}
static inline	unsigned int
read_MMU_TRAP_COUNT(void)
{
	DebugMR("Read MMU Trap Counter register\n");
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
	DebugMR("Set MMU Memory Protection Table Base register to 0x%lx\n",
		base);
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
	DebugMR("Set MMU PCI low bound register to 0x%lx\n", bound);
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
	DebugMR("Set MMU Physical memory high bound register to 0x%lx\n",
		bound);
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
	DebugCLW("Set MMU US CLW Disable register to %d\n", disable_flag);
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
	DebugCLW("Set MTRR#%ld register to ox%llx\n", no, value);
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
	DebugCLW("Read MMU US CLW Disable register\n");
	return (unsigned int)READ_MMU_US_CL_D();
}


/*
 * Flush TLB page
 */
static inline void
____flush_TLB_page(flush_op_t flush_op, flush_addr_t flush_addr)
{
	unsigned long flags;
	bool fl_c_needed = cpu_has(CPU_HWBUG_TLB_FLUSH_L1D);

	DebugTLB("Flush TLB page : op 0x%lx extended virtual addr 0x%lx\n",
		flush_op_val(flush_op), flush_addr_val(flush_addr));

	raw_all_irq_save(flags);
	FLUSH_TLB_ENTRY(flush_op_val(flush_op), flush_addr_val(flush_addr));
	if (fl_c_needed)
		__E2K_WAIT(_fl_c);
	raw_all_irq_restore(flags);
}

#define flush_TLB_page_begin()
#define flush_TLB_page_end() \
do { \
	__E2K_WAIT(_fl_c | _ma_c); \
} while (0)

static inline void
__flush_TLB_page(e2k_addr_t virt_addr, unsigned long context)
{
	____flush_TLB_page(flush_op_tlb_page_sys,
				flush_addr_make_sys(virt_addr, context));
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
	____flush_TLB_page(flush_op_tlb_page_sys,
				flush_addr_make_ss(virt_addr, context));
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

#define flush_DCACHE_line_end() \
do { \
	E2K_WAIT_FLUSH; \
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
	DebugMR("Flush DCACHE line : virtual addr 0x%lx\n", virt_addr);

	flush_DCACHE_line_begin();
	__flush_DCACHE_line(virt_addr);
	flush_DCACHE_line_end();
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
	NATIVE_WRITE_L2_REG(reg_val, reg_num, bank_num);
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

/*
 * Flush ICACHE line
 */
static inline	void
__flush_ICACHE_line(flush_op_t flush_op, flush_addr_t flush_addr)
{
	DebugMR("Flush ICACHE line : op 0x%lx extended virtual addr 0x%lx\n",
		flush_op_val(flush_op), flush_addr_val(flush_addr));
	FLUSH_ICACHE_LINE(flush_op_val(flush_op), flush_addr_val(flush_addr));
}

#define flush_ICACHE_line_begin()
#define flush_ICACHE_line_end() \
do { \
	E2K_WAIT_FLUSH; \
} while (0)

static inline void
__flush_ICACHE_line_user(e2k_addr_t virt_addr)
{
	__flush_ICACHE_line(flush_op_icache_line_user,
				flush_addr_make_user(virt_addr));
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
	__flush_ICACHE_line(flush_op_icache_line_sys,
				flush_addr_make_sys(virt_addr, context));
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
 * Flush and invalidate CACHE(s) (invalidate all caches of the processor)
 * WARNING: operation was deleted from instruction set begining V3-iset
 */

static inline void
boot_native_invalidate_CACHE_L12(void)
{
	int invalidate_supported;
	unsigned long flags;

	/* Invalidate operation was removed in E2S */
	invalidate_supported = BOOT_NATIVE_IS_MACHINE_ES2;

	raw_all_irq_save(flags);
	E2K_WAIT_MA;
	if (invalidate_supported)
		NATIVE_FLUSH_CACHE_L12(_flush_op_invalidate_cache_L12);
	else
		NATIVE_FLUSH_CACHE_L12(_flush_op_write_back_cache_L12);
	E2K_WAIT_FLUSH;
	raw_all_irq_restore(flags);
}

/*
 * Flush and write back CACHE(s) (write back and invalidate all caches
 * of the processor)
 * Flush cache is the same as write back
 */

static inline void
native_raw_write_back_CACHE_L12(void)
{
	__E2K_WAIT(E2K_WAIT_OP_MA_C_MASK);
	NATIVE_FLUSH_CACHE_L12(_flush_op_write_back_cache_L12);
	__E2K_WAIT(E2K_WAIT_OP_FL_C_MASK | E2K_WAIT_OP_MA_C_MASK);
}

static inline void
write_back_CACHE_L12(void)
{
	DebugMR("Flush : Write back all CACHEs (op 0x%lx)\n",
		_flush_op_write_back_cache_L12);
	FLUSH_CACHE_L12(_flush_op_write_back_cache_L12);
}

/*
 * Flush TLB (invalidate all TLBs of the processor)
 */

static inline void
native_raw_flush_TLB_all(void)
{
	__E2K_WAIT(E2K_WAIT_OP_ST_C_MASK);
	NATIVE_FLUSH_TLB_ALL(_flush_op_tlb_all);
	__E2K_WAIT(E2K_WAIT_OP_FL_C_MASK | E2K_WAIT_OP_MA_C_MASK);
}

static inline void
flush_TLB_all(void)
{
	DebugMR("Flush all TLBs (op 0x%lx)\n", _flush_op_tlb_all);
	FLUSH_TLB_ALL(_flush_op_tlb_all);
}

/*
 * Flush ICACHE (invalidate instruction caches of the processor)
 */
static inline void
flush_ICACHE_all(void)
{
	DebugMR("Flush all ICACHE op 0x%lx\n", _flush_op_icache_all);
	FLUSH_ICACHE_ALL(_flush_op_icache_all);
}

/*
 * Read CLW register
 */

static	inline	clw_reg_t
read_CLW_reg(clw_addr_t clw_addr)
{
	DebugCLW("Read CLW reg 0x%lx\n", clw_addr);
	return READ_CLW_REG(clw_addr);
}

static	inline	clw_reg_t
native_read_CLW_reg(clw_addr_t clw_addr)
{
	DebugCLW("Read CLW reg 0x%lx\n", clw_addr);
	return NATIVE_READ_CLW_REG(clw_addr);
}

/*
 * Read CLW bottom register
 */
#define	read_US_CL_B()		read_CLW_reg(ADDR_US_CL_B)
#define	READ_US_CL_B()		READ_CLW_REG(ADDR_US_CL_B)
#define	native_read_US_CL_B()	native_read_CLW_reg(ADDR_US_CL_B)
#define	NATIVE_READ_US_CL_B()	NATIVE_READ_CLW_REG(ADDR_US_CL_B)

/*
 * Read CLW up register
 */
#define	read_US_CL_UP()		read_CLW_reg(ADDR_US_CL_UP)
#define	READ_US_CL_UP()		READ_CLW_REG(ADDR_US_CL_UP)
#define	native_read_US_CL_UP()	native_read_CLW_reg(ADDR_US_CL_UP)
#define	NATIVE_READ_US_CL_UP()	NATIVE_READ_CLW_REG(ADDR_US_CL_UP)

/*
 * Read CLW bit-mask registers
 */
#define	read_US_CL_M0()		read_CLW_reg(ADDR_US_CL_M0)
#define	READ_US_CL_M0()		READ_CLW_REG(ADDR_US_CL_M0)
#define	read_US_CL_M1()		read_CLW_reg(ADDR_US_CL_M1)
#define	READ_US_CL_M1()		READ_CLW_REG(ADDR_US_CL_M1)
#define	read_US_CL_M2()		read_CLW_reg(ADDR_US_CL_M2)
#define	READ_US_CL_M2()		READ_CLW_REG(ADDR_US_CL_M2)
#define	read_US_CL_M3()		read_CLW_reg(ADDR_US_CL_M3)
#define	READ_US_CL_M3()		READ_CLW_REG(ADDR_US_CL_M3)
#define	native_read_US_CL_M0()	native_read_CLW_reg(ADDR_US_CL_M0)
#define	NATIVE_READ_US_CL_M0()	NATIVE_READ_CLW_REG(ADDR_US_CL_M0)
#define	native_read_US_CL_M1()	native_read_CLW_reg(ADDR_US_CL_M1)
#define	NATIVE_READ_US_CL_M1()	NATIVE_READ_CLW_REG(ADDR_US_CL_M1)
#define	native_read_US_CL_M2()	native_read_CLW_reg(ADDR_US_CL_M2)
#define	NATIVE_READ_US_CL_M2()	NATIVE_READ_CLW_REG(ADDR_US_CL_M2)
#define	native_read_US_CL_M3()	native_read_CLW_reg(ADDR_US_CL_M3)
#define	NATIVE_READ_US_CL_M3()	NATIVE_READ_CLW_REG(ADDR_US_CL_M3)

/*
 * Write CLW register
 */

static	inline	void
write_CLW_reg(clw_addr_t clw_addr, clw_reg_t val)
{
	DebugCLW("Write CLW reg 0x%lx value 0x%lx\n", clw_addr, val);
	WRITE_CLW_REG(clw_addr, val);
}

static	inline	void
native_write_CLW_reg(clw_addr_t clw_addr, clw_reg_t val)
{
	DebugCLW("Write CLW reg 0x%lx value 0x%lx\n", clw_addr, val);
	NATIVE_WRITE_CLW_REG(clw_addr, val);
}

/*
 * Write CLW bottom register
 */
#define	write_US_CL_B(val)		write_CLW_reg(ADDR_US_CL_B, val)
#define	WRITE_US_CL_B(val)		WRITE_CLW_REG(ADDR_US_CL_B, val)
#define	native_write_US_CL_B(val)	native_write_CLW_reg(ADDR_US_CL_B, val)
#define	NATIVE_WRITE_US_CL_B(val)	NATIVE_WRITE_CLW_REG(ADDR_US_CL_B, val)

/*
 * Write CLW up register
 */
#define	write_US_CL_UP(val)		write_CLW_reg(ADDR_US_CL_UP, val)
#define	WRITE_US_CL_UP(val)		WRITE_CLW_REG(ADDR_US_CL_UP, val)
#define	native_write_US_CL_UP(val)	native_write_CLW_reg(ADDR_US_CL_UP, val)
#define	NATIVE_WRITE_US_CL_UP(val)	NATIVE_WRITE_CLW_REG(ADDR_US_CL_UP, val)

/*
 * Write CLW bit-mask registers
 */
#define	write_US_CL_M0(val)		write_CLW_reg(ADDR_US_CL_M0, val)
#define	WRITE_US_CL_M0(val)		WRITE_CLW_REG(ADDR_US_CL_M0, val)
#define	write_US_CL_M1(val)		write_CLW_reg(ADDR_US_CL_M1, val)
#define	WRITE_US_CL_M1(val)		WRITE_CLW_REG(ADDR_US_CL_M1, val)
#define	write_US_CL_M2(val)		write_CLW_reg(ADDR_US_CL_M2, val)
#define	WRITE_US_CL_M2(val)		WRITE_CLW_REG(ADDR_US_CL_M2, val)
#define	write_US_CL_M3(val)		write_CLW_reg(ADDR_US_CL_M3, val)
#define	WRITE_US_CL_M3(val)		WRITE_CLW_REG(ADDR_US_CL_M3, val)
#define	native_write_US_CL_M0(val)	native_write_CLW_reg(ADDR_US_CL_M0, val)
#define	NATIVE_WRITE_US_CL_M0(val)	NATIVE_WRITE_CLW_REG(ADDR_US_CL_M0, val)
#define	native_write_US_CL_M1(val)	native_write_CLW_reg(ADDR_US_CL_M1, val)
#define	NATIVE_WRITE_US_CL_M1(val)	NATIVE_WRITE_CLW_REG(ADDR_US_CL_M1, val)
#define	native_write_US_CL_M2(val)	native_write_CLW_reg(ADDR_US_CL_M2, val)
#define	NATIVE_WRITE_US_CL_M2(val)	NATIVE_WRITE_CLW_REG(ADDR_US_CL_M2, val)
#define	native_write_US_CL_M3(val)	native_write_CLW_reg(ADDR_US_CL_M3, val)
#define	NATIVE_WRITE_US_CL_M3(val)	NATIVE_WRITE_CLW_REG(ADDR_US_CL_M3, val)


#endif /* ! __ASSEMBLY__ */

#endif  /* _E2K_MMU_REGS_H_ */
