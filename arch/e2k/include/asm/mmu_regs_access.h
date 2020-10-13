/*
 * asm-e2k/mmu_regs_access.h: E2K MMU registers access.
 *
 * Copyright 2012 Pavel V. Pantellev (panteleev_p@mcst.ru)
 */

#ifndef	_E2K_MMU_REGS_ACCESS_H_
#define	_E2K_MMU_REGS_ACCESS_H_

#include <asm/debug_print.h>
#include <asm/e2k_api.h>
#include <asm/head.h>
#include <asm/mmu_regs.h>

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

#ifndef __ASSEMBLY__
/*
 * Write MMU register
 */
static	inline	void
write_MMU_reg(mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	DebugMR("Write MMU reg 0x%lx value 0x%lx\n",
		MMU_REG_NO_FROM_MMU_ADDR(mmu_addr), mmu_reg_val(mmu_reg));
	WRITE_MMU_REG(mmu_addr_val(mmu_addr), mmu_reg_val(mmu_reg));
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

/*
 * Read MMU Control register
 */
static	inline	unsigned long
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
static	inline	void
set_MMU_CR(unsigned long mmu_cr)
{
	DebugMR("Set MMU Control Register to 0x%lx\n", mmu_cr);
	WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR_NO), mmu_cr);
	DebugMR("Read MMU Control Register : 0x%lx\n",
		READ_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CR_NO)));
}

/*
 * Write MMU Context register
 */
static	inline	void
set_MMU_CONT(unsigned long context)
{
	DebugMCR("Set MMU CONTEXT register to 0x%lx\n", context);
	WRITE_MMU_REG(_MMU_REG_NO_TO_MMU_ADDR_VAL(_MMU_CONT_NO), context);
}

/*
 * Write MMU Control Register of secondary space table
 */
static	inline	void
set_MMU_CR3_RG(unsigned long mmu_page_dir)
{
	DebugMR("Set MMU INTEL page table base register to 0x%lx\n",
		mmu_page_dir);
	WRITE_MMU_CR3_RG(mmu_page_dir);
}

/*
 * Write MMU ELBRUS page table base register
 */
static	inline	void
set_MMU_ELB_PTB(unsigned long mmu_elb_ptb)
{
	DebugMR("Set MMU ELBRUS page table base register to 0x%lx\n",
		mmu_elb_ptb);
	WRITE_MMU_ELB_PTB(mmu_elb_ptb);
}

/*
 * Write MMU root page table base register
 */
static	inline	void
set_MMU_ROOT_PTB(unsigned long mmu_root_ptb)
{
	DebugMR("Set MMU root page table base register to 0x%lx\n",
		mmu_root_ptb);
	WRITE_MMU_ROOT_PTB(mmu_root_ptb);
}

/*
 * Set MMU Trap Point register
 */
static	inline	void
set_MMU_TRAP_POINT(void *trap_cellar)
{
	DebugMR("Set MMU Trap Point register to 0x%llx\n", (u64) trap_cellar);
	WRITE_MMU_TRAP_POINT(trap_cellar);
}

/*
 * Set MMU Trap Counter register
 */
static	inline	void
set_MMU_TRAP_COUNT(unsigned int counter)
{
	DebugMR("Set MMU Trap Counter register to %u\n", counter);
	WRITE_MMU_TRAP_COUNT(counter);
}
static	inline	void
reset_MMU_TRAP_COUNT(void)
{
	RESET_MMU_TRAP_COUNT();
}

/*
 * Read MMU Trap Counter register
 */
static	inline	unsigned int
read_MMU_TRAP_COUNT(void)
{
	DebugMR("Read MMU Trap Counter register\n");
	return READ_MMU_TRAP_COUNT();
}

/*
 * Set MMU Memory Protection Table Base register
 */
static	inline	void
set_MMU_MPT_B(unsigned long base)
{
	DebugMR("Set MMU Memory Protection Table Base register to 0x%lx\n",
		base);
	WRITE_MMU_MPT_B(base);
}

/*
 * Set MMU PCI Low Bound register
 */
static	inline	void
set_MMU_PCI_L_B(unsigned long bound)
{
	DebugMR("Set MMU PCI low bound register to 0x%lx\n", bound);
	WRITE_MMU_PCI_L_B(bound);
}

/*
 * Set MMU Phys High Bound register
 */
static	inline	void
set_MMU_PH_H_B(unsigned long bound)
{
	DebugMR("Set MMU Physical memory high bound register to 0x%lx\n", bound);
	WRITE_MMU_PH_H_B(bound);
}

/*
 * Write User Stack Clean Window Disable register
 */
static	inline	void
write_MMU_US_CL_D(unsigned int disable_flag)
{
	if (disable_flag)
		E2K_WAIT(_all_e);
	WRITE_MMU_US_CL_D(disable_flag);
}

/*
 * Set Memory Type Range Registers ( MTRRS )
 */
static	inline	void
set_MMU_MTRR_REG(unsigned long no, long long value)
{
	DebugCLW("Set MTRR#%lu register to ox%llx\n", no, value);
	WRITE_MTRR_REG(no, value);
}

/*
 * Get Memory Type Range Registers ( MTRRS )
 */
static	inline	unsigned int
read_MMU_US_CL_D(void)
{
	DebugCLW("Read MMU US CLW Disable register\n");
	return (unsigned int)READ_MMU_US_CL_D();
}

/*
 * Get Entry probe for virtual address
 */
static	inline	probe_entry_t
get_MMU_DTLB_ENTRY(e2k_addr_t virt_addr)
{
	DebugMR("Get DTLB entry probe for virtual address 0x%lx\n",
		virt_addr);
	return __probe_entry(GET_MMU_DTLB_ENTRY(virt_addr));
}

/*
 * Read CLW register
 */
static	inline	clw_reg_t
read_CLW_reg(clw_addr_t clw_addr)
{
	DebugCLW("Read CLW reg 0x%lx\n", clw_addr_val(clw_addr));
	return __clw_reg(READ_CLW_REG(clw_addr));
}

/*
 * Write Data TLB tag register
 */
static	inline	void
write_DTLB_tag_reg(tlb_addr_t tlb_addr, tlb_tag_t tlb_tag)
{
	DebugMR("Write DTLB addr 0x%lx tag 0x%lx\n",
		tlb_addr_val(tlb_addr), tlb_tag_val(tlb_tag));
	E2K_WRITE_MAS_D(tlb_addr_val(tlb_addr), tlb_tag_val(tlb_tag),
			MAS_DTLB_REG);
}

/*
 * Write Data TLB entry register
 */
static	inline	void
write_DTLB_entry_reg(tlb_addr_t tlb_addr, mmu_reg_t pte)
{
	DebugMR("Write DTLB addr 0x%lx entry 0x%lx\n",
		tlb_addr_val(tlb_addr), pte);
	E2K_WRITE_MAS_D(tlb_addr_val(tlb_addr), pte, MAS_DTLB_REG);
}

/*
 * Read Data TLB tag register
 */
static	inline	tlb_tag_t
read_DTLB_tag_reg(tlb_addr_t tlb_addr)
{
	tlb_tag_t tlb_tag;
	tlb_tag_val(tlb_tag) = E2K_READ_MAS_D(tlb_addr_val(tlb_addr),
							MAS_DTLB_REG);
	DebugTLB("Read DTLB tag 0x%lx for addr 0x%lx\n",
		tlb_tag_val(tlb_tag), tlb_addr_val(tlb_addr));
	return tlb_tag;
}
static	inline	tlb_tag_t
read_DTLB_va_tag_reg(e2k_addr_t virt_addr, int set_num, int large_page)
{
	tlb_addr_t tlb_addr;
	tlb_addr = tlb_addr_tag_access;
	tlb_addr = tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr,
								large_page);
	tlb_addr = tlb_addr_set_set_num(tlb_addr, set_num);
	return read_DTLB_tag_reg(tlb_addr);
}

/*
 * Read Data TLB entry register
 */
static	inline	mmu_reg_t
read_DTLB_entry_reg(tlb_addr_t tlb_addr)
{
	mmu_reg_t pte;
	pte = E2K_READ_MAS_D(tlb_addr_val(tlb_addr), MAS_DTLB_REG);
	DebugTLB("Read DTLB entry 0x%lx for addr 0x%lx\n",
		pte, tlb_addr_val(tlb_addr));
	return pte;
}

static	inline	mmu_reg_t
read_DTLB_va_entry_reg(e2k_addr_t virt_addr, int set_num, int large_page)
{
	tlb_addr_t tlb_addr;
	tlb_addr = tlb_addr_entry_access;
	tlb_addr = tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr,
								large_page);
	tlb_addr = tlb_addr_set_set_num(tlb_addr, set_num);
	return read_DTLB_entry_reg(tlb_addr);
}

/*
 * Flush TLB page
 */
static inline void ____flush_TLB_page(flush_op_t flush_op,
				      flush_addr_t flush_addr)
{
	DebugTLB("Flush TLB page : op 0x%lx extended virtual addr 0x%lx\n",
		flush_op_val(flush_op), flush_addr_val(flush_addr));

	E2K_WRITE_MAS_D(flush_op_val(flush_op), flush_addr_val(flush_addr),
			MAS_TLB_PAGE_FLUSH);
}

#define flush_TLB_page_begin()
#define flush_TLB_page_end() \
do { \
	E2K_WAIT(_fl_c | _ma_c); \
} while (0)

static inline void __flush_TLB_page(e2k_addr_t virt_addr, unsigned long context)
{
	____flush_TLB_page(flush_op_tlb_page_sys,
			   flush_addr_make_sys(virt_addr, context));
}

static inline void flush_TLB_page(e2k_addr_t virt_addr, unsigned long context)
{
	flush_TLB_page_begin();
	__flush_TLB_page(virt_addr, context);
	flush_TLB_page_end();
}

static inline void __flush_TLB_kernel_page(e2k_addr_t virt_addr)
{
	__flush_TLB_page(virt_addr, E2K_KERNEL_CONTEXT);
}

static inline void flush_TLB_kernel_page(e2k_addr_t virt_addr)
{
	flush_TLB_page_begin();
	__flush_TLB_kernel_page(virt_addr);
	flush_TLB_page_end();
}

static inline void __flush_TLB_ss_page(e2k_addr_t virt_addr,
				       unsigned long context)
{
	____flush_TLB_page(flush_op_tlb_page_sys,
			   flush_addr_make_ss(virt_addr, context));
}

static inline void flush_TLB_ss_page(e2k_addr_t virt_addr,
				     unsigned long context)
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
	E2K_WRITE_MAS_D(virt_addr, 0UL, MAS_DCACHE_LINE_FLUSH);
}

static inline void flush_DCACHE_line(e2k_addr_t virt_addr)
{
	DebugMR("Flush DCACHE line: virtual addr 0x%lx\n", virt_addr);

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
	E2K_WRITE_MAS_D(mk_dcache_l1_addr(virt_addr, set, 1, 0),
		0UL, MAS_DCACHE_L1_REG);
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
 * Flush ICACHE line
 */
static inline void
__flush_ICACHE_line(flush_op_t flush_op, flush_addr_t flush_addr)
{
	DebugMR("Flush ICACHE line : op 0x%lx extended virtual addr 0x%lx\n",
		flush_op_val(flush_op), flush_addr_val(flush_addr));

	E2K_WRITE_MAS_D(flush_op_val(flush_op), flush_addr_val(flush_addr),
			MAS_ICACHE_LINE_FLUSH);
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

static inline void
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

static inline void
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
 */
static	inline	void
invalidate_CACHE_all(void)
{
	int invalidate_supported;

	DebugMR("Flush : Invalidate all CACHEs (op 0x%lx)\n",
		_flush_op_invalidate_cache_all);

	/* Invalidate operation was removed in E2S */
	invalidate_supported = IS_MACHINE_E3M || IS_MACHINE_E3S
			|| IS_MACHINE_ES2;

        E2K_WAIT_MA;
	if (invalidate_supported)
		E2K_WRITE_MAS_D(_flush_op_invalidate_cache_all,
				0UL, MAS_CACHE_FLUSH);
	else
		E2K_WRITE_MAS_D(_flush_op_write_back_cache_all,
				0UL, MAS_CACHE_FLUSH);
		
        E2K_WAIT_FLUSH;
}

/*
 * Flush and write back CACHE(s) (write back and invalidate all caches
 * of the processor)
 */
static	inline	void
write_back_CACHE_all(void)
{
	DebugMR("Flush : Write back all CACHEs (op 0x%lx)\n",
		_flush_op_write_back_cache_all);

        E2K_WAIT_MA;
	E2K_WRITE_MAS_D(_flush_op_write_back_cache_all, 0UL, MAS_CACHE_FLUSH);
        E2K_WAIT_FLUSH;
}

/*
 * Flush TLB (invalidate all TLBs of the processor)
 */
static inline void
flush_TLB_all(void)
{
	DebugMR("Flush all TLBs (op 0x%lx)\n", _flush_op_tlb_all);

	E2K_WAIT_ST;
	E2K_WRITE_MAS_D(_flush_op_tlb_all, 0UL, MAS_TLB_FLUSH);
	E2K_WAIT(_fl_c | _ma_c);
}

/*
 * Flush ICACHE (invalidate instruction caches of the processor)
 */
static	inline	void
flush_ICACHE_all(void)
{
	DebugMR("Flush all ICACHE op 0x%lx\n", _flush_op_icache_all);

        E2K_WAIT_ST;
	E2K_WRITE_MAS_D(_flush_op_icache_all, 0UL, MAS_ICACHE_FLUSH);
        E2K_WAIT_FLUSH;
}
#endif /* __ASSEMBLY__ */

#endif	/* _E2K_MMU_REGS_ACCESS_H_ */
