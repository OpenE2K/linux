#ifndef	_E2K_TLB_REGS_ACCESS_H_
#define	_E2K_TLB_REGS_ACCESS_H_

#include <asm/tlb_regs_types.h>
#include <asm/mmu_regs_access.h>

/*
 * DTLB/ITLB registers operations
 */

/*
 * Write Data TLB tag register
 */
static inline	void
write_DTLB_tag_reg(tlb_addr_t tlb_addr, tlb_tag_t tlb_tag)
{
	DebugMR("Write DTLB addr 0x%lx tag 0x%lx\n",
		tlb_addr_val(tlb_addr), tlb_tag_val(tlb_tag));
	WRITE_DTLB_REG(tlb_addr_val(tlb_addr), tlb_tag_val(tlb_tag));
}

/*
 * Write Data TLB entry register
 */
static inline	void
write_DTLB_entry_reg(tlb_addr_t tlb_addr, mmu_reg_t pte)
{
	DebugMR("Write DTLB addr 0x%lx entry 0x%llx\n",
		tlb_addr_val(tlb_addr), pte);
	WRITE_DTLB_REG(tlb_addr_val(tlb_addr), pte);
}

/*
 * Read Data TLB tag register
 */
static inline	tlb_tag_t
read_DTLB_tag_reg(tlb_addr_t tlb_addr)
{
	tlb_tag_t tlb_tag;
	tlb_tag_val(tlb_tag) = READ_DTLB_REG(tlb_addr_val(tlb_addr));
	DebugTLB("Read DTLB tag 0x%lx for addr 0x%lx\n",
		tlb_tag_val(tlb_tag), tlb_addr_val(tlb_addr));
	return tlb_tag;
}
static inline	tlb_tag_t
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
static inline	mmu_reg_t
read_DTLB_entry_reg(tlb_addr_t tlb_addr)
{
	mmu_reg_t pte;
	pte = READ_DTLB_REG(tlb_addr_val(tlb_addr));
	DebugTLB("Read DTLB entry 0x%llx for addr 0x%lx\n",
		pte, tlb_addr_val(tlb_addr));
	return pte;
}
static inline	mmu_reg_t
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
 * Get Entry probe for virtual address
 */

#define	GET_MMU_DTLB_ENTRY(virt_addr)	\
		(unsigned long)ENTRY_PROBE_MMU_OP(probe_addr_val(virt_addr))
static inline	probe_entry_t
get_MMU_DTLB_ENTRY(e2k_addr_t virt_addr)
{
	DebugMR("Get DTLB entry probe for virtual address 0x%lx\n",
		virt_addr);
	return __probe_entry(GET_MMU_DTLB_ENTRY(virt_addr));
}

/*
 * Get physical address for virtual address
 */

#define	GET_MMU_PHYS_ADDR(virt_addr)	\
		((unsigned long)ADDRESS_PROBE_MMU_OP(probe_addr_val(virt_addr)))
static inline	probe_entry_t
get_MMU_phys_addr(e2k_addr_t virt_addr)
{
	DebugMR("Get physical address for virtual address 0x%lx\n",
		virt_addr);
	return __probe_entry(GET_MMU_PHYS_ADDR(virt_addr));
}

#endif
