#ifndef	_E2K_TLB_REGS_ACCESS_H_
#define	_E2K_TLB_REGS_ACCESS_H_

#include <asm/tlb_regs_types.h>
#include <asm/mmu_regs_access.h>

#undef	DEBUG_TLB_MODE
#undef	DebugTLB
#define	DEBUG_TLB_MODE		0	/* TLB registers access */
#define DebugTLB(...)		DebugPrint(DEBUG_TLB_MODE, ##__VA_ARGS__)

/*
 * DTLB/ITLB registers operations
 */

/*
 * Write Data TLB tag register
 */
static inline void
write_DTLB_tag_reg(tlb_addr_t tlb_addr, tlb_tag_t tlb_tag)
{
	DebugMR("Write DTLB addr 0x%lx tag 0x%lx\n",
		tlb_addr_val(tlb_addr), tlb_tag_val(tlb_tag));
	WRITE_DTLB_REG(tlb_addr_val(tlb_addr), tlb_tag_val(tlb_tag));
}

/*
 * Write Data TLB entry register
 */
static inline void
write_DTLB_entry_reg(tlb_addr_t tlb_addr, mmu_reg_t pte)
{
	DebugMR("Write DTLB addr 0x%lx entry 0x%llx\n",
		tlb_addr_val(tlb_addr), pte);
	WRITE_DTLB_REG(tlb_addr_val(tlb_addr), pte);
}

/*
 * Read Data TLB tag register
 */
static inline tlb_tag_t
read_DTLB_tag_reg(tlb_addr_t tlb_addr)
{
	tlb_tag_t tlb_tag;
	tlb_tag_val(tlb_tag) = READ_DTLB_REG(tlb_addr_val(tlb_addr));
	DebugTLB("Read DTLB tag 0x%lx for addr 0x%lx\n",
		tlb_tag_val(tlb_tag), tlb_addr_val(tlb_addr));
	return tlb_tag;
}
static inline tlb_tag_t
read_DTLB_va_tag_reg(e2k_addr_t virt_addr, int set_num, int large_page)
{
	tlb_addr_t tlb_addr;
	tlb_addr = tlb_addr_tag_access;
	tlb_addr = tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr,
								large_page);
	tlb_addr = tlb_addr_set_set_num(tlb_addr, set_num);
	return read_DTLB_tag_reg(tlb_addr);
}
static inline tlb_tag_t
get_tlb_tag_reg(int line_no, int set_no)
{
	tlb_addr_t tlb_addr;
	tlb_addr = tlb_addr_tag_access;
	tlb_addr = tlb_addr_set_line_num(tlb_addr, line_no);
	tlb_addr = tlb_addr_set_set_num(tlb_addr, set_no);
	return read_DTLB_tag_reg(tlb_addr);
}

/*
 * Read Data TLB entry register
 */
static inline mmu_reg_t
read_DTLB_entry_reg(tlb_addr_t tlb_addr)
{
	mmu_reg_t pte;
	pte = READ_DTLB_REG(tlb_addr_val(tlb_addr));
	DebugTLB("Read DTLB entry 0x%llx for addr 0x%lx\n",
		pte, tlb_addr_val(tlb_addr));
	return pte;
}
static inline mmu_reg_t
read_DTLB_va_entry_reg(e2k_addr_t virt_addr, int set_num, int large_page)
{
	tlb_addr_t tlb_addr;
	tlb_addr = tlb_addr_entry_access;
	tlb_addr = tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr,
								large_page);
	tlb_addr = tlb_addr_set_set_num(tlb_addr, set_num);
	return read_DTLB_entry_reg(tlb_addr);
}
static inline pte_t
get_tlb_entry_reg(int line_no, int set_no)
{
	pte_t tlb_entry;

	tlb_addr_t tlb_addr;
	tlb_addr = tlb_addr_entry_access;
	tlb_addr = tlb_addr_set_line_num(tlb_addr, line_no);
	tlb_addr = tlb_addr_set_set_num(tlb_addr, set_no);
	pte_val(tlb_entry) = read_DTLB_entry_reg(tlb_addr);
	return tlb_entry;
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

typedef struct tlb_set_state {
	tlb_tag_t	tlb_tag;
	pte_t		tlb_entry;
} tlb_set_state_t;

typedef struct tlb_line_state {
	e2k_addr_t	va;
	bool		huge;
	tlb_set_state_t	sets[NATIVE_TLB_SETS_NUM];
} tlb_line_state_t;

typedef struct tlb_line_sets {
	tlb_set_state_t	sets[NATIVE_TLB_SETS_NUM];
} tlb_line_sets_t;

typedef struct tlb_state {
	tlb_line_sets_t	lines[NATIVE_TLB_LINES_NUM];
} tlb_state_t;

static inline tlb_tag_t
get_va_tlb_set_tag(e2k_addr_t addr, int set_no, bool large_page)
{
	return read_DTLB_va_tag_reg(addr, set_no, large_page);
}

static inline pte_t
get_va_tlb_set_entry(e2k_addr_t addr, int set_no, bool large_page)
{
	pte_t tlb_entry;

	pte_val(tlb_entry) = read_DTLB_va_entry_reg(addr, set_no, large_page);
	return tlb_entry;
}

static inline void
get_va_tlb_state(tlb_line_state_t *tlb, e2k_addr_t addr, bool large_page)
{
	tlb_set_state_t *set_state;
	int set_no;

	tlb->va = addr;
	tlb->huge = large_page;

	for (set_no = 0; set_no < NATIVE_TLB_SETS_NUM; set_no++) {
		tlb_tag_t tlb_tag;
		pte_t tlb_entry;

		set_state = &tlb->sets[set_no];
		tlb_tag = get_va_tlb_set_tag(addr, set_no, large_page);
		tlb_entry = get_va_tlb_set_entry(addr, set_no, large_page);
		set_state->tlb_tag = tlb_tag;
		set_state->tlb_entry = tlb_entry;
	}
}

static inline void
get_tlb_line_sets(tlb_set_state_t *sets_state, int line_no)
{
	tlb_set_state_t *set;
	int set_no;

	for (set_no = 0; set_no < NATIVE_TLB_SETS_NUM; set_no++) {
		tlb_tag_t tlb_tag;
		pte_t tlb_entry;

		set = &sets_state[set_no];
		tlb_tag = get_tlb_tag_reg(line_no, set_no);
		tlb_entry = get_tlb_entry_reg(line_no, set_no);
		set->tlb_tag = tlb_tag;
		set->tlb_entry = tlb_entry;
	}
}

static inline void
get_all_tlb_state(tlb_state_t *tlb)
{
	tlb_line_sets_t *line;
	int line_no;

	for (line_no = 0; line_no < NATIVE_TLB_LINES_NUM; line_no++) {
		line = &tlb->lines[line_no];
		get_tlb_line_sets(line->sets, line_no);
	}
}

#endif	/* !_E2K_TLB_REGS_ACCESS_H_ */
