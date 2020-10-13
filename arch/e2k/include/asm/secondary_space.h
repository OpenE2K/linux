/*
 * Secondary space support for E2K binary compiler
 * asm/secondary_space.h
 * 48-bit E2K addr:
 *
 * 47 pgd  39 38 pud 30 29 pmd 21 20 pte 12 11 offset  0
 * |_________|_________|_________|_________|____________|
 *
 *                   31  pgd  22 21 pte  12 11 offset  0
 * __________________|__________|__________|____________|32-bit i386 addr
 *
 */
#ifndef _SECONDARY_SPACE_H
#define	_SECONDARY_SPACE_H

#ifndef __ASSEMBLY__
#include <linux/mm_types.h>
#include <asm/machdep.h>
#include <asm/page.h>
#include <asm/processor.h>
#include <asm/types.h>
#include <asm/mmu_regs.h>
#endif /* !__ASSEMBLY__ */

#define BINCO_PROTOCOL_VERSION	2

#define SS_SIZE			((machine.iset_ver >= E2K_ISET_V3) ? \
					(0x800000000000UL) : (0x100000000UL))
#define ADDR32_MASK		(0xffffffffUL)
#define MPT_SIZE		((SS_SIZE >> PAGE_SHIFT) >> 3) /* bit on page */

#define SS_ADDR_START		((machine.iset_ver >= E2K_ISET_V3) ? \
				0x0000400000000000L : 0x0000100000000000L)

				/* 
				 * If updating this value - do not forget to 
				 * update E2K_ARG3_MASK - mask for 63-45 bits 
				 * and PAGE_OFFSET. kravtsunov_e.
				 */
#define SS_ADDR_END		(SS_ADDR_START + SS_SIZE)

#ifdef CONFIG_SECONDARY_SPACE_SUPPORT
#define ADDR_IN_SS(a)		((a >= SS_ADDR_START) && (a < SS_ADDR_END))
#else
#define ADDR_IN_SS(a)		0
#endif

#ifdef CONFIG_UPT_SUPPORT
#define IS_UPT_E3S		(!IS_MACHINE_E3M)
#else /* !CONFIG_UPT_SUPPORT: */
#define IS_UPT_E3S		0
#endif /* CONFIG_UPT_SUPPORT */

#define	PAGE_IN_SS(page)	((page_to_phys(page) & ~ADDR32_MASK) == 0)

#define SS_N_PMD		4
#define SS_PMD_ORDER		3

#define SS_N_PTE		2
#define SS_PTE_ORDER		2

#define SS_PMD_MASK		(PAGE_MASK << SS_PMD_ORDER)
#define SS_PTE_MASK		(PAGE_MASK << SS_PTE_ORDER)
#define __GFP_IA32		__GFP_DMA
#define SS_ALLOC_FLAG		GFP_KERNEL|__GFP_REPEAT|__GFP_ZERO|__GFP_IA32| \
				__GFP_COMP

#define IN_INTEL_MODE		((u64 )get_MMU_CR3_RG() !=	\
					 __pa(empty_sec_pg_dir))
#define IS_FIRST_PTE(a)		!((a >> PMD_SHIFT) & 0x1)
#define PMD0			E2K_VA_MASK & (PGDIR_MASK|PUD_MASK|(~PMD_MASK))
#define PREV_PMD(a)		(a & PMD0) | ((pmd_index(a) - 1) << PMD_SHIFT)

#define SET_TBL_FREE(a)							\
({									\
		*(u64 *)a = (u64)_PAGE_SEC_MAP;				\
})
#define TBL_IS_FREE(a)		(*(u64 *)a == (u64)_PAGE_SEC_MAP)
#define SET_TBL_ZERO(a)		(*(u64 *)a = 0UL)

#define	DEBUG_SS_MODE		0	/* Secondary Space Debug */
#define DebugSS(...)		DebugPrint(DEBUG_SS_MODE ,##__VA_ARGS__)

#define KERNEL_SLEEP(SEC)						\
({									\
	set_current_state(TASK_INTERRUPTIBLE);				\
	schedule_timeout(SEC * HZ);					\
})
/* returns page(s) within 32-bit phys address space */
#ifndef __ASSEMBLY__

extern
inline struct page *get_i386_pages(int order);

extern
void verify_SS_addr(e2k_addr_t addr);
extern
void print_sec(void);

extern
s64 sys_el_binary(s64 work, s64 arg2, s64 arg3, s64 arg4);

extern struct page *remap_page_to_ss_memory(struct page *page,
			struct vm_area_struct *vma, unsigned long address,
			gfp_t gfp_mask);

/*
 * Intreface of el_binary() syscall
 * Work argument(arg1) values:
 */
#define GET_SECONDARY_SPACE_OFFSET	0
#define SET_SECONDARY_REMAP_BOUND	1
#define SET_SECONDARY_DESCRIPTOR	2
#define SET_SECONDARY_MTRR		3
#define GET_SECONDARY_MTRR		4
#define TGKILL_INFO			6
#define SIG_EXIT_GROUP			7
#define FLUSH_CMD_CACHES_DEPRECATED	8
#define SET_SYSCALL_RESTART_IGNORE	9
#define SET_RP_BOUNDS_AND_IP		10
#define SET_SECONDARY_64BIT_MODE	11
#define GET_PROTOCOL_VERSION		12

/* Selector numbers for GET_SECONDARY_SPACE_OFFSET */
enum sel_num {
	CS_SELECTOR		= 0,
	DS_SELECTOR		= 1,
	ES_SELECTOR		= 2,
	SS_SELECTOR		= 3,
	FS_SELECTOR		= 4,
	GS_SELECTOR		= 5,
};

#define E2K_ARG3_MASK	(0xffffe000ffffffffLL)
#define I32_ADDR_TO_E2K(arg)					\
({      							\
	s64 argm;						\
	argm = arg;						\
	if (IS_UPT_E3S && machine.iset_ver < E2K_ISET_V3) {	\
		argm &= E2K_ARG3_MASK;				\
		argm |= SS_ADDR_START;				\
	}							\
	argm;							\
})
#endif /* !__ASSEMBLY__ */

#endif /* _SECONDARY_SPACE_H */
