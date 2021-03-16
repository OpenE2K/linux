#ifndef	_E2K_TLB_REGS_TYPES_H_
#define	_E2K_TLB_REGS_TYPES_H_

#include <linux/types.h>
#include <asm/machdep.h>


/* now DTLB entry format is different on iset V6 vs V2-V5 */
#if	CONFIG_CPU_ISET >= 6
# ifdef	CONFIG_MMU_PT_V6
#  define	MMU_IS_DTLB_V6()	true
# else	/* ! CONFIG_MMU_PT_V6 */
#  define	MMU_IS_DTLB_V6()	false
# endif	/* CONFIG_MMU_PT_V6 */
#elif	CONFIG_CPU_ISET >= 2
#  define	MMU_IS_DTLB_V6()	false
#elif	CONFIG_CPU_ISET == 0
# ifdef	E2K_P2V
#  define	MMU_IS_DTLB_V6()	\
			(boot_machine.mmu_pt_v6)
# else	/* ! E2K_P2V */
#  define	MMU_IS_DTLB_V6()	\
			(machine.mmu_pt_v6)
# endif	/* E2K_P2V */
#else	/* CONFIG_CPU_ISET undefined or negative */
# warning "Undefined CPU ISET VERSION #, MMU pt_v6 mode is defined dinamicaly"
# ifdef	E2K_P2V
#  define	MMU_IS_DTLB_V6()	\
			(boot_machine.mmu_pt_v6)
# else	/* ! E2K_P2V */
#  define	MMU_IS_DTLB_V6()	\
			(machine.mmu_pt_v6)
# endif	/* E2K_P2V */
#endif	/* CONFIG_CPU_ISET 0-6 */


/*
 * TLB (DTLB & ITLB) structure
 */

#define	NATIVE_TLB_LINES_BITS_NUM	(machine.tlb_lines_bits_num)
#define	BOOT_NATIVE_TLB_LINES_BITS_NUM	(boot_machine.tlb_lines_bits_num)

#define	NATIVE_TLB_LINES_NUM		(1 << NATIVE_TLB_LINES_BITS_NUM)
#define	BOOT_NATIVE_TLB_LINES_NUM	(1 << BOOT_NATIVE_TLB_LINES_BITS_NUM)

#define	NATIVE_MAX_TLB_LINES_NUM	(1 << ES2_TLB_LINES_BITS_NUM)

#define	NATIVE_TLB_SETS_NUM		4
#define	BOOT_NATIVE_TLB_SETS_NUM	NATIVE_TLB_SETS_NUM
#define	NATIVE_TLB_LARGE_PAGE_SET_NO	3	/* large page entries */
						/* occupied this set in each */
						/* line */

/*
 * DTLB/ITLB registers operations
 */

/* DTLB/ITLB registers access operations address */

#ifndef	__ASSEMBLY__
typedef	e2k_addr_t		tlb_addr_t;
typedef	tlb_addr_t		dtlb_addr_t;
typedef	tlb_addr_t		itlb_addr_t;
#endif	/* ! __ASSEMBLY__ */

#define	tlb_addr_val(tlb_addr)		(tlb_addr)
#define	dtlb_addr_val(dtlb_addr)	tlb_addr_val(dtlb_addr)
#define	itlb_addr_val(itlb_addr)	tlb_addr_val(itlb_addr)

#define	__tlb_addr(tlb_addr_val)	(tlb_addr_val)
#define	__dtlb_addr(dtlb_addr_val)	__tlb_addr(dtlb_addr_val)
#define	__itlb_addr(dtlb_addr_val)	__tlb_addr(itlb_addr_val)


/* Virtual page address translation to TLB line & set */

#define	_TLB_ADDR_LINE_NUM_SHIFT	12	/* [19:12] */

#define	E2K_PG_4K_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & (machine.tlb_addr_line_num)) >> \
				_TLB_ADDR_LINE_NUM_SHIFT)
#define	BOOT_E2K_PG_4K_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & (boot_machine.tlb_addr_line_num)) >> \
				_TLB_ADDR_LINE_NUM_SHIFT)

#define	E2K_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & (machine.tlb_addr_line_num2)) >> \
				(machine.tlb_addr_line_num_shift2))
#define	BOOT_E2K_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) \
		(((virt_addr) & (boot_machine.tlb_addr_line_num2)) >> \
				(boot_machine.tlb_addr_line_num_shift2))

#define VADDR_TO_TLB_LINE_NUM(virt_addr, large_page)	\
		((large_page) ? E2K_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) : \
				E2K_PG_4K_TO_TLB_LINE_NUM(virt_addr))
#define BOOT_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page)	\
		((large_page) ? BOOT_E2K_PG_LARGE_TO_TLB_LINE_NUM(virt_addr) : \
				BOOT_E2K_PG_4K_TO_TLB_LINE_NUM(virt_addr))

#define _TLB_ADDR_TYPE		0x0000000000000007	/* type of operation */
#define	_TLB_ADDR_TAG_ACCESS	0x0000000000000000	/* tag access oper. */
							/* type */
#define	_TLB_ADDR_ENTRY_ACCESS	0x0000000000000001	/* entry access oper. */
							/* type */

#define	tlb_addr_set_type(tlb_addr, type)	\
		(__tlb_addr((tlb_addr_val(tlb_addr) & ~_TLB_ADDR_TYPE) | \
		((type) & _TLB_ADDR_TYPE)))
#define	tlb_addr_set_tag_access(tlb_addr)	\
		tlb_addr_set_type(tlb_addr, _TLB_ADDR_TAG_ACCESS)
#define	tlb_addr_set_entry_access(tlb_addr)	\
		tlb_addr_set_type(tlb_addr, _TLB_ADDR_ENTRY_ACCESS)
#define	tlb_addr_tag_access	_TLB_ADDR_TAG_ACCESS
#define	tlb_addr_entry_access	_TLB_ADDR_ENTRY_ACCESS

#define	tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page) \
		(__tlb_addr((tlb_addr_val(tlb_addr) & \
					~((machine.tlb_addr_line_num) | \
					(machine.tlb_addr_line_num2))) | \
		(VADDR_TO_TLB_LINE_NUM(virt_addr, large_page) << \
					_TLB_ADDR_LINE_NUM_SHIFT) | \
		(VADDR_TO_TLB_LINE_NUM(virt_addr, large_page) << \
					(machine.tlb_addr_line_num_shift2))))
#define	boot_tlb_addr_set_vaddr_line_num(tlb_addr, virt_addr, large_page) \
		(__tlb_addr((tlb_addr_val(tlb_addr) & \
				~((boot_machine.tlb_addr_line_num) | \
				(boot_machine.tlb_addr_line_num2))) | \
		(BOOT_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page) << \
				_TLB_ADDR_LINE_NUM_SHIFT) | \
		(BOOT_VADDR_TO_TLB_LINE_NUM(virt_addr, large_page) << \
				(boot_machine.tlb_addr_line_num_shift2))))

#define	tlb_addr_set_set_num(tlb_addr, set_num)	\
		(__tlb_addr((tlb_addr_val(tlb_addr) & \
				~(machine.tlb_addr_set_num)) | \
		(((set_num) << (machine.tlb_addr_set_num_shift)) & \
				(machine.tlb_addr_set_num))))
#define	boot_tlb_addr_set_set_num(tlb_addr, set_num)	\
		(__tlb_addr((tlb_addr_val(tlb_addr) & \
				~(boot_machine.tlb_addr_set_num)) | \
		(((set_num) << (boot_machine.tlb_addr_set_num_shift)) & \
				(boot_machine.tlb_addr_set_num))))

/* DTLB/ITLB tag structure */

#ifndef	__ASSEMBLY__
typedef	e2k_addr_t		tlb_tag_t;
typedef	tlb_tag_t		dtlb_tag_t;
typedef	tlb_tag_t		itlb_tag_t;
#endif	/* ! __ASSEMBLY__ */

#define	tlb_tag_val(tlb_tag)		(tlb_tag)
#define	dtlb_tag_val(dtlb_tag)		tlb_tag_val(dtlb_tag)
#define	itlb_tag_val(itlb_tag)		tlb_tag_val(itlb_tag)

#define	__tlb_tag(tlb_tag_val)		(tlb_tag_val)
#define	__dtlb_tag(dtlb_tag_val)	__tlb_tag(dtlb_tag_val)
#define	__itlb_tag(dtlb_tag_val)	__tlb_tag(itlb_tag_val)

#define	_TLB_TAG_VA_TAG_SHIFT		7	/* [35: 7] */
#define	_TLB_TAG_CONTEXT_SHIFT		36	/* [47:36] */

#define _TLB_TAG_VA_TAG		0x0000000fffffff80	/* tag of virtual */
							/* address [47:19] */
							/* [18:12] - line # */
#define _TLB_TAG_CONTEXT	0x0000fff000000000	/* context # */
#define _TLB_TAG_ROOT		0x0001000000000000	/* should be 0 */
#define _TLB_TAG_PHYS		0x0002000000000000	/* should be 0 */
#define _TLB_TAG_G		0x0004000000000000	/* global page */
#define _TLB_TAG_USED		0x0008000000000000	/* used flag */
#define _TLB_TAG_VALID		0x0010000000000000	/* valid bit */

#define	TLB_VADDR_TO_VA_TAG(virt_addr)	\
		((((virt_addr) >> PAGE_SHIFT) & _TLB_TAG_VA_TAG) << \
		_TLB_TAG_VA_TAG_SHIFT)

#define _TLB_TAG_KERNEL_IMAGE		(_TLB_TAG_VALID | _TLB_TAG_USED | \
		((long)E2K_KERNEL_CONTEXT << _TLB_TAG_CONTEXT_SHIFT))
#define	_TLB_KERNEL_SWITCHING_IMAGE	_TLB_TAG_KERNEL_IMAGE
#define	_TLB_KERNEL_US_STACK		(_TLB_TAG_VALID | _TLB_TAG_USED | \
		((long)E2K_KERNEL_CONTEXT << _TLB_TAG_CONTEXT_SHIFT))

#define	TLB_KERNEL_SWITCHING_TEXT	__tlb_tag(_TLB_KERNEL_SWITCHING_IMAGE)
#define	TLB_KERNEL_SWITCHING_DATA	__tlb_tag(_TLB_KERNEL_SWITCHING_IMAGE)
#define	TLB_KERNEL_SWITCHING_US_STACK	__tlb_tag(_TLB_KERNEL_US_STACK)

#define	tlb_tag_get_va_tag(tlb_tag)	\
		(tlb_tag_val(tlb_tag) & _TLB_TAG_VA_TAG)
#define	tlb_tag_set_va_tag(tlb_tag, va_page)	\
		(__tlb_tag((tlb_tag_val(tlb_tag) & ~_TLB_TAG_VA_TAG) | \
		((va_page) & _TLB_TAG_VA_TAG)))
#define	tlb_tag_set_vaddr_va_tag(tlb_tag, virt_addr)	\
		(__tlb_tag((tlb_tag_val(tlb_tag) & ~_TLB_TAG_VA_TAG) | \
		TLB_VADDR_TO_VA_TAG(virt_addr)))

#define	tlb_tag_get_context(tlb_tag)	\
		(tlb_tag_val(tlb_tag) & _TLB_TAG_CONTEXT)
#define	tlb_tag_set_context(tlb_tag, context)	\
		(__tlb_tag((tlb_tag_val(tlb_tag) & ~_TLB_TAG_CONTEXT) | \
		((context) << _TLB_TAG_CONTEXT_SHIFT) & _TLB_TAG_CONTEXT))

/*
 * This takes a virtual page address and protection bits to make
 * TLB tag: tlb_tag_t
 */
#define mk_tlb_tag_vaddr(virt_addr, tag_pgprot) \
	(__tlb_tag(TLB_VADDR_TO_VA_TAG(virt_addr) | tlb_tag_val(tag_pgprot)))

/* DTLB/ITLB entry structure is the same as PTE structure of page tables */

/*
 * TLB address probe operations , TLB Entry_probe operations
 */

/* Virtual address for TLB address probe & Entry probe operations */
#ifndef __ASSEMBLY__
typedef	e2k_addr_t			probe_addr_t;

#define	probe_addr_val(probe_addr)	(probe_addr)

#define	__probe_addr(probe_addr_val)	(probe_addr_val)
#endif /* __ASSEMBLY__ */

#define _PROBE_ADDR_VA		0x0000ffffffffffff	/* virtual address */
							/* [47: 0] */

/* Result of TLB Entry probe operation */
#ifndef __ASSEMBLY__
typedef	unsigned long			probe_entry_t;

#define	probe_entry_val(probe_entry)	(probe_entry)

#define	__probe_entry(probe_entry_val)	(probe_entry_val)

#include <asm/pgtable_types.h>
#include <asm/mmu-regs-types-v2.h>
#include <asm/mmu-regs-types-v6.h>

#if	DTLB_ENTRY_PH_BOUND_V2 == DTLB_ENTRY_PH_BOUND_V6
# define DTLB_ENTRY_PH_BOUND	DTLB_ENTRY_PH_BOUND_V6
#else
# error	"Page table PH_BOUND bit is different for V2 vs V6"
#endif
#if	DTLB_ENTRY_ILLEGAL_PAGE_V2 == DTLB_ENTRY_ILLEGAL_PAGE_V6
# define DTLB_ENTRY_ILLEGAL_PAGE DTLB_ENTRY_ILLEGAL_PAGE_V6
#else
# error	"Page table ILLEGAL_PAGE bit is different for V2 vs V6"
#endif
#if	DTLB_ENTRY_PAGE_MISS_V2 == DTLB_ENTRY_PAGE_MISS_V6
# define DTLB_ENTRY_PAGE_MISS	DTLB_ENTRY_PAGE_MISS_V6
#else
# error	"Page table PAGE_MISS bit is different for V2 vs V6"
#endif

static inline probe_entry_t
mmu_fill_dtlb_val_flags(const uni_dtlb_t uni_flags, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return fill_dtlb_val_v6_flags(uni_flags);
	else
		return fill_dtlb_val_v2_flags(uni_flags);
}
static inline probe_entry_t
mmu_get_dtlb_val_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags,
			bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return get_dtlb_val_v6_flags(dtlb_val, uni_flags);
	else
		return get_dtlb_val_v2_flags(dtlb_val, uni_flags);
}
static inline bool
mmu_test_dtlb_val_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags,
			bool mmu_pt_v6)
{
	return mmu_get_dtlb_val_flags(dtlb_val, uni_flags, mmu_pt_v6) != 0;
}
static inline probe_entry_t
mmu_set_dtlb_val_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags,
			bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return set_dtlb_val_v6_flags(dtlb_val, uni_flags);
	else
		return set_dtlb_val_v2_flags(dtlb_val, uni_flags);
}
static inline probe_entry_t
mmu_clear_dtlb_val_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags,
			bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return clear_dtlb_val_v6_flags(dtlb_val, uni_flags);
	else
		return clear_dtlb_val_v2_flags(dtlb_val, uni_flags);
}
static inline probe_entry_t
fill_dtlb_val_flags(const uni_dtlb_t uni_flags)
{
	return mmu_fill_dtlb_val_flags(uni_flags, MMU_IS_DTLB_V6());
}
static inline probe_entry_t
get_dtlb_val_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags)
{
	return mmu_get_dtlb_val_flags(dtlb_val, uni_flags, MMU_IS_DTLB_V6());
}
static inline bool
test_dtlb_val_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags)
{
	return mmu_test_dtlb_val_flags(dtlb_val, uni_flags, MMU_IS_DTLB_V6());
}
static inline probe_entry_t
set_dtlb_val_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags)
{
	return mmu_set_dtlb_val_flags(dtlb_val, uni_flags, MMU_IS_DTLB_V6());
}
static inline probe_entry_t
clear_dtlb_val_flags(probe_entry_t dtlb_val, const uni_dtlb_t uni_flags)
{
	return mmu_clear_dtlb_val_flags(dtlb_val, uni_flags, MMU_IS_DTLB_V6());
}
#define	DTLB_ENTRY_INIT(uni_flags)		fill_dtlb_val_flags(uni_flags)
#define	DTLB_ENTRY_GET(dtlb_val, uni_flags)	\
		get_dtlb_val_flags(dtlb_val, uni_flags)
#define	DTLB_ENTRY_TEST(dtlb_val, uni_flags)	\
		test_dtlb_val_flags(dtlb_val, uni_flags)
#define	DTLB_ENTRY_SET(dtlb_val, uni_flags)	\
		set_dtlb_val_flags(dtlb_val, uni_flags)
#define	DTLB_ENTRY_CLEAR(dtlb_val, uni_flags)	\
		clear_dtlb_val_flags(dtlb_val, uni_flags)

#define	DTLB_ENTRY_ERROR_MASK	DTLB_ENTRY_INIT(UNI_DTLB_ERROR_MASK)
#define	DTLB_ENTRY_MISS_LEVEL_MASK	\
				DTLB_ENTRY_INIT(UNI_DTLB_MISS_LEVEL)
#define	DTLB_ENTRY_PROBE_SUCCESSFUL	\
				DTLB_ENTRY_INIT(UNI_DTLB_SUCCESSFUL)
#define	DTLB_ENTRY_RES_BITS	DTLB_ENTRY_INIT(UNI_DTLB_RES_BITS)
#define	DTLB_ENTRY_WR		DTLB_ENTRY_INIT(UNI_PAGE_WRITE)
#define	DTLB_ENTRY_PV		DTLB_ENTRY_INIT(UNI_PAGE_PRIV)
#define	DTLB_ENTRY_VVA		DTLB_ENTRY_INIT(UNI_PAGE_VALID)
#define	DTLB_EP_RES		DTLB_ENTRY_INIT(UNI_DTLB_EP_RES)
#define	DTLB_EP_FAULT_RES	(~DTLB_EP_RES)
#define	DTLB_ENTRY_TEST_WRITEABLE(dtlb_val)	\
		DTLB_ENTRY_TEST(dtlb_val, UNI_PAGE_WRITE)
#define	DTLB_ENTRY_TEST_VVA(dtlb_val)	\
		DTLB_ENTRY_TEST(dtlb_val, UNI_PAGE_VALID)
#define	DTLB_ENTRY_TEST_SUCCESSFUL(dtlb_val)	\
		((MMU_IS_DTLB_V6()) ? \
			DTLB_ENTRY_TEST(dtlb_val, UNI_DTLB_SUCCESSFUL) \
			: \
			!DTLB_ENTRY_TEST(dtlb_val, UNI_DTLB_SUCCESSFUL))

static inline probe_entry_t
mmu_phys_addr_to_dtlb_pha(e2k_addr_t phys_addr, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return PA_TO_DTLB_ENTRY_PHA_V6(phys_addr);
	else
		return PA_TO_DTLB_ENTRY_PHA_V2(phys_addr);
}
static inline e2k_addr_t
mmu_dtlb_pha_to_phys_addr(probe_entry_t dtlb_val, bool mmu_pt_v6)
{
	if (mmu_pt_v6)
		return DTLB_ENTRY_PHA_TO_PA_V6(dtlb_val);
	else
		return DTLB_ENTRY_PHA_TO_PA_V2(dtlb_val);
}

static inline probe_entry_t
phys_addr_to_dtlb_pha(e2k_addr_t phys_addr)
{
	return mmu_phys_addr_to_dtlb_pha(phys_addr, MMU_IS_DTLB_V6());
}
static inline e2k_addr_t
dtlb_pha_to_phys_addr(probe_entry_t dtlb_val)
{
	return mmu_dtlb_pha_to_phys_addr(dtlb_val, MMU_IS_DTLB_V6());
}
#define	PA_TO_DTLB_ENTRY_PHA(phys_addr)	phys_addr_to_dtlb_pha(phys_addr)
#define	DTLB_ENTRY_PHA_TO_PA(dtlb_val)	dtlb_pha_to_phys_addr(dtlb_val)

/* physical memory bound (x86)	[63] */
#define	PH_BOUND_EP_RES		DTLB_ENTRY_PH_BOUND
/* illegal page			[62] */
#define	ILLEGAL_PAGE_EP_RES	DTLB_ENTRY_ILLEGAL_PAGE
/* page miss			[61] */
#define	PAGE_MISS_EP_RES	DTLB_ENTRY_PAGE_MISS
/* miss level			[60:59] */
#define	MISS_LEVEL_EP_RES	DTLB_ENTRY_MISS_LEVEL_MASK
/* reserved bits		[57] */
#define	RES_BITS_EP_RES		DTLB_ENTRY_RES_BITS

/*
 * DTLB address probe result format
 */
/* Physical address of successfull DTLB address probe [39: 0]/[47:0] */
#define	PH_ADDR_AP_RES		DTLB_ENTRY_INIT(UNI_DTLB_PH_ADDR_AP_RES)
/* AP disable result		[62] */
#define	DISABLE_AP_RES		ILLEGAL_PAGE_EP_RES
/* page miss			[61] */
#define	PAGE_MISS_AP_RES	PAGE_MISS_EP_RES
/* illegal page			[58] */
#define	ILLEGAL_PAGE_AP_RES	ILLEGAL_PAGE_EP_RES

#define	PH_ADDR_IS_PRESENT(ap_res)	(((ap_res) & ~PH_ADDR_AP_RES) == 0)
#define	PH_ADDR_IS_MISS(ap_res)		((ap_res) & PAGE_MISS_AP_RES)
#define	PH_ADDR_IS_VALID(ap_res)	((PH_ADDR_IS_PRESENT(ap_res) || \
						PH_ADDR_IS_MISS(ap_res)))
#define	PH_ADDR_IS_INVALID(ap_res)	((ap_res) & ILLEGAL_PAGE_AP_RES)
#define	GET_PROBE_PH_ADDR(ap_res)	((ap_res) & PH_ADDR_AP_RES)\

#if	!defined(CONFIG_PARAVIRT_GUEST) && !defined(CONFIG_KVM_GUEST_KERNEL)
/* it is native kernel without any virtualization */
/* or it is native host kernel with virtualization support */
#elif	defined(CONFIG_KVM_GUEST_KERNEL)
/* it is pure guest kernel (not paravirtualized based on pv_ops) */
#include <asm/kvm/guest/tlb_regs_types.h>
#elif	defined(CONFIG_PARAVIRT_GUEST)
/* it is paravirtualized host and guest kernel */
#include <asm/paravirt/mmu.h>
#else
 #error	"Unknown virtualization type"
#endif	/* ! CONFIG_PARAVIRT_GUEST && ! CONFIG_KVM_GUEST_KERNEL */

#endif /* __ASSEMBLY__ */

#endif
