/* SPDX-License-Identifier: GPL-2.0 */
/*
 * ultra.S: Don't expand these all over the place...
 *
 * Copyright (C) 1997, 2000, 2008 David S. Miller (davem@davemloft.net)
 */

#include <asm/asi.h>
#include <asm/pgtable.h>
#include <asm/page.h>
#include <asm/spitfire.h>
#include <asm/mmu_context.h>
#include <asm/mmu.h>
#include <asm/pil.h>
#include <asm/head.h>
#include <asm/thread_info.h>
#include <asm/cacheflush.h>
#include <asm/hypervisor.h>
#include <asm/cpudata.h>
#ifdef CONFIG_E90S
#include <asm/ttable.h>
#include <asm/e90s.h>
#include <asm/epicdef.h>
#endif /*CONFIG_E90S*/

	/* Basically, most of the Spitfire vs. Cheetah madness
	 * has to do with the fact that Cheetah does not support
	 * IMMU flushes out of the secondary context.  Someone needs
	 * to throw a south lake birthday party for the folks
	 * in Microelectronics who refused to fix this shit.
	 */

	/* This file is meant to be read efficiently by the CPU, not humans.
	 * Staraj sie tego nikomu nie pierdolnac...
	 */
	.text
	.align		32
	.globl		__flush_tlb_mm
__flush_tlb_mm:		/* 19 insns */
	/* %o0=(ctx & TAG_CONTEXT_BITS), %o1=SECONDARY_CONTEXT */
	ldxa		[%o1] ASI_DMMU, %g2
	cmp		%g2, %o0
	bne,pn		%icc, __spitfire_flush_tlb_mm_slow
	 mov		0x50, %g3
	stxa		%g0, [%g3] ASI_DMMU_DEMAP
	stxa		%g0, [%g3] ASI_IMMU_DEMAP
	sethi		%hi(KERNBASE), %g3
	flush		%g3
	retl
	 nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
#ifdef CONFIG_MCST
	nop
#endif

	.align		32
	.globl		__flush_tlb_page
__flush_tlb_page:	/* 22 insns */
	/* %o0 = context, %o1 = vaddr */
	rdpr		%pstate, %g7
	andn		%g7, PSTATE_IE, %g2
	wrpr		%g2, %pstate
	mov		SECONDARY_CONTEXT, %o4
	ldxa		[%o4] ASI_DMMU, %g2
	stxa		%o0, [%o4] ASI_DMMU
	andcc		%o1, 1, %g0
	andn		%o1, 1, %o3
	be,pn		%icc, 1f
	 or		%o3, 0x10, %o3
	stxa		%g0, [%o3] ASI_IMMU_DEMAP
1:	stxa		%g0, [%o3] ASI_DMMU_DEMAP
	membar		#Sync
	stxa		%g2, [%o4] ASI_DMMU
	sethi		%hi(KERNBASE), %o4
	flush		%o4
	retl
	 wrpr		%g7, 0x0, %pstate
	nop
	nop
	nop
	nop

	.align		32
	.globl		__flush_tlb_pending
__flush_tlb_pending:	/* 27 insns */
	/* %o0 = context, %o1 = nr, %o2 = vaddrs[] */
	rdpr		%pstate, %g7
	sllx		%o1, 3, %o1
	andn		%g7, PSTATE_IE, %g2
	wrpr		%g2, %pstate
	mov		SECONDARY_CONTEXT, %o4
	ldxa		[%o4] ASI_DMMU, %g2
	stxa		%o0, [%o4] ASI_DMMU
1:	sub		%o1, (1 << 3), %o1
	ldx		[%o2 + %o1], %o3
	andcc		%o3, 1, %g0
	andn		%o3, 1, %o3
	be,pn		%icc, 2f
	 or		%o3, 0x10, %o3
	stxa		%g0, [%o3] ASI_IMMU_DEMAP
2:	stxa		%g0, [%o3] ASI_DMMU_DEMAP
	membar		#Sync
	brnz,pt		%o1, 1b
	 nop
	stxa		%g2, [%o4] ASI_DMMU
	sethi		%hi(KERNBASE), %o4
	flush		%o4
	retl
	 wrpr		%g7, 0x0, %pstate
	nop
	nop
	nop
	nop

	.align		32
	.globl		__flush_tlb_kernel_range
__flush_tlb_kernel_range:	/* 31 insns */
	/* %o0=start, %o1=end */
	cmp		%o0, %o1
	be,pn		%xcc, 2f
	 sub		%o1, %o0, %o3
	srlx		%o3, 18, %o4
	brnz,pn		%o4, __spitfire_flush_tlb_kernel_range_slow
	 sethi		%hi(PAGE_SIZE), %o4
	sub		%o3, %o4, %o3
	or		%o0, 0x20, %o0		! Nucleus
1:	stxa		%g0, [%o0 + %o3] ASI_DMMU_DEMAP
	stxa		%g0, [%o0 + %o3] ASI_IMMU_DEMAP
	membar		#Sync
	brnz,pt		%o3, 1b
	 sub		%o3, %o4, %o3
2:	sethi		%hi(KERNBASE), %o3
	flush		%o3
	retl
	 nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

__spitfire_flush_tlb_kernel_range_slow:
	mov		63 * 8, %o4
1:	ldxa		[%o4] ASI_ITLB_DATA_ACCESS, %o3
	andcc		%o3, 0x40, %g0			/* _PAGE_L_4U */
	bne,pn		%xcc, 2f
	 mov		TLB_TAG_ACCESS, %o3
	stxa		%g0, [%o3] ASI_IMMU
	stxa		%g0, [%o4] ASI_ITLB_DATA_ACCESS
	membar		#Sync
2:	ldxa		[%o4] ASI_DTLB_DATA_ACCESS, %o3
	andcc		%o3, 0x40, %g0
	bne,pn		%xcc, 2f
	 mov		TLB_TAG_ACCESS, %o3
	stxa		%g0, [%o3] ASI_DMMU
	stxa		%g0, [%o4] ASI_DTLB_DATA_ACCESS
	membar		#Sync
2:	sub		%o4, 8, %o4
	brgez,pt	%o4, 1b
	 nop
	retl
	 nop

__spitfire_flush_tlb_mm_slow:
	rdpr		%pstate, %g1
	wrpr		%g1, PSTATE_IE, %pstate
	stxa		%o0, [%o1] ASI_DMMU
	stxa		%g0, [%g3] ASI_DMMU_DEMAP
	stxa		%g0, [%g3] ASI_IMMU_DEMAP
	flush		%g6
	stxa		%g2, [%o1] ASI_DMMU
	sethi		%hi(KERNBASE), %o1
	flush		%o1
	retl
	 wrpr		%g1, 0, %pstate

/*
 * The following code flushes one page_size worth.
 */
	.section .kprobes.text, "ax"
	.align		32
	.globl		__flush_icache_page
__flush_icache_page:	/* %o0 = phys_page */
#ifdef	CONFIG_RMO
	membar		#StoreStore
#endif	/* CONFIG_RMO */
	srlx		%o0, PAGE_SHIFT, %o0
	sethi		%hi(PAGE_OFFSET), %g1
	sllx		%o0, PAGE_SHIFT, %o0
	sethi		%hi(PAGE_SIZE), %g2
	ldx		[%g1 + %lo(PAGE_OFFSET)], %g1
	add		%o0, %g1, %o0
1:	subcc		%g2, 32, %g2
	bne,pt		%icc, 1b
	 flush		%o0 + %g2
	retl
	 nop

#ifdef DCACHE_ALIASING_POSSIBLE

#if (PAGE_SHIFT != 13)
#error only page shift of 13 is supported by dcache flush
#endif

#define DTAG_MASK 0x3

	/* This routine is Spitfire specific so the hardcoded
	 * D-cache size and line-size are OK.
	 */
	.align		64
	.globl		__flush_dcache_page
__flush_dcache_page:	/* %o0=kaddr, %o1=flush_icache */
	sethi		%hi(PAGE_OFFSET), %g1
	ldx		[%g1 + %lo(PAGE_OFFSET)], %g1
	sub		%o0, %g1, %o0			! physical address
	srlx		%o0, 11, %o0			! make D-cache TAG
	sethi		%hi(1 << 14), %o2		! D-cache size
	sub		%o2, (1 << 5), %o2		! D-cache line size
1:	ldxa		[%o2] ASI_DCACHE_TAG, %o3	! load D-cache TAG
	andcc		%o3, DTAG_MASK, %g0		! Valid?
	be,pn		%xcc, 2f			! Nope, branch
	 andn		%o3, DTAG_MASK, %o3		! Clear valid bits
	cmp		%o3, %o0			! TAG match?
	bne,pt		%xcc, 2f			! Nope, branch
	 nop
	stxa		%g0, [%o2] ASI_DCACHE_TAG	! Invalidate TAG
	membar		#Sync
2:	brnz,pt		%o2, 1b
	 sub		%o2, (1 << 5), %o2		! D-cache line size

	/* The I-cache does not snoop local stores so we
	 * better flush that too when necessary.
	 */
	brnz,pt		%o1, __flush_icache_page
	 sllx		%o0, 11, %o0
	retl
	 nop

#endif /* DCACHE_ALIASING_POSSIBLE */

	.previous

	/* Cheetah specific versions, patched at boot time. */
__cheetah_flush_tlb_mm: /* 19 insns */
	rdpr		%pstate, %g7
	andn		%g7, PSTATE_IE, %g2
	wrpr		%g2, 0x0, %pstate
	wrpr		%g0, 1, %tl
	mov		PRIMARY_CONTEXT, %o2
	mov		0x40, %g3
	ldxa		[%o2] ASI_DMMU, %g2
	srlx		%g2, CTX_PGSZ1_NUC_SHIFT, %o1
	sllx		%o1, CTX_PGSZ1_NUC_SHIFT, %o1
	or		%o0, %o1, %o0	/* Preserve nucleus page size fields */
	stxa		%o0, [%o2] ASI_DMMU
	stxa		%g0, [%g3] ASI_DMMU_DEMAP
	stxa		%g0, [%g3] ASI_IMMU_DEMAP
	stxa		%g2, [%o2] ASI_DMMU
	sethi		%hi(KERNBASE), %o2
	flush		%o2
	wrpr		%g0, 0, %tl
	retl
	 wrpr		%g7, 0x0, %pstate

#ifdef CONFIG_MCST
__e90s_r2000_with_bug_flush_tlb_mm: /* 20 insns */
	/* %o0=(ctx & TAG_CONTEXT_BITS), %o1=SECONDARY_CONTEXT */
	rdpr		%pstate, %g7
	andn		%g7, PSTATE_IE, %g2
	wrpr		%g2, 0x0, %pstate
	wrpr		%g0, 1, %tl
	mov		PRIMARY_CONTEXT, %o2
	mov		0x40, %g3
	mov		0x90, %o3
	ldxa		[%o2] ASI_DMMU, %g2
	srlx		%g2, CTX_PGSZ1_NUC_SHIFT, %o1
	sllx		%o1, CTX_PGSZ1_NUC_SHIFT, %o1
	or		%o0, %o1, %o0	/* Preserve nucleus page size fields */
	stxa		%o0, [%o2] ASI_DMMU
	stxa		%g0, [%g3] ASI_DMMU_DEMAP
	stxa		%g0, [%o3] ASI_IMMU_DEMAP
	stxa		%g2, [%o2] ASI_DMMU
	sethi		%hi(KERNBASE), %o2
	flush		%o2
	wrpr		%g0, 0, %tl
	retl
	 wrpr		%g7, 0x0, %pstate

e90_fix_fast_instruction_access_MMU_miss_hw_bug: /* 3 * 8 insns */
	rdpr	%tl, %g1
	cmp	%g1, 2
	bne	1f
	nop
	wrpr	1, %tl
	nop
	retry
	nop

	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

1:	BTRAPTL1(0x64)

e90_fix_tt0_hw_bug: /* 8 insns */
	rdpr	%tpc, %g7
	brz	%g7, 1f
	 nop
	retry

	nop
1:	udiv	%g0, %g0, %g0
	nop
	nop
#endif

__cheetah_flush_tlb_page:	/* 22 insns */
	/* %o0 = context, %o1 = vaddr */
	rdpr		%pstate, %g7
	andn		%g7, PSTATE_IE, %g2
	wrpr		%g2, 0x0, %pstate
	wrpr		%g0, 1, %tl
	mov		PRIMARY_CONTEXT, %o4
	ldxa		[%o4] ASI_DMMU, %g2
	srlx		%g2, CTX_PGSZ1_NUC_SHIFT, %o3
	sllx		%o3, CTX_PGSZ1_NUC_SHIFT, %o3
	or		%o0, %o3, %o0	/* Preserve nucleus page size fields */
	stxa		%o0, [%o4] ASI_DMMU
	andcc		%o1, 1, %g0
	be,pn		%icc, 1f
	 andn		%o1, 1, %o3
	stxa		%g0, [%o3] ASI_IMMU_DEMAP
1:	stxa		%g0, [%o3] ASI_DMMU_DEMAP
	membar		#Sync
	stxa		%g2, [%o4] ASI_DMMU
	sethi		%hi(KERNBASE), %o4
	flush		%o4
	wrpr		%g0, 0, %tl
	retl
	 wrpr		%g7, 0x0, %pstate

__cheetah_flush_tlb_pending:	/* 27 insns */
	/* %o0 = context, %o1 = nr, %o2 = vaddrs[] */
	rdpr		%pstate, %g7
	sllx		%o1, 3, %o1
	andn		%g7, PSTATE_IE, %g2
	wrpr		%g2, 0x0, %pstate
	wrpr		%g0, 1, %tl
	mov		PRIMARY_CONTEXT, %o4
	ldxa		[%o4] ASI_DMMU, %g2
	srlx		%g2, CTX_PGSZ1_NUC_SHIFT, %o3
	sllx		%o3, CTX_PGSZ1_NUC_SHIFT, %o3
	or		%o0, %o3, %o0	/* Preserve nucleus page size fields */
	stxa		%o0, [%o4] ASI_DMMU
1:	sub		%o1, (1 << 3), %o1
	ldx		[%o2 + %o1], %o3
	andcc		%o3, 1, %g0
	be,pn		%icc, 2f
	 andn		%o3, 1, %o3
	stxa		%g0, [%o3] ASI_IMMU_DEMAP
2:	stxa		%g0, [%o3] ASI_DMMU_DEMAP
	membar		#Sync
	brnz,pt		%o1, 1b
	 nop
	stxa		%g2, [%o4] ASI_DMMU
	sethi		%hi(KERNBASE), %o4
	flush		%o4
	wrpr		%g0, 0, %tl
	retl
	 wrpr		%g7, 0x0, %pstate

__cheetah_flush_tlb_kernel_range:	/* 31 insns */
	/* %o0=start, %o1=end */
	cmp		%o0, %o1
	be,pn		%xcc, 2f
	 sub		%o1, %o0, %o3
	srlx		%o3, 18, %o4
	brnz,pn		%o4, 3f
	 sethi		%hi(PAGE_SIZE), %o4
	sub		%o3, %o4, %o3
	or		%o0, 0x20, %o0		! Nucleus
1:	stxa		%g0, [%o0 + %o3] ASI_DMMU_DEMAP
	stxa		%g0, [%o0 + %o3] ASI_IMMU_DEMAP
	membar		#Sync
	brnz,pt		%o3, 1b
	 sub		%o3, %o4, %o3
2:	sethi		%hi(KERNBASE), %o3
	flush		%o3
	retl
	 nop
3:	mov		0x80, %o4
	stxa		%g0, [%o4] ASI_DMMU_DEMAP
	membar		#Sync
	stxa		%g0, [%o4] ASI_IMMU_DEMAP
	membar		#Sync
	retl
	 nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

#ifdef DCACHE_ALIASING_POSSIBLE
__cheetah_flush_dcache_page: /* 11 insns */
	sethi		%hi(PAGE_OFFSET), %g1
	ldx		[%g1 + %lo(PAGE_OFFSET)], %g1
	sub		%o0, %g1, %o0
	sethi		%hi(PAGE_SIZE), %o4
1:	subcc		%o4, (1 << 5), %o4
	stxa		%g0, [%o0 + %o4] ASI_DCACHE_INVALIDATE
	membar		#Sync
	bne,pt		%icc, 1b
	 nop
	retl		/* I-cache flush never needed on Cheetah, see callers. */
	 nop
#endif /* DCACHE_ALIASING_POSSIBLE */

#ifdef	CONFIG_SPARC64_SUN4V
	/* Hypervisor specific versions, patched at boot time.  */
__hypervisor_tlb_tl0_error:
	save		%sp, -192, %sp
	mov		%i0, %o0
	call		hypervisor_tlbop_error
	 mov		%i1, %o1
	ret
	 restore

__hypervisor_flush_tlb_mm: /* 19 insns */
	mov		%o0, %o2	/* ARG2: mmu context */
	mov		0, %o0		/* ARG0: CPU lists unimplemented */
	mov		0, %o1		/* ARG1: CPU lists unimplemented */
	mov		HV_MMU_ALL, %o3	/* ARG3: flags */
	mov		HV_FAST_MMU_DEMAP_CTX, %o5
	ta		HV_FAST_TRAP
	brnz,pn		%o0, 1f
	 mov		HV_FAST_MMU_DEMAP_CTX, %o1
	retl
	 nop
1:	sethi		%hi(__hypervisor_tlb_tl0_error), %o5
	jmpl		%o5 + %lo(__hypervisor_tlb_tl0_error), %g0
	 nop
	nop
	nop
	nop
	nop
	nop
	nop

__hypervisor_flush_tlb_page: /* 22 insns */
	/* %o0 = context, %o1 = vaddr */
	mov		%o0, %g2
	mov		%o1, %o0              /* ARG0: vaddr + IMMU-bit */
	mov		%g2, %o1	      /* ARG1: mmu context */
	mov		HV_MMU_ALL, %o2	      /* ARG2: flags */
	srlx		%o0, PAGE_SHIFT, %o0
	sllx		%o0, PAGE_SHIFT, %o0
	ta		HV_MMU_UNMAP_ADDR_TRAP
	brnz,pn		%o0, 1f
	 mov		HV_MMU_UNMAP_ADDR_TRAP, %o1
	retl
	 nop
1:	sethi		%hi(__hypervisor_tlb_tl0_error), %o2
	jmpl		%o2 + %lo(__hypervisor_tlb_tl0_error), %g0
	 nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

__hypervisor_flush_tlb_pending: /* 27 insns */
	/* %o0 = context, %o1 = nr, %o2 = vaddrs[] */
	sllx		%o1, 3, %g1
	mov		%o2, %g2
	mov		%o0, %g3
1:	sub		%g1, (1 << 3), %g1
	ldx		[%g2 + %g1], %o0      /* ARG0: vaddr + IMMU-bit */
	mov		%g3, %o1	      /* ARG1: mmu context */
	mov		HV_MMU_ALL, %o2	      /* ARG2: flags */
	srlx		%o0, PAGE_SHIFT, %o0
	sllx		%o0, PAGE_SHIFT, %o0
	ta		HV_MMU_UNMAP_ADDR_TRAP
	brnz,pn		%o0, 1f
	 mov		HV_MMU_UNMAP_ADDR_TRAP, %o1
	brnz,pt		%g1, 1b
	 nop
	retl
	 nop
1:	sethi		%hi(__hypervisor_tlb_tl0_error), %o2
	jmpl		%o2 + %lo(__hypervisor_tlb_tl0_error), %g0
	 nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

__hypervisor_flush_tlb_kernel_range: /* 31 insns */
	/* %o0=start, %o1=end */
	cmp		%o0, %o1
	be,pn		%xcc, 2f
	 sub		%o1, %o0, %g2
	srlx		%g2, 18, %g3
	brnz,pn		%g3, 4f
	 mov		%o0, %g1
	sethi		%hi(PAGE_SIZE), %g3
	sub		%g2, %g3, %g2
1:	add		%g1, %g2, %o0	/* ARG0: virtual address */
	mov		0, %o1		/* ARG1: mmu context */
	mov		HV_MMU_ALL, %o2	/* ARG2: flags */
	ta		HV_MMU_UNMAP_ADDR_TRAP
	brnz,pn		%o0, 3f
	 mov		HV_MMU_UNMAP_ADDR_TRAP, %o1
	brnz,pt		%g2, 1b
	 sub		%g2, %g3, %g2
2:	retl
	 nop
3:	sethi		%hi(__hypervisor_tlb_tl0_error), %o2
	jmpl		%o2 + %lo(__hypervisor_tlb_tl0_error), %g0
	 nop
4:	mov		0, %o0		/* ARG0: CPU lists unimplemented */
	mov		0, %o1		/* ARG1: CPU lists unimplemented */
	mov		0, %o2		/* ARG2: mmu context == nucleus */
	mov		HV_MMU_ALL, %o3	/* ARG3: flags */
	mov		HV_FAST_MMU_DEMAP_CTX, %o5
	ta		HV_FAST_TRAP
	brnz,pn		%o0, 3b
	 mov		HV_FAST_MMU_DEMAP_CTX, %o1
	retl
	 nop

#ifdef DCACHE_ALIASING_POSSIBLE
	/* XXX Niagara and friends have an 8K cache, so no aliasing is
	 * XXX possible, but nothing explicit in the Hypervisor API
	 * XXX guarantees this.
	 */
__hypervisor_flush_dcache_page:	/* 2 insns */
	retl
	 nop
#endif
#endif	/*CONFIG_SPARC64_SUN4V*/

tlb_patch_one:
1:	lduw		[%o1], %g1
	stw		%g1, [%o0]
	flush		%o0
	subcc		%o2, 1, %o2
	add		%o1, 4, %o1
	bne,pt		%icc, 1b
	 add		%o0, 4, %o0
	retl
	 nop

#ifdef CONFIG_SMP
	/* These are all called by the slaves of a cross call, at
	 * trap level 1, with interrupts fully disabled.
	 *
	 * Register usage:
	 *   %g5	mm->context	(all tlb flushes)
	 *   %g1	address arg 1	(tlb page and range flushes)
	 *   %g7	address arg 2	(tlb range flush only)
	 *
	 *   %g6	scratch 1  (unusable for e90s)
	 *   %g2	scratch 2
	 *   %g3	scratch 3
	 *   %g4	scratch 4
	 */
	.align		32
	.globl		xcall_flush_tlb_mm
xcall_flush_tlb_mm:	/* 24 insns */
	mov		PRIMARY_CONTEXT, %g2
	ldxa		[%g2] ASI_DMMU, %g3
	srlx		%g3, CTX_PGSZ1_NUC_SHIFT, %g4
	sllx		%g4, CTX_PGSZ1_NUC_SHIFT, %g4
	or		%g5, %g4, %g5	/* Preserve nucleus page size fields */
	stxa		%g5, [%g2] ASI_DMMU
	mov		0x40, %g4
	stxa		%g0, [%g4] ASI_DMMU_DEMAP
	stxa		%g0, [%g4] ASI_IMMU_DEMAP
	stxa		%g3, [%g2] ASI_DMMU
	retry
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

#ifdef CONFIG_E90S
	.align		32
__e90s_r2000_with_bug_xcall_flush_tlb_mm:	/* 21 insns */
	mov		PRIMARY_CONTEXT, %g2
	ldxa		[%g2] ASI_DMMU, %g3
	srlx		%g3, CTX_PGSZ1_NUC_SHIFT, %g4
	sllx		%g4, CTX_PGSZ1_NUC_SHIFT, %g4
	or		%g5, %g4, %g5	/* Preserve nucleus page size fields */
	stxa		%g5, [%g2] ASI_DMMU
	mov		0x40, %g4
	mov		0x90, %g5
	stxa		%g0, [%g4] ASI_DMMU_DEMAP
	stxa		%g0, [%g5] ASI_IMMU_DEMAP
	stxa		%g3, [%g2] ASI_DMMU
	retry
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
#endif

	.globl		xcall_flush_tlb_page
xcall_flush_tlb_page:	/* 20 insns */
	/* %g5=context, %g1=vaddr */
	mov		PRIMARY_CONTEXT, %g4
	ldxa		[%g4] ASI_DMMU, %g2
	srlx		%g2, CTX_PGSZ1_NUC_SHIFT, %g4
	sllx		%g4, CTX_PGSZ1_NUC_SHIFT, %g4
	or		%g5, %g4, %g5
	mov		PRIMARY_CONTEXT, %g4
	stxa		%g5, [%g4] ASI_DMMU
	andcc		%g1, 0x1, %g0
	be,pn		%icc, 2f
	 andn		%g1, 0x1, %g5
	stxa		%g0, [%g5] ASI_IMMU_DEMAP
2:	stxa		%g0, [%g5] ASI_DMMU_DEMAP
	membar		#Sync
	stxa		%g2, [%g4] ASI_DMMU
	retry
	nop
	nop
	nop
	nop
	nop

	.globl		xcall_flush_tlb_kernel_range
xcall_flush_tlb_kernel_range:	/* 44 insns */
	sethi		%hi(PAGE_SIZE - 1), %g2
	or		%g2, %lo(PAGE_SIZE - 1), %g2
	andn		%g1, %g2, %g1
	andn		%g7, %g2, %g7
	sub		%g7, %g1, %g3
	srlx		%g3, 18, %g2
	brnz,pn		%g2, 2f
	 sethi		%hi(PAGE_SIZE), %g2
	sub		%g3, %g2, %g3
	or		%g1, 0x20, %g1		! Nucleus
1:	stxa		%g0, [%g1 + %g3] ASI_DMMU_DEMAP
	stxa		%g0, [%g1 + %g3] ASI_IMMU_DEMAP
	membar		#Sync
	brnz,pt		%g3, 1b
	 sub		%g3, %g2, %g3
	retry
2:	mov		63 * 8, %g1
1:	ldxa		[%g1] ASI_ITLB_DATA_ACCESS, %g2
	andcc		%g2, 0x40, %g0			/* _PAGE_L_4U */
	bne,pn		%xcc, 2f
	 mov		TLB_TAG_ACCESS, %g2
	stxa		%g0, [%g2] ASI_IMMU
	stxa		%g0, [%g1] ASI_ITLB_DATA_ACCESS
	membar		#Sync
2:	ldxa		[%g1] ASI_DTLB_DATA_ACCESS, %g2
	andcc		%g2, 0x40, %g0
	bne,pn		%xcc, 2f
	 mov		TLB_TAG_ACCESS, %g2
	stxa		%g0, [%g2] ASI_DMMU
	stxa		%g0, [%g1] ASI_DTLB_DATA_ACCESS
	membar		#Sync
2:	sub		%g1, 8, %g1
	brgez,pt	%g1, 1b
	 nop
	retry
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

	/* This runs in a very controlled environment, so we do
	 * not need to worry about BH races etc.
	 */
	.globl		xcall_sync_tick
xcall_sync_tick:

661:	rdpr		%pstate, %g2
	wrpr		%g2, PSTATE_IG | PSTATE_AG, %pstate
#ifdef	CONFIG_SPARC64_SUN4V
	.section	.sun4v_2insn_patch, "ax"
	.word		661b
	nop
	nop
	.previous
#endif	/*CONFIG_SPARC64_SUN4V*/

	rdpr		%pil, %g2
	wrpr		%g0, PIL_NORMAL_MAX, %pil
	sethi		%hi(109f), %g7
	b,pt		%xcc, etrap_irq
109:	 or		%g7, %lo(109b), %g7
#ifdef CONFIG_TRACE_IRQFLAGS
	call		trace_hardirqs_off
	 nop
#endif
	call		smp_synchronize_tick_client
	 nop
	b		rtrap_xcall
	 ldx		[%sp + PTREGS_OFF + PT_V9_TSTATE], %l1

	.globl		xcall_fetch_glob_regs
xcall_fetch_glob_regs:
	sethi		%hi(global_cpu_snapshot), %g1
	or		%g1, %lo(global_cpu_snapshot), %g1
	__GET_CPUID(%g2)
	sllx		%g2, 6, %g3
	add		%g1, %g3, %g1
	rdpr		%tstate, %g7
	stx		%g7, [%g1 + GR_SNAP_TSTATE]
	rdpr		%tpc, %g7
	stx		%g7, [%g1 + GR_SNAP_TPC]
	rdpr		%tnpc, %g7
	stx		%g7, [%g1 + GR_SNAP_TNPC]
	stx		%o7, [%g1 + GR_SNAP_O7]
	stx		%i7, [%g1 + GR_SNAP_I7]
	/* Don't try this at home kids... */
	rdpr		%cwp, %g3
	sub		%g3, 1, %g7
	wrpr		%g7, %cwp
	mov		%i7, %g7
	wrpr		%g3, %cwp
	stx		%g7, [%g1 + GR_SNAP_RPC]
	sethi		%hi(trap_block), %g7
	or		%g7, %lo(trap_block), %g7
	sllx		%g2, TRAP_BLOCK_SZ_SHIFT, %g2
	add		%g7, %g2, %g7
	ldx		[%g7 + TRAP_PER_CPU_THREAD], %g3
#ifdef	CONFIG_RMO
	membar		#StoreStore
#endif	/* CONFIG_RMO */
	stx		%g3, [%g1 + GR_SNAP_THREAD]
	retry

	.globl		xcall_fetch_glob_pmu
xcall_fetch_glob_pmu:
	sethi		%hi(global_cpu_snapshot), %g1
	or		%g1, %lo(global_cpu_snapshot), %g1
	__GET_CPUID(%g2)
	sllx		%g2, 6, %g3
	add		%g1, %g3, %g1
	rd		%pic, %g7
	stx		%g7, [%g1 + (4 * 8)]
	rd		%pcr, %g7
	stx		%g7, [%g1 + (0 * 8)]
	retry

	.globl		xcall_fetch_glob_pmu_n4
xcall_fetch_glob_pmu_n4:
	sethi		%hi(global_cpu_snapshot), %g1
	or		%g1, %lo(global_cpu_snapshot), %g1
	__GET_CPUID(%g2)
	sllx		%g2, 6, %g3
	add		%g1, %g3, %g1

	ldxa		[%g0] ASI_PIC, %g7
	stx		%g7, [%g1 + (4 * 8)]
	mov		0x08, %g3
	ldxa		[%g3] ASI_PIC, %g7
	stx		%g7, [%g1 + (5 * 8)]
	mov		0x10, %g3
	ldxa		[%g3] ASI_PIC, %g7
	stx		%g7, [%g1 + (6 * 8)]
	mov		0x18, %g3
	ldxa		[%g3] ASI_PIC, %g7
	stx		%g7, [%g1 + (7 * 8)]

	mov		%o0, %g2
	mov		%o1, %g3
	mov		%o5, %g7

	mov		HV_FAST_VT_GET_PERFREG, %o5
	mov		3, %o0
	ta		HV_FAST_TRAP
	stx		%o1, [%g1 + (3 * 8)]
	mov		HV_FAST_VT_GET_PERFREG, %o5
	mov		2, %o0
	ta		HV_FAST_TRAP
	stx		%o1, [%g1 + (2 * 8)]
	mov		HV_FAST_VT_GET_PERFREG, %o5
	mov		1, %o0
	ta		HV_FAST_TRAP
	stx		%o1, [%g1 + (1 * 8)]
	mov		HV_FAST_VT_GET_PERFREG, %o5
	mov		0, %o0
	ta		HV_FAST_TRAP
	stx		%o1, [%g1 + (0 * 8)]

	mov		%g2, %o0
	mov		%g3, %o1
	mov		%g7, %o5

	retry

__cheetah_xcall_flush_tlb_kernel_range:	/* 44 insns */
	sethi		%hi(PAGE_SIZE - 1), %g2
	or		%g2, %lo(PAGE_SIZE - 1), %g2
	andn		%g1, %g2, %g1
	andn		%g7, %g2, %g7
	sub		%g7, %g1, %g3
	srlx		%g3, 18, %g2
	brnz,pn		%g2, 2f
	 sethi		%hi(PAGE_SIZE), %g2
	sub		%g3, %g2, %g3
	or		%g1, 0x20, %g1		! Nucleus
1:	stxa		%g0, [%g1 + %g3] ASI_DMMU_DEMAP
	stxa		%g0, [%g1 + %g3] ASI_IMMU_DEMAP
	membar		#Sync
	brnz,pt		%g3, 1b
	 sub		%g3, %g2, %g3
	retry
2:	mov		0x80, %g2
	stxa		%g0, [%g2] ASI_DMMU_DEMAP
	membar		#Sync
	stxa		%g0, [%g2] ASI_IMMU_DEMAP
	membar		#Sync
	retry
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop
	nop

#ifdef DCACHE_ALIASING_POSSIBLE
	.align		32
	.globl		xcall_flush_dcache_page_cheetah
xcall_flush_dcache_page_cheetah: /* %g1 == physical page address */
	sethi		%hi(PAGE_SIZE), %g3
1:	subcc		%g3, (1 << 5), %g3
	stxa		%g0, [%g1 + %g3] ASI_DCACHE_INVALIDATE
	membar		#Sync
	bne,pt		%icc, 1b
	 nop
	retry
	nop
#endif /* DCACHE_ALIASING_POSSIBLE */

	.globl		xcall_flush_dcache_page_spitfire
xcall_flush_dcache_page_spitfire: /* %g1 == physical page address
				     %g7 == kernel page virtual address
				     %g5 == (page->mapping != NULL)  */
#ifdef DCACHE_ALIASING_POSSIBLE
	srlx		%g1, (13 - 2), %g1	! Form tag comparitor
	sethi		%hi(L1DCACHE_SIZE), %g3	! D$ size == 16K
	sub		%g3, (1 << 5), %g3	! D$ linesize == 32
1:	ldxa		[%g3] ASI_DCACHE_TAG, %g2
	andcc		%g2, 0x3, %g0
	be,pn		%xcc, 2f
	 andn		%g2, 0x3, %g2
	cmp		%g2, %g1

	bne,pt		%xcc, 2f
	 nop
	stxa		%g0, [%g3] ASI_DCACHE_TAG
	membar		#Sync
2:	cmp		%g3, 0
	bne,pt		%xcc, 1b
	 sub		%g3, (1 << 5), %g3

	brz,pn		%g5, 2f
#endif /* DCACHE_ALIASING_POSSIBLE */
	 sethi		%hi(PAGE_SIZE), %g3

1:	flush		%g7
	subcc		%g3, (1 << 5), %g3
	bne,pt		%icc, 1b
	 add		%g7, (1 << 5), %g7

2:	retry
	nop
	nop

#ifdef	CONFIG_SPARC64_SUN4V
	/* %g5:	error
	 * %g6:	tlb op
	 */
__hypervisor_tlb_xcall_error:
	mov	%g5, %g4
	mov	%g6, %g5
	ba,pt	%xcc, etrap
	 rd	%pc, %g7
	mov	%l4, %o0
	call	hypervisor_tlbop_error_xcall
	 mov	%l5, %o1
	ba,a,pt	%xcc, rtrap

	.globl		__hypervisor_xcall_flush_tlb_mm
__hypervisor_xcall_flush_tlb_mm: /* 24 insns */
	/* %g5=ctx, g1,g2,g3,g4,g7=scratch, %g6=unusable */
	mov		%o0, %g2
	mov		%o1, %g3
	mov		%o2, %g4
	mov		%o3, %g1
	mov		%o5, %g7
	clr		%o0		/* ARG0: CPU lists unimplemented */
	clr		%o1		/* ARG1: CPU lists unimplemented */
	mov		%g5, %o2	/* ARG2: mmu context */
	mov		HV_MMU_ALL, %o3	/* ARG3: flags */
	mov		HV_FAST_MMU_DEMAP_CTX, %o5
	ta		HV_FAST_TRAP
	mov		HV_FAST_MMU_DEMAP_CTX, %g6
	brnz,pn		%o0, 1f
	 mov		%o0, %g5
	mov		%g2, %o0
	mov		%g3, %o1
	mov		%g4, %o2
	mov		%g1, %o3
	mov		%g7, %o5
	membar		#Sync
	retry
1:	sethi		%hi(__hypervisor_tlb_xcall_error), %g4
	jmpl		%g4 + %lo(__hypervisor_tlb_xcall_error), %g0
	 nop

	.globl		__hypervisor_xcall_flush_tlb_page
__hypervisor_xcall_flush_tlb_page: /* 20 insns */
	/* %g5=ctx, %g1=vaddr */
	mov		%o0, %g2
	mov		%o1, %g3
	mov		%o2, %g4
	mov		%g1, %o0	        /* ARG0: virtual address */
	mov		%g5, %o1		/* ARG1: mmu context */
	mov		HV_MMU_ALL, %o2		/* ARG2: flags */
	srlx		%o0, PAGE_SHIFT, %o0
	sllx		%o0, PAGE_SHIFT, %o0
	ta		HV_MMU_UNMAP_ADDR_TRAP
	mov		HV_MMU_UNMAP_ADDR_TRAP, %g6
	brnz,a,pn	%o0, __hypervisor_tlb_xcall_error
	 mov		%o0, %g5
	mov		%g2, %o0
	mov		%g3, %o1
	mov		%g4, %o2
	membar		#Sync
	retry

	.globl		__hypervisor_xcall_flush_tlb_kernel_range
__hypervisor_xcall_flush_tlb_kernel_range: /* 25 insns */
	/* %g1=start, %g7=end, g2,g3,g4,g5,g6=scratch */
	sethi		%hi(PAGE_SIZE - 1), %g2
	or		%g2, %lo(PAGE_SIZE - 1), %g2
	andn		%g1, %g2, %g1
	andn		%g7, %g2, %g7
	sub		%g7, %g1, %g3
	add		%g2, 1, %g2
	sub		%g3, %g2, %g3
	mov		%o0, %g2
	mov		%o1, %g4
	mov		%o2, %g7
1:	add		%g1, %g3, %o0	/* ARG0: virtual address */
	mov		0, %o1		/* ARG1: mmu context */
	mov		HV_MMU_ALL, %o2	/* ARG2: flags */
	ta		HV_MMU_UNMAP_ADDR_TRAP
	mov		HV_MMU_UNMAP_ADDR_TRAP, %g6
	brnz,pn		%o0, __hypervisor_tlb_xcall_error
	 mov		%o0, %g5
	sethi		%hi(PAGE_SIZE), %o2
	brnz,pt		%g3, 1b
	 sub		%g3, %o2, %g3
	mov		%g2, %o0
	mov		%g4, %o1
	mov		%g7, %o2
	membar		#Sync
	retry
#endif	/*CONFIG_SPARC64_SUN4V*/

	/* These just get rescheduled to PIL vectors. */
	.globl		xcall_call_function
xcall_call_function:
	wr		%g0, (1 << PIL_SMP_CALL_FUNC), %set_softint
	retry

	.globl		xcall_call_function_single
xcall_call_function_single:
	wr		%g0, (1 << PIL_SMP_CALL_FUNC_SNGL), %set_softint
	retry

	.globl		xcall_receive_signal
xcall_receive_signal:
	wr		%g0, (1 << PIL_SMP_RECEIVE_SIGNAL), %set_softint
	retry

	.globl		xcall_capture
xcall_capture:
	wr		%g0, (1 << PIL_SMP_CAPTURE), %set_softint
	retry

#ifdef CONFIG_KGDB
	.globl		xcall_kgdb_capture
xcall_kgdb_capture:
	wr		%g0, (1 << PIL_KGDB_CAPTURE), %set_softint
	retry
#endif

#endif /* CONFIG_SMP */

	.globl		cheetah_patch_cachetlbops
cheetah_patch_cachetlbops:
	save		%sp, -128, %sp

#ifdef CONFIG_E90S
	rdpr		%ver, %o3
	srlx		%o3, 24, %o3
	and		%o3, 0xff, %o3
	cmp		%o3, 0x11	/* r2000, revision 1 */
	bne		1f
	 set		__flush_tlb_mm, %o0
	set		__e90s_r2000_with_bug_flush_tlb_mm, %o1
	call		tlb_patch_one
	 mov		20, %o2
#ifdef CONFIG_SMP
	set		xcall_flush_tlb_mm, %o0
	set		__e90s_r2000_with_bug_xcall_flush_tlb_mm, %o1
	call		tlb_patch_one
	 mov		21, %o2
#endif
	set		sparc64_ttable_tl0, %o0
	set		e90_fix_tt0_hw_bug, %o1
	call		tlb_patch_one
	 mov		8, %o2

	b,a 		2f
1:
	cmp		%o3, 0x20	/* r2000p */
	bl		3f
	 nop
	set		rtrap_irq, %o0
	set		r2000p_rtrap_irq, %o1
	call		tlb_patch_one
	 mov		2, %o2

#define BRANCH_ALWAYS	0x10680000
#define NOP		0x01000000
#define GEN_DO_PATCH(OLD, NEW)	\
	sethi	%hi(NEW), %g1; \
	or	%g1, %lo(NEW), %g1; \
	sethi	%hi(OLD), %g2; \
	or	%g2, %lo(OLD), %g2; \
	sub	%g1, %g2, %g1; \
	sethi	%hi(BRANCH_ALWAYS), %g3; \
	sll	%g1, 11, %g1; \
	srl	%g1, 11 + 2, %g1; \
	or	%g3, %lo(BRANCH_ALWAYS), %g3; \
	or	%g3, %g1, %g3; \
	stw	%g3, [%g2]; \
	sethi	%hi(NOP), %g3; \
	or	%g3, %lo(NOP), %g3; \
	stw	%g3, [%g2 + 0x4]; \
	flush	%g2;

	GEN_DO_PATCH(tl0_ivec, r2000p_do_ivec)
	GEN_DO_PATCH(tl1_ivec, r2000p_do_ivec)

3:
#endif /*CONFIG_E90S*/
	sethi		%hi(__flush_tlb_mm), %o0
	or		%o0, %lo(__flush_tlb_mm), %o0
	sethi		%hi(__cheetah_flush_tlb_mm), %o1
	or		%o1, %lo(__cheetah_flush_tlb_mm), %o1
	call		tlb_patch_one
	 mov		19, %o2
#ifdef CONFIG_E90S
2:
#endif
	sethi		%hi(__flush_tlb_page), %o0
	or		%o0, %lo(__flush_tlb_page), %o0
	sethi		%hi(__cheetah_flush_tlb_page), %o1
	or		%o1, %lo(__cheetah_flush_tlb_page), %o1
	call		tlb_patch_one
	 mov		22, %o2

	sethi		%hi(__flush_tlb_pending), %o0
	or		%o0, %lo(__flush_tlb_pending), %o0
	sethi		%hi(__cheetah_flush_tlb_pending), %o1
	or		%o1, %lo(__cheetah_flush_tlb_pending), %o1
	call		tlb_patch_one
	 mov		27, %o2

	sethi		%hi(__flush_tlb_kernel_range), %o0
	or		%o0, %lo(__flush_tlb_kernel_range), %o0
	sethi		%hi(__cheetah_flush_tlb_kernel_range), %o1
	or		%o1, %lo(__cheetah_flush_tlb_kernel_range), %o1
	call		tlb_patch_one
	 mov		31, %o2

#ifdef DCACHE_ALIASING_POSSIBLE
	sethi		%hi(__flush_dcache_page), %o0
	or		%o0, %lo(__flush_dcache_page), %o0
	sethi		%hi(__cheetah_flush_dcache_page), %o1
	or		%o1, %lo(__cheetah_flush_dcache_page), %o1
	call		tlb_patch_one
	 mov		11, %o2
#endif /* DCACHE_ALIASING_POSSIBLE */

#ifdef CONFIG_SMP
	sethi		%hi(xcall_flush_tlb_kernel_range), %o0
	or		%o0, %lo(xcall_flush_tlb_kernel_range), %o0
	sethi		%hi(__cheetah_xcall_flush_tlb_kernel_range), %o1
	or		%o1, %lo(__cheetah_xcall_flush_tlb_kernel_range), %o1
	call		tlb_patch_one
	 mov		44, %o2
#endif /* CONFIG_SMP */

	ret
	 restore

#ifdef	CONFIG_SPARC64_SUN4V
	.globl		hypervisor_patch_cachetlbops
hypervisor_patch_cachetlbops:
	save		%sp, -128, %sp

	sethi		%hi(__flush_tlb_mm), %o0
	or		%o0, %lo(__flush_tlb_mm), %o0
	sethi		%hi(__hypervisor_flush_tlb_mm), %o1
	or		%o1, %lo(__hypervisor_flush_tlb_mm), %o1
	call		tlb_patch_one
	 mov		19, %o2

	sethi		%hi(__flush_tlb_page), %o0
	or		%o0, %lo(__flush_tlb_page), %o0
	sethi		%hi(__hypervisor_flush_tlb_page), %o1
	or		%o1, %lo(__hypervisor_flush_tlb_page), %o1
	call		tlb_patch_one
	 mov		22, %o2

	sethi		%hi(__flush_tlb_pending), %o0
	or		%o0, %lo(__flush_tlb_pending), %o0
	sethi		%hi(__hypervisor_flush_tlb_pending), %o1
	or		%o1, %lo(__hypervisor_flush_tlb_pending), %o1
	call		tlb_patch_one
	 mov		27, %o2

	sethi		%hi(__flush_tlb_kernel_range), %o0
	or		%o0, %lo(__flush_tlb_kernel_range), %o0
	sethi		%hi(__hypervisor_flush_tlb_kernel_range), %o1
	or		%o1, %lo(__hypervisor_flush_tlb_kernel_range), %o1
	call		tlb_patch_one
	 mov		31, %o2

#ifdef DCACHE_ALIASING_POSSIBLE
	sethi		%hi(__flush_dcache_page), %o0
	or		%o0, %lo(__flush_dcache_page), %o0
	sethi		%hi(__hypervisor_flush_dcache_page), %o1
	or		%o1, %lo(__hypervisor_flush_dcache_page), %o1
	call		tlb_patch_one
	 mov		2, %o2
#endif /* DCACHE_ALIASING_POSSIBLE */

#ifdef CONFIG_SMP
	sethi		%hi(xcall_flush_tlb_mm), %o0
	or		%o0, %lo(xcall_flush_tlb_mm), %o0
	sethi		%hi(__hypervisor_xcall_flush_tlb_mm), %o1
	or		%o1, %lo(__hypervisor_xcall_flush_tlb_mm), %o1
	call		tlb_patch_one
	 mov		24, %o2

	sethi		%hi(xcall_flush_tlb_page), %o0
	or		%o0, %lo(xcall_flush_tlb_page), %o0
	sethi		%hi(__hypervisor_xcall_flush_tlb_page), %o1
	or		%o1, %lo(__hypervisor_xcall_flush_tlb_page), %o1
	call		tlb_patch_one
	 mov		20, %o2

	sethi		%hi(xcall_flush_tlb_kernel_range), %o0
	or		%o0, %lo(xcall_flush_tlb_kernel_range), %o0
	sethi		%hi(__hypervisor_xcall_flush_tlb_kernel_range), %o1
	or		%o1, %lo(__hypervisor_xcall_flush_tlb_kernel_range), %o1
	call		tlb_patch_one
	 mov		44, %o2
#endif /* CONFIG_SMP */

	ret
	 restore
#endif	/*CONFIG_SPARC64_SUN4V*/


#ifdef CONFIG_E90S
        .globl          xcall_dump_stack_chain
xcall_dump_stack_chain:
        rdpr            %pstate, %g2
        wrpr            %g2, PSTATE_IG | PSTATE_AG, %pstate
        rdpr            %pil, %g2
        wrpr            %g0, 15, %pil
        sethi           %hi(110f), %g7
        b,pt            %xcc, etrap_irq
110:     or             %g7, %lo(110b), %g7
        call            dump_backtrace_smp
         add            %sp, PTREGS_OFF, %o0
        clr             %l6
        /* Has to be a non-v9 branch due to the large distance. */
        b               rtrap_xcall
         ldx            [%sp + PTREGS_OFF + PT_V9_TSTATE], %l1

#define E90S_R2000_PWRCTRL_REG_ADDR	0x38

	.globl  __e90s_enter_c6
	.type		__e90s_enter_c6,#function
__e90s_enter_c6:
	save	%sp, -128, %sp
	wrpr    %g0, (PSTATE_PRIV|PSTATE_PEF), %pstate
	flushw
	stx	%i6, [%sp + STACK_BIAS + 0x70]
	stx	%i7, [%sp + STACK_BIAS + 0x78]
	rdpr	%tick, %g2
	stx	%g2, [%sp + STACK_BIAS + 0x80]
	rdpr	%wstate, %o5
	stx	%o6, [%g6 + TI_KSP]
	stb	%o5, [%g6 + TI_WSTATE]
	rdpr	%cwp, %o5
	stb	%o5, [%g6 + TI_CWP]

	/* cpu will be in c3 state until all other cpus of the cluster have gone
	 * in c6 too, then all cluster goes into c6. So we have to unmask irqs
	 * in order to be woken up from c3. */
	wrpr    %g0, (PSTATE_PRIV|PSTATE_PEF|PSTATE_IE), %pstate
	wrpr		%g0, 0, %pil

	set	6, %g1 /* C6 */
	set	E90S_R2000_PWRCTRL_REG_ADDR, %g2
	stxa	%g0, [%g0] ASI_IC_TAG /* flush icache: bug 139677 */
	stxa	%g1, [%g2] ASI_DCU_CONTROL_REG
	nop; nop; nop; nop; nop; nop; nop; nop; /* 20 nops: bug 139677 */
	nop; nop; nop; nop; nop; nop; nop; nop;
	nop; nop; nop; nop;
	ret
	 restore
	.size		__e90s_enter_c6,.-__e90s_enter_c6

	.globl  __e90s_exit_c6
	.type		__e90s_exit_c6,#function
__e90s_exit_c6:
	TRAP_LOAD_THREAD_REG(%g6, %g1)
	call	setup_trap_table
	 nop
	ldub	[%g6 + TI_CWP], %g1
	wrpr	%g1, %cwp
	ldx	[%g6 + TI_KSP], %o6
	ldub	[%g6 + TI_WSTATE], %o5
	ldub	[%g6 + TI_NEW_CHILD], %o7
	wrpr	%o5, 0x0, %wstate
	ldx	[%sp + STACK_BIAS + 0x70], %i6
	ldx	[%sp + STACK_BIAS + 0x78], %i7
	ldx	[%sp + STACK_BIAS + 0x80], %g2
	wrpr	%g2, %tick
	ldx	[%g6 + TI_TASK], %g4
	LOAD_PER_CPU_BASE(%g5, %g6, %g1, %g2, %g3)

	wrpr    %g0, (PSTATE_PRIV|PSTATE_PEF|PSTATE_IE), %pstate
	ret
	 restore
	.size		__e90s_exit_c6,.-__e90s_exit_c6

#endif /*CONFIG_E90S*/
