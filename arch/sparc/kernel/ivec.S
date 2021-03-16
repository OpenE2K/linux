/* SPDX-License-Identifier: GPL-2.0 */
	/* The registers for cross calls will be:
	 *
	 * DATA 0: [low 32-bits]  Address of function to call, jmp to this
	 *         [high 32-bits] MMU Context Argument 0, place in %g5
	 * DATA 1: Address Argument 1, place in %g1
	 * DATA 2: Address Argument 2, place in %g7
	 *
	 * With this method we can do most of the cross-call tlb/cache
	 * flushing very quickly.
	 */
	.align		32
	.globl		do_ivec
	.type		do_ivec,#function
#ifdef CONFIG_E90S
#include <asm/e90s.h>
	.globl		r2000p_do_ivec, r2000p_rtrap_irq
	.type		r2000p_do_ivec,#function
do_ivec:
	mov		APIC_VECT, %g2
	lduwa		[%g2] ASI_LAPIC, %g5
	mov		APIC_EOI, %g2
#ifdef CONFIG_SMP
	cmp		%g5, INVALIDATE_TLB_VECTOR
	be,a		do_ivec_xcall_e90s
	 stwa		%g0, [%g2] ASI_LAPIC
        cmp     	%g5, CYCLES_SYNC_VECTOR
        be,a     	 do_ivec_cycl_sync_e90s
	 stwa		%g0, [%g2] ASI_LAPIC
#endif
	cmp		%g5, APIC_SPIV_SPURIOUS_VECT
	be,a		do_ivec_spurious_e90s
	 stwa		%g0, [%g2] ASI_LAPIC

	mov		APIC_SPIV_SPURIOUS_VECT - 0x10, %g3
	mov		APIC_TASKPRI, %g1
	stwa		%g3, [%g1] ASI_LAPIC
	membar		#Sync

	stw		%g5, [%g6]
	set		1<<PIL_DEVICE_IRQ, %g2
	wr		%g2, 0x0, %set_softint
	retry
	nop

r2000p_do_ivec:
	mov		CEPIC_VECT_INTA, %g2
	lduwa		[%g2] ASI_EPIC, %g5
	and		%g5, CEPIC_VECT_INTA_VMASK, %g1
	mov		CEPIC_EOI, %g2
#ifdef CONFIG_SMP
	cmp		%g1, EPIC_INVALIDATE_TLB_VECTOR
	be,a		do_ivec_xcall_e90s
	 stwa		%g5, [%g2] ASI_EPIC
	cmp		%g1, EPIC_CYCLES_SYNC_VECTOR
	be,a     	 do_ivec_cycl_sync_e90s
	 stwa		%g5, [%g2] ASI_EPIC
#endif
	cmp		%g1, SPURIOUS_EPIC_VECTOR
	be,a		do_ivec_spurious_e90s
	 stwa		%g5, [%g2] ASI_EPIC

	set		(3 << CEPIC_CPR_CORE_PRIORITY_SHIFT), %g3
        mov		CEPIC_CPR, %g2
        stwa		%g3, [%g2] ASI_EPIC

	set		(3 << CEPIC_VECT_INTA_PRI_SHIFT), %g3
	or		%g3, %g1, %g1
	stw		%g1, [%g6]
	set		1<<PIL_DEVICE_IRQ, %g2
	wr		%g2, 0x0, %set_softint
	retry

r2000p_rtrap_irq:
        mov		CEPIC_CPR, %l0
        stwa		%g0, [%l0] ASI_EPIC

#ifdef CONFIG_SMP
do_ivec_xcall_e90s:
	set	tlb_call_data, %g2
	mov	%g6, %g3
	ldx 	[%g2], %g6
	ldx 	[%g2 + 8], %g5
	ldx 	[%g2 + 16], %g1
	ldx 	[%g2 + 24], %g7
	sllx	%g3, 32, %g3
	or	%g3, %g6, %g6
	set	tlb_call_finished, %g2
1:	lduw	[%g2], %g3
	add	%g3, 1, %g4
	casa	[%g2] ASI_N,  %g3, %g4
	cmp	%g3, %g4
	bne,pn	%icc, 1b
	 nop
	srlx	%g6, 32, %g3
	sllx	%g6, 32, %g6
	srlx	%g6, 32, %g6
	jmpl	%g6, %g0
	 mov	%g3, %g6
#endif /*CONFIG_SMP*/

do_ivec_cycl_sync_e90s:
	rd	%tick, %g2
	add	%g2, CYCL_SYNC_GAP>>1, %g2	/* to round up */
	and	%g2, ~(CYCL_SYNC_GAP - 1), %g2
	/* add	%g2, for more precicsion we could add interrupt time cycles */
	wrpr	%g2, 0, %tick
	set	go_cycl_sync, %g3
	stx	%g2, [%g3] /* set any !=0 value; cycles - for debug */
do_ivec_spurious_e90s:
	membar	#Sync 
	retry
#else	/*CONFIG_E90S*/
do_ivec:
	mov		0x40, %g3
	ldxa		[%g3 + %g0] ASI_INTR_R, %g3
	sethi		%hi(KERNBASE), %g4
	cmp		%g3, %g4
	bgeu,pn		%xcc, do_ivec_xcall
	 srlx		%g3, 32, %g5
	stxa		%g0, [%g0] ASI_INTR_RECEIVE
	membar		#Sync

	sethi		%hi(ivector_table_pa), %g2
	ldx		[%g2 + %lo(ivector_table_pa)], %g2
	sllx		%g3, 4, %g3
	add		%g2, %g3, %g3

	TRAP_LOAD_IRQ_WORK_PA(%g6, %g1)

	ldx		[%g6], %g5
	stxa		%g5, [%g3] ASI_PHYS_USE_EC
	stx		%g3, [%g6]
	wr		%g0, 1 << PIL_DEVICE_IRQ, %set_softint
	retry
do_ivec_xcall:
	mov		0x50, %g1
	ldxa		[%g1 + %g0] ASI_INTR_R, %g1
	srl		%g3, 0, %g3

	mov		0x60, %g7
	ldxa		[%g7 + %g0] ASI_INTR_R, %g7
	stxa		%g0, [%g0] ASI_INTR_RECEIVE
	membar		#Sync
	ba,pt		%xcc, 1f
	 nop

	.align		32
1:	jmpl		%g3, %g0
	 nop
	.size		do_ivec,.-do_ivec

#endif	/*CONFIG_E90S*/
