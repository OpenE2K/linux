#ifndef _ASM_SPARC_IRQ_VECTORS_H
#define _ASM_SPARC_IRQ_VECTORS_H

#define ERROR_APIC_VECTOR		0xfe
#define INVALIDATE_TLB_VECTOR		0xfd
#define CYCLES_SYNC_VECTOR		0xfc
#define RESCHEDULE_VECTOR		0xec
#define CALL_FUNCTION_VECTOR		0xeb
#define CALL_FUNCTION_SINGLE_VECTOR	0xea
#define RDMA_INTERRUPT_VECTOR		0xe9
#define IRQ_WORK_VECTOR			0xe8
#define NMI_PSEUDO_VECTOR               0x100

/*
 * Local APIC timer IRQ vector is on a different priority level,
 * to work around the 'lost local interrupt if more than 2 IRQ
 * sources per level' errata.
 */
#define LOCAL_TIMER_VECTOR		0xdf


#ifdef	CONFIG_EPIC
#define CEPIC_TIMER_VECTOR			0x2ea
#define CEPIC_EPIC_INT_VECTOR			0x2fb
#define EPIC_IRQ_WORK_VECTOR			0x2fc
#define EPIC_CALL_FUNCTION_SINGLE_VECTOR	0x2fd
#define EPIC_CALL_FUNCTION_VECTOR		0x2fe
#define EPIC_RESCHEDULE_VECTOR			0x2ff

#define EPIC_CYCLES_SYNC_VECTOR			0x3fb
#define EPIC_INVALIDATE_TLB_VECTOR		0x3fc
#define PREPIC_ERROR_VECTOR			0x3fd
#define ERROR_EPIC_VECTOR			0x3fe
#define SPURIOUS_EPIC_VECTOR			0x3ff
#endif


#include <asm-l/irq_vectors.h>

#endif /* _ASM_SPARC_IRQ_VECTORS_H */

