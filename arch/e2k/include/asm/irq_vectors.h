#ifndef _ASM_E2K_IRQ_VECTORS_H
#define _ASM_E2K_IRQ_VECTORS_H

#define ERROR_APIC_VECTOR		0xfe
#define RESCHEDULE_VECTOR		0xfd
#define CALL_FUNCTION_VECTOR		0xfc
#define CALL_FUNCTION_SINGLE_VECTOR	0xfb
#define RDMA_INTERRUPT_VECTOR		0xf9
#define LVT3_INTERRUPT_VECTOR		0xf8
#define LVT4_INTERRUPT_VECTOR		0xf7
#define IRQ_WORK_VECTOR			0xf6
#define NMI_PSEUDO_VECTOR		0x100
/*
 * Local APIC timer IRQ vector is on a different priority level,
 * to work around the 'lost local interrupt if more than 2 IRQ
 * sources per level' errata.
 */
#define LOCAL_TIMER_VECTOR		0xef

#include <asm-l/irq_vectors.h>

#endif /* _ASM_E2K_IRQ_VECTORS_H */

