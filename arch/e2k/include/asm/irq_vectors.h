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

#ifdef	CONFIG_VIRTUALIZATION
/* VIRQ vector to emulate SysRq on guest kernel */
#define	SYSRQ_SHOWSTATE_APIC_VECTOR	0xfa
/* VIRQ vector to emulate NMI on guest kernel */
#define	KVM_NMI_APIC_VECTOR		0xee

#define	SYSRQ_SHOWSTATE_EPIC_VECTOR	0x3fa
#define	KVM_NMI_EPIC_VECTOR		0x3ee
#endif	/* CONFIG_VIRTUALIZATION */

#ifdef	CONFIG_EPIC
/* EPIC system vectors have the highest priority level of 3 (0x300 - 0x3ff) */
#define LINP0_INTERRUPT_VECTOR			0x3e0
#define LINP1_INTERRUPT_VECTOR			0x3e1
#define LINP2_INTERRUPT_VECTOR			0x3e2
#define LINP3_INTERRUPT_VECTOR			0x3e3
#define LINP4_INTERRUPT_VECTOR			0x3e4
#define LINP5_INTERRUPT_VECTOR			0x3e5
#define CEPIC_TIMER_VECTOR			0x3ef
#define CEPIC_EPIC_INT_VECTOR			0x3f0
#define EPIC_IRQ_WORK_VECTOR			0x3f6
#define PREPIC_ERROR_VECTOR			0x3f9
#define EPIC_CALL_FUNCTION_SINGLE_VECTOR	0x3fb
#define EPIC_CALL_FUNCTION_VECTOR		0x3fc
#define EPIC_RESCHEDULE_VECTOR			0x3fd
#define ERROR_EPIC_VECTOR			0x3fe
#define SPURIOUS_EPIC_VECTOR			0x3ff
#endif

#ifdef CONFIG_KVM_ASYNC_PF
#define ASYNC_PF_WAKE_VECTOR			0x3f8
#endif /* CONFIG_KVM_ASYNC_PF */

#include <asm-l/irq_vectors.h>

#endif /* _ASM_E2K_IRQ_VECTORS_H */

