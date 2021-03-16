#ifndef _ASM_E2K_THREADS_H
#define _ASM_E2K_THREADS_H


/*
 * e2k arch-dependent limits for the nr of threads virtual CPUs
 * virtual IRQs
 */

/* KVM manage */
#define	KVM_VM_MAX_LIMIT	1024	/* max number of VM IDs at use */

/* VCPUs manage */
#define KVM_MAX_VCPUS 64

/* VIRQ manage */
#define	KVM_VIRQ_VCPUS_BASE_NO	0x01000000

/* VIRQ VCPU:	one for each Local APIC */
/*		one for erly timer interrupt */
#define	KVM_MAX_VIRQ_VCPUS	(KVM_MAX_VCPUS + 1)

#endif	/* _ASM_E2K_THREADS_H */
