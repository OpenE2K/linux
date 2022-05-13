
#ifndef	__E2K_ASM_KVM_IRQ_H_
#define	__E2K_ASM_KVM_IRQ_H_

#include <linux/types.h>
#include <asm/kvm/threads.h>

/*
 * VIRTUAL INTERRUPTS
 *
 * Virtual interrupts that a guest OS may receive from KVM.
 */
#define KVM_VIRQ_TIMER	0  /* timer interrupt */
#define KVM_VIRQ_HVC	1  /* HyperVisor Console interrupt */
#define KVM_VIRQ_LAPIC	2  /* virtual local APIC interrupt */
#define KVM_VIRQ_CEPIC	3  /* virtual CEPIC interrupt */
#define KVM_NR_VIRQS	(KVM_VIRQ_CEPIC + 1)

#define KVM_MAX_NR_VIRQS	(KVM_MAX_VIRQ_VCPUS * KVM_NR_VIRQS)

#if KVM_NR_VIRQS > KVM_MAX_NR_VIRQS
 #error	"limit of max number of VIRQs exceeded"
#endif

static inline const char *kvm_get_virq_name(int virq_id)
{
	switch (virq_id) {
	case KVM_VIRQ_TIMER:
		return "early_timer";
	case KVM_VIRQ_HVC:
		return "hvc_virq";
	case KVM_VIRQ_LAPIC:
		return "lapic";
	case KVM_VIRQ_CEPIC:
		return "cepic";
	default:
		return "???";
	}
}

typedef int (*irq_thread_t)(void *);
extern int debug_guest_virqs;

#endif  /* __E2K_ASM_KVM_IRQ_H_ */
