
#ifndef	__E2K_ASM_KVM_GUEST_IRQ_H_
#define	__E2K_ASM_KVM_GUEST_IRQ_H_

#include <linux/types.h>
#include <linux/interrupt.h>
#include <linux/kvm_host.h>

/* Interrupt types. */
typedef enum kvm_irq_type {
	IRQT_UNBOUND = 0,
	IRQT_VIRQ,
	IRQT_IPI,
} kvm_irq_type_t;

#define	KVM_NR_IRQS		NR_IRQS	/* now limited by common NR IRQS */
					/* as on host */
#define	KVM_NR_VIRQS_PER_CPU	4
#define	KVM_NR_VCPUS		(KVM_NR_VIRQS_PER_CPU * NR_CPUS)
/*
 * Modes to handle Virtual IRQs (see field 'flags' below)
 */
#define	BY_DIRECT_INJ_VIRQ_MODE	3		/* handle VIRQ by direct */
						/* injection on VCPU */
#define	BY_DIRECT_INJ_VIRQ_FLAG	(1UL << BY_DIRECT_INJ_VIRQ_MODE)

static inline unsigned long
kvm_get_default_virq_flags(int virq_id)
{
	unsigned long def_flags = 0;

#ifdef	CONFIG_DIRECT_VIRQ_INJECTION
	def_flags |= BY_DIRECT_INJ_VIRQ_FLAG;
#endif	/* CONFIG_DIRECT_VIRQ_INJECTION */

	return def_flags;
}

typedef struct kvm_virq_info {
	unsigned long mode;		/* handling mode of virtual IRQ */
					/* (see above) */
	unsigned long flags;		/* flags of virtual IRQ (see above) */
	int virq_nr;			/* # of VIRQ */
	int gpid_nr;			/* guest kernel thread ID on host */
	void *dev_id;			/* VIRQ device ID */
	irq_handler_t handler;		/* VIRQ handler */
	atomic_t *count;		/* pointer to current atomic counter */
					/* of received VIRQs */
					/* counter is common for host & guest */
	struct task_struct *task;	/* kernel thread task to handle VIRQ */
} kvm_virq_info_t;

/*
 * Packed IRQ information:
 * type - enum kvm_irq_type
 * cpu - cpu this event channel is bound to
 * index - type-specific information:
 *    PIRQ - vector, with MSB being "needs EIO"
 *    VIRQ - virq number
 *    IPI - IPI vector
 *    EVTCHN -
 */
typedef struct kvm_irq_info {
	kvm_irq_type_t type;	/* type */
	int cpu;		/* cpu bound (-1 if not bound) */
	bool active;		/* IRQ is active */

	union {			/* type-specific info */
		kvm_virq_info_t virq;
	} u;
} kvm_irq_info_t;

extern int kvm_request_virq(int virq, irq_handler_t handler, int cpu,
			unsigned long irqflags, const char *name, void *dev);
static inline int
kvm_request_direct_virq(int virq, irq_handler_t handler, int cpu,
				const char *name, void *dev)
{
	return kvm_request_virq(virq, handler, cpu,
				BY_DIRECT_INJ_VIRQ_FLAG, name, dev);
}

extern int kvm_free_virq(int virq, int cpu, void *dev);

#endif  /* __E2K_ASM_KVM_GUEST_IRQ_H_ */
