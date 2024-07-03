/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest virtual IRQs implementation.
 */
#include <linux/kernel.h>
#include <linux/interrupt.h>
#include <linux/kernel_stat.h>
#include <linux/kthread.h>

#include <uapi/linux/sched/types.h>

#include <asm/console.h>
#include <asm/irq_regs.h>

#include <asm/kvm/guest.h>
#include <asm/kvm/hypercall.h>
#include <asm/kvm/guest/irq.h>
#include <asm/kvm/guest/processor.h>
#include <asm/kvm/guest/cpu.h>

#include "irq.h"
#include "traps.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_IRQ_MODE
#undef	DebugKVMIRQ
#define	DEBUG_KVM_IRQ_MODE	0	/* kernel virtual IRQ debugging */
#define	DebugKVMIRQ(fmt, args...)					\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_DIRECT_IRQ_MODE
#undef	DebugDIRQ
#define	DEBUG_DIRECT_IRQ_MODE	0	/* direct IRQ injection debugging */
#define	DebugDIRQ(fmt, args...)						\
({									\
	if (DEBUG_DIRECT_IRQ_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

/* On VIRQ VCUPs common printk() cannot be used, because of thread */
/* running on these VCPUs has not task structure */
#undef	DEBUG_DUMP_KVM_MODE
#undef	DebugDKVM
#define	DEBUG_DUMP_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugDKVM(fmt, args...)						\
({									\
	if (DEBUG_DUMP_KVM_MODE)					\
		dump_printk("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_DUMP_KVM_IRQ_MODE
#undef	DebugDKVMIRQ
#define	DEBUG_DUMP_KVM_IRQ_MODE	0	/* kernel virtual IRQ debugging */
#define	DebugDKVMIRQ(fmt, args...)					\
({									\
	if (DEBUG_DUMP_KVM_IRQ_MODE)					\
		dump_printk("%s(): " fmt, __func__, ##args);		\
})

/*
 * FIXME: all VIRQ should be registered at a list or table and
 * need implement function to free all VIRQs
 *
 * based on Xen model of interrupts (driver/xen/events.c)
 * There are a few kinds of interrupts which should be mapped to an event
 * channel:
 *
 * 1. Inter-domain notifications.  This includes all the virtual
 *    device events, since they're driven by front-ends in another domain
 *    (typically dom0). Not supported at present.
 * 2. VIRQs, typically used for timers.  These are per-cpu events.
 * 3. IPIs. Not supported at present.
 * 4. Hardware interrupts. Not supported at present.
 */

kvm_irq_info_t irq_info[KVM_NR_IRQS];
int kvm_nr_irqs = 0;

static DEFINE_SPINLOCK(irq_mapping_lock);

/* IRQ <-> VIRQ mapping. */
static DEFINE_PER_CPU(int [KVM_NR_VIRQS], virq_to_irq) = {
	[0 ... KVM_NR_VIRQS - 1] = -1
};

/* Constructor for packed IRQ information. */
static inline kvm_irq_info_t mk_unbound_info(void)
{
	return (kvm_irq_info_t) { .type = IRQT_UNBOUND };
}

static inline kvm_irq_info_t mk_virq_info(int virq, int cpu)
{
	return (kvm_irq_info_t) { .type = IRQT_VIRQ,
				  .cpu = cpu,
				  .active = false,
				  .u.virq.virq_nr = virq,
				  .u.virq.gpid_nr = 0,
				  .u.virq.task = NULL,
				  .u.virq.dev_id = NULL,
				  .u.virq.handler = NULL,
				  .u.virq.count = NULL,
				};
}

static DEFINE_PER_CPU(struct pt_regs, vcpu_virq_regs);

/*
 * Accessors for packed IRQ information.
 */

static inline void set_gpid_to_irq(unsigned irq, unsigned gpid_nr)
{
	kvm_virq_info_t *info = virq_info_from_irq(irq);

	info->gpid_nr = gpid_nr;
}

static inline void set_virq_task_to_irq(unsigned irq,
						struct task_struct *task)
{
	kvm_virq_info_t *info = virq_info_from_irq(irq);

	info->task = task;
}

static inline void activate_irq(unsigned irq, bool activate)
{
	kvm_irq_info_t *info = info_for_irq(irq);

	info->active = activate;
}

static int find_unbound_irq(void)
{
	int irq;

	for (irq = 0; irq < kvm_nr_irqs; irq++)
		if (irq_info[irq].type == IRQT_UNBOUND)
			return irq;

	if (kvm_nr_irqs >= KVM_NR_IRQS)
		panic("No available IRQ to bind to: increase KVM_NR_IRQS!\n");
	BUG_ON(irq_info[irq].type != IRQT_UNBOUND);
	kvm_nr_irqs++;

	return irq;
}

static inline int do_bind_virq_to_irq(unsigned int virq, unsigned int cpu,
					bool create)
{
	int irq;

	spin_lock(&irq_mapping_lock);

	irq = per_cpu(virq_to_irq, cpu)[virq];

	if (irq < 0 && create) {
		irq = find_unbound_irq();
		irq_info[irq] = mk_virq_info(virq, cpu);
		per_cpu(virq_to_irq, cpu)[virq] = irq;
	}

	spin_unlock(&irq_mapping_lock);

	return irq;
}

static int bind_virq_to_irq(unsigned int virq, unsigned int cpu)
{
	return do_bind_virq_to_irq(virq, cpu, true);
}

static void unbind_from_irq(unsigned int irq)
{
	int cpu = cpu_from_irq(irq);

	spin_lock(&irq_mapping_lock);

	switch (type_from_irq(irq)) {
	case IRQT_VIRQ:
		per_cpu(virq_to_irq, cpu)[virq_from_irq(irq)] = -1;
		break;
	case IRQT_IPI:
		panic("unbind_from_irq() does not yet implemented fo IPI\n");
		break;
	default:
		break;
	}

	if (irq_info[irq].type != IRQT_UNBOUND) {
		irq_info[irq] = mk_unbound_info();
		if (irq + 1 == kvm_nr_irqs)
			kvm_nr_irqs--;
	}

	spin_unlock(&irq_mapping_lock);
}

#ifdef	CONFIG_DIRECT_VIRQ_INJECTION
static int do_request_direct_virq(int irq, const char *name)
{
	kvm_virq_info_t *virq_info = virq_info_from_irq(irq);
	int virq = virq_from_irq(irq);
	int cpu = cpu_from_irq(irq);
	atomic_t *virqs_num;
	int ret;

	DebugDIRQ("process %s (%d): started to register VIRQ #%d CPU #%d "
		"for %s\n",
		current->comm, current->pid, virq, cpu, name);

	/* atomic VIRQs counter can be received only on this CPU */
	BUG_ON(cpu != smp_processor_id());

	virqs_num = kvm_get_virqs_atomic_counter(virq);
	if (IS_ERR(virqs_num)) {
		pr_err("%s(): could not take VIRQs #%d atomic counter\n",
			__func__, virq);
		return PTR_ERR(virqs_num);
	}
	virq_info->count = virqs_num;

	ret = HYPERVISOR_get_guest_direct_virq(irq, virq);
	if (ret && ret != -EEXIST) {
		DebugDIRQ("could not register VIRQ #%d for %s\n",
			virq, name);
	} else if (ret == -EEXIST) {
		virq_info->mode = BY_DIRECT_INJ_VIRQ_MODE;
		DebugDIRQ("VIRQ #%d IRQ #%d was already registered for %s\n",
			virq, irq, name);
		ret = 0;
	} else {
		virq_info->mode = BY_DIRECT_INJ_VIRQ_MODE;
		DebugDIRQ("VIRQ #%d IRQ #%d registered for %s\n",
			virq, irq, name);
	}
	return ret;
}

static int do_free_direct_virq(int irq)
{
	int ret;

	DebugDIRQ("process %s (%d): started to free VIRQ #%d CPU #%d\n",
		current->comm, current->pid,
		virq_from_irq(irq), cpu_from_irq(irq));

	ret = HYPERVISOR_free_guest_direct_virq(irq);
	return ret;
}
#else	/* ! CONFIG_DIRECT_VIRQ_INJECTION */
static int do_request_direct_virq(int irq, const char *name)
{
	pr_err("Cannot request direct VIRQ injection, turn ON config mode "
		"to enable this feature\n");
	return -ENOSYS;
}
static int do_free_direct_virq(int irq)
{
	pr_warn("Cannot free direct VIRQ injection, turn ON config mode "
		"to enable this feature\n");
	return -ENOSYS;
}
#endif	/* CONFIG_DIRECT_VIRQ_INJECTION */

int kvm_request_virq(int virq, irq_handler_t handler, int cpu,
			unsigned long irqflags, const char *name, void *dev)
{
	kvm_virq_info_t *virq_info;
	int irq;
	int ret = -ENOSYS;

	DebugKVM("process %s (%d): started to register VIRQ #%d CPU #%d "
		"for %s\n",
		current->comm, current->pid, virq, cpu, name);

	irq = bind_virq_to_irq(virq, cpu);
	DebugKVM("VIRQ #%d CPU #%d binded to IRQ #%d\n",
		virq, cpu, irq);

	virq_info = virq_info_from_irq(irq);
	virq_info->virq_nr = virq;
	virq_info->dev_id = dev;
	virq_info->handler = handler;

	if (irqflags == 0)
		irqflags = kvm_get_default_virq_flags(virq);

	if (irqflags & BY_DIRECT_INJ_VIRQ_FLAG) {
		ret = do_request_direct_virq(irq, name);
		if (ret == 0) {
			goto out;
		}
		DebugDIRQ("could not request direct IRQ #%d %s injection\n",
			irq, name);
	} else {
		BUG();
	}

out:
	if (ret) {
		unbind_from_irq(irq);
		DebugKVM("could not register VIRQ #%d for %s\n",
			virq, name);
	} else {
		activate_irq(irq, true	/* activate */);
		DebugKVM("VIRQ #%d IRQ #%d registered and activated for %s\n",
			virq, irq, name);
	}
	return ret;
}

int kvm_free_virq(int virq, int cpu, void *dev)
{
	kvm_virq_info_t *virq_info;
	int irq;
	int ret = -ENOSYS;

	DebugKVM("process %s (%d): started to free VIRQ #%d CPU #%d\n",
		current->comm, current->pid, virq, cpu);

	irq = per_cpu(virq_to_irq, cpu)[virq];
	if (irq < 0) {
		DebugKVM("VIRQ #%d CPU #%d is not bound any IRQ so it free\n",
			virq, cpu);
		return 0;
	}
	virq_info = virq_info_from_irq(irq);

	if (virq_info->flags & BY_DIRECT_INJ_VIRQ_FLAG) {
		ret = do_free_direct_virq(irq);
	} else {
		BUG();
	}

	unbind_from_irq(irq);

	if (ret) {
		DebugKVM("failed for VIRQ #%d CPU #%d, error %d\n",
			virq, cpu, ret);
	} else {
		DebugKVM("VIRQ #%d CPU #%d is now free\n", virq, cpu);
	}
	return ret;
}

__init void kvm_virqs_init(int cpu)
{
	struct pt_regs *regs;

	regs = this_cpu_ptr(&vcpu_virq_regs);
	memset(regs, 0, sizeof(*regs));
}
