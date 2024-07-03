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
#include <linux/hardirq.h>
#include <linux/kthread.h>

#include <asm/apic.h>
#include <asm/trap_table.h>
#include <asm/e2k_debug.h>
#include <asm/timer.h>
#include <asm/irq_regs.h>

#include <asm/kvm/guest.h>
#include <asm/kvm/hypercall.h>
#include <asm/kvm/guest/irq.h>
#include <asm/kvm/guest/processor.h>
#include <asm/kvm/guest/io.h>

#include "cpu.h"
#include "irq.h"

#undef	DEBUG_KVM_MODE
#undef	DebugKVM
#define	DEBUG_KVM_MODE	0	/* kernel virtual machine debugging */
#define	DebugKVM(fmt, args...)						\
({									\
	if (DEBUG_KVM_MODE)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_THREAD_IRQ_MODE
#undef	DebugKVMTI
#define	DEBUG_KVM_THREAD_IRQ_MODE	0	/* kernel virtual IRQ thread */
						/* debugging */
#define	DebugKVMTI(fmt, args...)					\
({									\
	if (DEBUG_KVM_THREAD_IRQ_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_LAPIC_IRQ_MODE
#undef	DebugLAI
#define	DEBUG_KVM_LAPIC_IRQ_MODE	0	/* local APIC IRQ thread */
						/* debugging */
#define	DebugLAI(fmt, args...)					\
({									\
	if (DEBUG_KVM_LAPIC_IRQ_MODE)					\
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

static bool bsp_direct_virq_lapic = false;

static int kvm_lapic_virq_panic(struct notifier_block *this,
					unsigned long event, void *ptr);

static DEFINE_PER_CPU(struct notifier_block, resume_block_cpu);

/*
 * Basic functions to access to local APIC state fields on guest.
 */
static inline int kvm_read_lapic_virqs_num(void)
{
	kvm_apic_state_t *lapic;

	lapic = kvm_vcpu_lapic_state();
	return atomic_read(&lapic->virqs_num);
}
static inline void kvm_dec_lapic_virqs_num(void)
{
	kvm_apic_state_t *lapic;

	lapic = kvm_vcpu_lapic_state();
	atomic_dec(&lapic->virqs_num);
}
static inline bool kvm_dec_and_test_lapic_virqs_num(void)
{
	kvm_apic_state_t *lapic;

	lapic = kvm_vcpu_lapic_state();
	return atomic_dec_and_test(&lapic->virqs_num);
}

/*
 * Local APIC of guest VCPU virtualized by host (see arch/e2k/kvm/lapic.c)
 * Any virtual IRQ received by local APIC on host, which must be handled
 * by guest, causes virtual IRQ type of KVM_VIRQ_LAPIC and wake up
 * special thread on special VIRQ VCPU. This thread wakes up the thread
 * on real VCPU which starts this handler
 */
static irqreturn_t kvm_lapic_interrupt(int irq, void *dev_id)
{
	struct pt_regs *regs;
	long cpu = (long)dev_id;
	irqreturn_t ret;
	unsigned long flags;

	DebugLAI("process %s (%d): started for local APIC VIRQ #%d "
		"on CPU #%ld\n",
		current->comm, current->pid, irq, cpu);
	if (cpu != smp_processor_id()) {
		/* here need access to foreign local APIC, not own */
		/* Update local APIC base address to enable such access */
		BUG_ON(true);
	}
	raw_local_irq_save(flags);
	regs = get_irq_regs();

	ret = native_do_interrupt(regs);

	if (regs->interrupt_vector == KVM_NMI_APIC_VECTOR) {
		/* NMI IPI on guest implemented as general inteerupt */
		/* with vector KVM_NMI_APIC_VECTOR */
		/* but nmi_call_function_interrupt() has been called */
		/* under NMI disabled, so now enable NMIs */
		exiting_irq();
		KVM_INIT_KERNEL_IRQ_MASK_REG(false,	/* enable IRQs */
					     false	/* disable NMIs */);
	}
	raw_local_irq_restore(flags);

	DebugKVMTI("local APIC VIRQ #%d on CPU #%ld handled\n",
		irq, cpu);
	return ret;
}

static int kvm_do_setup_lapic_virq(bool bsp, int cpu)
{
	const char *name;
	struct notifier_block *resume_block;
	unsigned long irqflags;
	int ret;

	if (!paravirt_enabled())
		return 0;

	DebugKVM("installing KVM guest local APIC VIRQ on CPU %d\n",
		cpu);

	name = kasprintf(GFP_KERNEL, "lapic/%d", cpu);
	if (!name)
		name = "<lapic kasprintf failed>";

	irqflags = kvm_get_default_virq_flags(KVM_VIRQ_LAPIC);

	if (irqflags & BY_DIRECT_INJ_VIRQ_FLAG) {
		BUG_ON(cpu != smp_processor_id());
		ret = kvm_request_virq(KVM_VIRQ_LAPIC,
				&kvm_lapic_interrupt, cpu,
				BY_DIRECT_INJ_VIRQ_FLAG,
				name, (void *) (long) cpu);
		if (ret == 0) {
			if (bsp)
				bsp_direct_virq_lapic = true;
			goto success;
		}
		DebugDIRQ("could not request direct local APIC VIRQ %s "
			"injection\n", name);
	} else {
		/* unknown mode to request VIRQ delivery */
		BUG_ON(true);
		ret = -EINVAL;
	}
	if (ret) {
		panic("could not register local APIC VIRQ #%d for CPU #%d\n",
			KVM_VIRQ_LAPIC, cpu);
	}

success:
	resume_block = &per_cpu(resume_block_cpu, cpu);
	resume_block->notifier_call = kvm_lapic_virq_panic;
	resume_block->next = NULL;
	atomic_notifier_chain_register(&panic_notifier_list, resume_block);

	if (bsp) {
		/* Local APIC support on guest is now ready, so enable */
		/* APIC timer and set up the local APIC timer on boot CPU */
		disable_apic_timer = false;
	}

	DebugKVM("KVM guest local APIC VIRQ on CPU %d installed\n", cpu);
	return ret;
}

__init int kvm_setup_boot_lapic_virq(void)
{
	return kvm_do_setup_lapic_virq(true, raw_smp_processor_id());
}

int kvm_setup_secondary_lapic_virq(unsigned int cpuid)
{
	return kvm_do_setup_lapic_virq(false, cpuid);
}

static int
kvm_lapic_virq_panic(struct notifier_block *this,
			unsigned long event, void *ptr)
{
	return NOTIFY_DONE;
}
