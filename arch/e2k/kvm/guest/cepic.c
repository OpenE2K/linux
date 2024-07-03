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

#include <asm/trap_table.h>
#include <asm/e2k_debug.h>
#include <asm/epic.h>
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
#define	DEBUG_KVM_MODE	1	/* kernel virtual machine debugging */
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

#undef	DEBUG_KVM_CEPIC_IRQ_MODE
#undef	DebugCEI
#define	DEBUG_KVM_CEPIC_IRQ_MODE	0	/* CEPIC IRQ thread */
						/* debugging */
#define	DebugCEI(fmt, args...)					\
({									\
	if (DEBUG_KVM_CEPIC_IRQ_MODE)					\
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

static bool bsp_direct_virq_cepic;

static int kvm_cepic_virq_panic(struct notifier_block *this,
					unsigned long event, void *ptr);

static DEFINE_PER_CPU(struct notifier_block, resume_block_cpu);

/*
 * Basic functions to access to CEPIC state fields on guest.
 */
static inline int kvm_read_cepic_virqs_num(void)
{
	kvm_epic_state_t *cepic;

	cepic = kvm_vcpu_cepic_state();
	return atomic_read(&cepic->virqs_num);
}
static inline void kvm_dec_cepic_virqs_num(void)
{
	kvm_epic_state_t *cepic;

	cepic = kvm_vcpu_cepic_state();
	atomic_dec(&cepic->virqs_num);
}
static inline bool kvm_dec_and_test_cepic_virqs_num(void)
{
	kvm_epic_state_t *cepic;

	cepic = kvm_vcpu_cepic_state();
	return atomic_dec_and_test(&cepic->virqs_num);
}

/*
 * CEPIC of guest VCPU virtualized by host (see arch/e2k/kvm/cepic.c)
 * Any virtual IRQ received by CEPIC on host, which must be handled
 * by guest, causes virtual IRQ type of KVM_VIRQ_CEPIC and wake up
 * special thread on special VIRQ VCPU. This thread wakes up the thread
 * on real VCPU which starts this handler
 */
static irqreturn_t kvm_cepic_interrupt(int irq, void *dev_id)
{
	struct pt_regs *regs;
	long cpu = (long)dev_id;
	irqreturn_t ret;
	unsigned long flags;

	DebugCEI("process %s (%d): started for CEPIC VIRQ #%d on CPU #%ld\n",
		current->comm, current->pid, irq, cpu);
	if (cpu != smp_processor_id()) {
		/* here need access to foreign CEPIC, not own */
		/* Update CEPIC base address to enable such access */
		BUG_ON(true);
	}
	raw_local_irq_save(flags);
	regs = get_irq_regs();

	ret = native_do_interrupt(regs);

	if (regs->interrupt_vector == KVM_NMI_EPIC_VECTOR) {
		/* NMI IPI on guest implemented as general interrupt */
		/* with vector KVM_NMI_EPIC_VECTOR */
		/* but nmi_call_function_interrupt() has been called */
		/* under NMI disabled, so now enable NMIs */
		irq_exit();
		KVM_INIT_KERNEL_IRQ_MASK_REG(false,	/* enable IRQs */
					     false	/* disable NMIs */);
	}
	raw_local_irq_restore(flags);

	DebugKVMTI("CEPIC VIRQ #%d on CPU #%ld handled\n",
		irq, cpu);
	return ret;
}

static int kvm_do_setup_cepic_virq(bool bsp, int cpu)
{
	const char *name;
	struct notifier_block *resume_block;
	unsigned long irqflags;
	int ret;

	if (!paravirt_enabled())
		return 0;
	pr_info("installing KVM guest CEPIC VIRQ on CPU %d\n",
		cpu);

	name = kasprintf(GFP_KERNEL, "cepic/%d", cpu);
	if (!name)
		name = "<cepic kasprintf failed>";

	irqflags = kvm_get_default_virq_flags(KVM_VIRQ_CEPIC);

	if (irqflags & BY_DIRECT_INJ_VIRQ_FLAG) {
		BUG_ON(cpu != smp_processor_id());
		ret = kvm_request_virq(KVM_VIRQ_CEPIC,
				&kvm_cepic_interrupt, cpu,
				BY_DIRECT_INJ_VIRQ_FLAG,
				name, (void *) (long) cpu);
		if (ret == 0) {
			if (bsp)
				bsp_direct_virq_cepic = true;
			goto success;
		}
		DebugDIRQ("could not request direct CEPIC VIRQ %s injection\n",
			name);
	} else {
		/* unknown mode to request VIRQ delivery */
		BUG_ON(true);
		ret = -EINVAL;
	}
	if (ret) {
		panic("could not register CEPIC VIRQ #%d for CPU #%d\n",
			KVM_VIRQ_CEPIC, cpu);
	}

success:
	resume_block = &per_cpu(resume_block_cpu, cpu);
	resume_block->notifier_call = kvm_cepic_virq_panic;
	resume_block->next = NULL;
	atomic_notifier_chain_register(&panic_notifier_list, resume_block);

	if (bsp) {
		/* CEPIC support on guest is now ready, so enable */
		/* EPIC timer and set up the CEPIC timer on boot CPU */
		disable_epic_timer = false;
		setup_boot_epic_clock();
	}

	DebugKVM("KVM guest CEPIC VIRQ on CPU %d installed\n", cpu);
	return ret;
}

__init int kvm_setup_boot_cepic_virq(void)
{
	return kvm_do_setup_cepic_virq(true, raw_smp_processor_id());
}

static int
kvm_cepic_virq_panic(struct notifier_block *this,
			unsigned long event, void *ptr)
{
	return NOTIFY_DONE;
}
