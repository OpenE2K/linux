/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * KVM guest traps handling
 */

#include <linux/types.h>
#include <linux/ptrace.h>
#include <linux/uaccess.h>
#include <linux/vmalloc.h>
#include <linux/sched/debug.h>

#include <asm/cpu_regs.h>
#include <asm/regs_state.h>
#include <asm/mmu_types.h>
#include <asm/process.h>
#include <asm/traps.h>
#include <asm/trap_table.h>
#include <asm/irq_regs.h>
#include <asm/nmi.h>
#include <asm/e2k_debug.h>

#include <asm/kvm/guest/trace-hw-stacks.h>
#include <asm/kvm/guest/traps.h>

#ifdef CONFIG_USE_AAU
#include <asm/aau_context.h>
#endif

#include <asm-l/pic.h>

#include "process.h"
#include "irq.h"
#include "io.h"
#include "pic.h"

#undef	DEBUG_GUEST_TRAPS
#undef	DebugGT
#define	DEBUG_GUEST_TRAPS	0	/* guest traps trace */
#define	DebugGT(fmt, args...)						\
({									\
	if (DEBUG_GUEST_TRAPS)						\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_GUEST_INTERRUPTS
#undef	DebugINT
#define	DEBUG_GUEST_INTERRUPTS	0	/* guest interrupts trace */
#define	DebugINT(fmt, args...)						\
({									\
	if (DEBUG_GUEST_INTERRUPTS)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_GUEST_DIRECT_INTR
#undef	DebugDINT
#define	DEBUG_GUEST_DIRECT_INTR	0	/* guest interrupts trace */
#define	DebugDINT(fmt, args...)						\
({									\
	if (DEBUG_GUEST_DIRECT_INTR)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_GUEST_HS_MODE
#undef	DebugGHS
#define	DEBUG_GUEST_HS_MODE	0	/* Hard Stack expantions */
#define	DebugGHS(fmt, args...)						\
({									\
	if (DEBUG_GUEST_HS_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

#undef	DEBUG_KVM_MMIO_MODE
#undef	DebugMMIO
#define	DEBUG_KVM_MMIO_MODE	0	/* kernel KVM MMIO debugging */
#define	DebugMMIO(fmt, args...)						\
({									\
	if (DEBUG_KVM_MMIO_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

/*
 * The function handles page fault trap on address inside guest kernel:
 *	IO remapping area;
 *	VGA VRAM area
 * The function returnes 0, if it is not KVM MMIO request of guest kernel
 * and not zero value, if the fault was handled (probably with error)
 */
unsigned long kvm_do_mmio_page_fault(struct pt_regs *regs,
						trap_cellar_t *tcellar)
{
	e2k_addr_t addr;
	tc_cond_t condition;
	tc_opcode_t opcode;
	int fmt;
	u64 data;
	int size;
	bool is_write;

	addr = tcellar->address;
	DebugMMIO("started for address 0x%lx\n", addr);

	if (!kernel_mode(regs)) {
		/* trap on user and cannot be to IO */
		return 0;	/* not handled */
	}
	if (likely(addr >= GUEST_VMALLOC_START && addr < GUEST_VMALLOC_END)) {
		struct vm_struct *vm;

		vm = find_io_vm_area((const void *)addr);
		if (unlikely(vm == NULL)) {
			DebugMMIO("could not find MMIO address 0x%lx into "
				"IO remapping areas\n",
				addr);
			return 0;	/* not handled */
		}
		if (unlikely(!(vm->flags & VM_IOREMAP))) {
			DebugMMIO("MMIO address 0x%lx is not from IO "
				"remapping area\n",
				addr);
			return 0;	/* not handled */
		}
		DebugMMIO("address 0x%lx is from MMIO remapping space\n",
			addr);
	} else if (likely(KVM_IS_VGA_VRAM_VIRT_ADDR(addr))) {
		DebugMMIO("address 0x%lx is from VGA VMRAM mapping space\n",
			addr);
	} else {
		/* This address is not competence of the function */
		DebugMMIO("address 0x%lx is not from MMIO or VGA VRAM\n",
			addr);
		return 0;	/* not handled */
	}
	condition = tcellar->condition;
	WARN_ON(AS(condition).spec);	/* speculative access to IO memory */
	is_write = AS(condition).store;
	AW(opcode) = AS(tcellar->condition).opcode;
	fmt = AS(opcode).fmt;
	WARN_ON((unsigned int)fmt > 5 || fmt == 0);
	size = 1 << (fmt - 1);
	if (size > sizeof(u64))
		size = sizeof(u64);
	data = tcellar->data;

	DebugMMIO("will pass to QEMU KVM MMIO or VGA VRAM request: "
		"%s address 0x%lx, data 0x%llx, size %d, mas 0x%x\n",
		(is_write) ? "write to" : "read from",
		addr, data, size, AS(condition).mas);

	data = kvm_handle_guest_mmio((void __iomem *)addr,
					data, size, is_write);
	if (is_write) {
		DebugMMIO("writed to address 0x%lx data 0x%llx, size %d\n",
			addr, data, size);
		return true;	/* MMIO request handled */
	}
	DebugMMIO("read from address 0x%lx data 0x%llx, size %d\n",
		addr, data, size);
	/* FIXME: here should be recovery of interrupted MMU load operation */
	WARN_ON(true);

	return true;	/* MMIO request handled */
}

/*
 * The function handles kvm guest traps on hardware procedure stack overflow
 * or underflow. If stack overflow occured then the procedure stack will be
 * expanded. In the case of stack underflow it will be constricted
 */

static int kvm_proc_stack_bounds(struct pt_regs *regs)
{
	WARN_ONCE(1, "implement me");
	return -ENOSYS;
}
static int kvm_chain_stack_bounds(struct pt_regs *regs)
{
	WARN_ONCE(1, "implement me");
	return -ENOSYS;
}

int kvm_do_hw_stack_bounds(struct pt_regs *regs,
			bool proc_bounds, bool chain_bounds)
{
	int ret = 0;

	if (proc_bounds)
		ret |= kvm_proc_stack_bounds(regs);
	if (chain_bounds)
		ret |= kvm_chain_stack_bounds(regs);
	return ret;
}

int kvm_host_apply_psp_delta_to_signal_stack(unsigned long base,
			unsigned long size, unsigned long start,
			unsigned long end, unsigned long delta)
{
	int ret;

	ret = HYPERVISOR_apply_psp_bounds(base, size, start, end, delta);
	if (ret != 0) {
		pr_err("%s(): could not apply updated procedure stack "
			"boundaries, error %d\n",
			__func__, ret);
	}
	return ret;
}

int kvm_host_apply_pcsp_delta_to_signal_stack(unsigned long base,
			unsigned long size, unsigned long start,
			unsigned long end, unsigned long delta)
{
	int ret;

	ret = HYPERVISOR_apply_pcsp_bounds(base, size, start, end, delta);
	if (ret != 0) {
		pr_err("%s(): could not apply updated chain stack "
			"boundaries, error %d\n",
			__func__, ret);
	}
	return ret;
}

int kvm_host_apply_usd_delta_to_signal_stack(unsigned long top,
					unsigned long delta, bool incr)
{
	int ret;

	ret = HYPERVISOR_apply_usd_bounds(top, delta, incr);
	if (ret != 0) {
		pr_err("%s(): could not apply updated user data stack "
			"boundaries, error %d\n",
			__func__, ret);
	}
	return ret;
}

#ifdef	CONFIG_VIRQ_VCPU_INJECTION
/*
 * Real VIRQs handlers are guest kernel threads bind to the VCPU
 * So here it need only set reschedule flag to switch to VIRQs handler
 * thread before return from common traps handler.
 * The function should return number of handled interrupts.
 * FIXME: it need check on VIRQs waiting for handling to do not make
 * unnecessary processes switch
 */
static inline int kvm_virq_vcpu_intr_handler(int irq, struct pt_regs *regs)
{
	pr_err("%s(): IRQ #%d %s should be already handled\n",
		__func__, irq, kvm_get_virq_name(virq_from_irq(irq)));
	return false;
}
static inline int kvm_virq_vcpu_intr_thread(int irq, struct pt_regs *regs)
{
	set_tsk_need_resched(current);
	return true;
}
#else	/* ! CONFIG_VIRQ_VCPU_INJECTION */
static inline int kvm_virq_vcpu_intr_handler(int irq, struct pt_regs *regs)
{
	/* VIRQ VCPU and VIRQs handler can not be used */
	return 0;
}
static inline int kvm_virq_vcpu_intr_thread(int irq, struct pt_regs *regs)
{
	/* VIRQ VCPU and VIRQs handler thread can not be used */
	return 0;
}
#endif	/* CONFIG_VIRQ_VCPU_INJECTION */

#ifdef	CONFIG_DIRECT_VIRQ_INJECTION
static inline int kvm_direct_virq_intr_handler(int irq, struct pt_regs *regs)
{
	kvm_virq_info_t *virq_info;
	irq_handler_t handler;
	void *dev;
	struct pt_regs *old_regs;
	int virq;
	int virqs_num;
	int handled = 0;
	int ret;

	virq_info = virq_info_from_irq(irq);
	virq = virq_from_irq(irq);
	virqs_num = atomic_read(virq_info->count);
	DebugDINT("started for irq #%d %s, pending interrupts %d\n",
		irq, kvm_get_virq_name(virq), virqs_num);
	if (virqs_num <= 0)
		return 0;

	handler = virq_info->handler;
	BUG_ON(handler == NULL);
	dev = virq_info->dev_id;
	old_regs = set_irq_regs(regs);

	do {
		ret = handler(virq, dev);
		if (ret == IRQ_NONE) {
			/* IRQ could not be handled: */
			/* other IRQ is being handled and EOI is not yet */
			/* sent, because of new interrupt recevied while */
			/* handle_IRQ_event() enable IRQs */
			/* In this case should be one more handler below */
			/* on stack and it handle all pending IRQs */
			goto busy;
		} else if (ret != IRQ_HANDLED) {
			pr_err("%s(): failed, returns error %d\n",
				__func__, ret);
		} else {
			DebugDINT("irq #%d %s handled\n",
				irq, kvm_get_virq_name(virq));
			handled += 1;
		}
		virqs_num = atomic_dec_return(virq_info->count);
	} while (virqs_num > 0);

busy:
	set_irq_regs(old_regs);

	return handled;
}
#else	/* ! CONFIG_DIRECT_VIRQ_INJECTION */
static inline int kvm_direct_virq_intr_handler(int irq, struct pt_regs *regs)
{
	/* direct VIRQs injection mode turn off, so cannot use the handler */
	return 0;
}
#endif	/* CONFIG_DIRECT_VIRQ_INJECTION */

irqreturn_t kvm_do_interrupt(struct pt_regs *regs)
{
	int irq;
	int handled_num = 0;
	int cpu = smp_processor_id();

	for (irq = 0; irq < kvm_nr_irqs; irq++) {
		kvm_irq_info_t *info;
		kvm_virq_info_t *virq_info;
		int handled;
		int virqs_num;

		info = info_for_irq(irq);
		if (unlikely(info->type == IRQT_UNBOUND)) {
			continue;
		} else if (!is_irq_active(irq)) {
			continue;
		} else if (cpu_from_irq(irq) != cpu) {
			continue;
		} else if (unlikely(info->type != IRQT_VIRQ)) {
			pr_err("%s(): invalid type %d of virtual IRQ #%d "
				"cannot be handled\n",
				__func__, info->type, irq);
			continue;
		}
		virq_info = virq_info_from_irq(irq);
		virqs_num = atomic_read(virq_info->count);
		if (unlikely(virqs_num <= 0)) {
			DebugINT("none pending IRQs #%d %s\n",
				irq, kvm_get_virq_name(virq_from_irq(irq)));
			continue;
		}
		switch (virq_info->mode) {
		case BY_DIRECT_INJ_VIRQ_MODE:
			handled = kvm_direct_virq_intr_handler(irq, regs);
			break;
		default:
			pr_err("%s(): invalid handling mode of IRQ #%d %s\n",
				__func__, irq,
				kvm_get_virq_name(virq_from_irq(irq)));
			handled = 0;
		}
		if (likely(handled)) {
			DebugINT("handled %d interrupts of IRQ #%d %s from "
				"pending %d interrupts\n",
				handled, irq,
				kvm_get_virq_name(virq_from_irq(irq)),
				virqs_num);
			handled_num += handled;
			continue;
		}
		pr_err("%s(): could not handle none of pending %d interrupts "
			"for IRQ #%d %s\n",
			__func__, virqs_num, irq,
			kvm_get_virq_name(virq_from_irq(irq)));
	}
	DebugINT("total handled interrupts number is %d\n", handled_num);
	HYPERVISOR_virqs_handled();
	if (handled_num)
		return IRQ_HANDLED;
	else
		return IRQ_NONE;
}

irqreturn_t guest_do_interrupt(struct pt_regs *regs)
{
	return guest_do_interrupt_pic(regs);
}

/*
 * pseudo IRQ to emulate SysRq on guest kernel
 */
void kvm_sysrq_showstate_interrupt(struct pt_regs *regs)
{
	ack_pic_irq();
	/* dump stacks uses NMI to interrupt other CPUs and dump current */
	/* process state running on the CPU */
	raw_all_irq_enable();

	if (kvm_get_vcpu_state()->do_dump_state)
		show_state_filter(0);
	if (kvm_get_vcpu_state()->do_dump_stack)
		dump_stack();
	HYPERVISOR_vcpu_show_state_completion();
}

void __init_recv kvm_init_system_handlers_table(void)
{
	kvm_init_system_handlers_table_pic();
}

void __init_recv kvm_init_system_handlers_table_apic(void)
{
	/* VIRQ vector to emulate SysRq on guest kernel */
	setup_PIC_vector_handler(SYSRQ_SHOWSTATE_APIC_VECTOR,
			kvm_sysrq_showstate_interrupt, 1,
			"kvm_sysrq_showstate_interrupt");
	setup_PIC_vector_handler(KVM_NMI_APIC_VECTOR,
			(void (*)(struct pt_regs *))nmi_call_function_interrupt,
			1,
			"nmi_call_function_interrupt");
}

void __init_recv kvm_init_system_handlers_table_epic(void)
{
	/* VIRQ vector to emulate SysRq on guest kernel */
	setup_PIC_vector_handler(SYSRQ_SHOWSTATE_EPIC_VECTOR,
			kvm_sysrq_showstate_interrupt, 1,
			"kvm_sysrq_showstate_interrupt");
	setup_PIC_vector_handler(KVM_NMI_EPIC_VECTOR,
			(void (*)(struct pt_regs *))nmi_call_function_interrupt,
			1,
			"nmi_call_function_interrupt");
}
