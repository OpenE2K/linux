/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/ptrace.h>
#include <linux/init.h>
#include <linux/irq.h>
#include <linux/delay.h>
#include <linux/smp.h>
#include <linux/seq_file.h>
#include <linux/export.h>
#include <linux/cpu.h>
#include <linux/extable.h>
#include <linux/nmi.h>

#include <asm/apic.h>
#include <asm/epic.h>
#include <asm/e2k_api.h>
#include <asm/e2k.h>
#include <asm/mmu_context.h>
#include <asm/io.h>
#include <asm/iolinkmask.h>
#include <asm/machdep.h>
#include <asm/smp.h>
#include <asm/ptrace.h>
#include <asm/console.h>
#include <asm/host_printk.h>

#include <asm/sections.h>
#include <linux/uaccess.h>

#include <asm/kvm/hypercall.h>
#include <asm/kvm/guest/regs_state.h>

#include "time.h"
#include "pic.h"

#undef	DEBUG_KVM_SHUTDOWN_MODE
#undef	DebugKVMSH
#define	DEBUG_KVM_SHUTDOWN_MODE	1	/* KVM shutdown debugging */
#define	DebugKVMSH(fmt, args...)					\
({									\
	if (DEBUG_KVM_SHUTDOWN_MODE)					\
		pr_info("%s(): " fmt, __func__, ##args);		\
})

unsigned int guest_machine_id = -1;
EXPORT_SYMBOL(guest_machine_id);

static int e2k_virt_show_cpuinfo(struct seq_file *m, void *v);

extern struct exception_table_entry __start___ex_table[];
extern struct exception_table_entry __stop___ex_table[];
extern u32 __initdata __visible main_extable_sort_needed;
static void __init kvm_sort_main_extable(void);

#define	MACH_TYPE_NAME_E2K_INKNOWN_VIRT	0
#define MACH_TYPE_NAME_E2K_PARA_VIRT	1
#define	MACH_TYPE_NAME_E2K_HW_VIRT	2
#define	MACH_TYPE_NAME_E2K_HW_PARA_VIRT	3

/*
 * Machine type names.
 * Machine name can be retrieved from /proc/cpuinfo as model name.
 */
static char *kvm_cpu_type_name[] = {
	"unknown",
	"pv",
	"hv",
	"hv+pv",
};
static char *kvm_mach_type_name[] = {
	"unknown",
	"kvm-para-virt",
	"kvm-hw-virt",
	"kvm-hw-para-virt",
};
static int kvm_get_machine_type_name(void)
{
	int mach_type = MACH_TYPE_NAME_E2K_INKNOWN_VIRT;

	if (IS_HV_GM()) {
		mach_type = MACH_TYPE_NAME_E2K_HW_VIRT;
	} else {
#ifdef	CONFIG_KVM_GUEST_KERNEL
		/* it is paravirtualized guest machine */
		mach_type = MACH_TYPE_NAME_E2K_PARA_VIRT;
#endif	/* CONFIG_KVM_GUEST_KERNEL */
	}
	return mach_type;
}

/*
 * mach_type_id variable is set in setup_arch() function.
 */
static int kvm_mach_type_id = -1;

/*
 * Function to get name of virtual machine type.
 * Must be used after setup_arch().
 */
char *kvm_get_cpu_type_name(void)
{
	return kvm_cpu_type_name[kvm_mach_type_id];
}
char *kvm_get_mach_type_name(void)
{
	return kvm_mach_type_name[kvm_mach_type_id];
}
void kvm_set_mach_type_id(void)
{
	kvm_mach_type_id = kvm_get_machine_type_name();
}

static void
e2k_virt_setup_cpu_info(cpuinfo_e2k_t *cpu_info)
{
	e2k_idr_t IDR;

	IDR = read_IDR_reg();
	strncpy(cpu_info->vendor, ELBRUS_CPU_VENDOR, 16);
	cpu_info->family = E2K_VIRT_CPU_FAMILY;
	cpu_info->model  = IDR.IDR_mdl;
	cpu_info->revision = IDR.IDR_rev;
}

void e2k_virt_shutdown(void)
{
	kvm_time_shutdown();
/*
	if (current->mm && !test_ts_flag(TS_REMAP_HW_STACKS_TO_KERNEL)) {
		set_ts_flag(TS_REMAP_HW_STACKS_TO_KERNEL);
		deactivate_mm(current, current->mm);
		clear_ts_flag(TS_REMAP_HW_STACKS_TO_KERNEL);
	}
 */
	pr_err("%s(): is not implemented or deleted\n", __func__);
}

/*
 * The SHUTDOWN hypercall takes a string to describe what's happening, and
 * an argument which says whether this to restart (reboot) the Guest or not.
 *
 * Note that the Host always prefers that the Guest speak in physical addresses
 * rather than virtual addresses, so we use __pa() here.
 */
void e2k_virt_power_off(void)
{
	DebugKVMSH("started on %s (%d), cpu %d\n",
		current->comm, current->pid, smp_processor_id());
	e2k_virt_shutdown();
	HYPERVISOR_kvm_shutdown("KVM Power down", KVM_SHUTDOWN_POWEROFF);
}

/*
 * Rebooting also tells the Host we're finished, but the RESTART flag tells the
 * Launcher to reboot us.
 */
static void e2k_virt_restart_machine(char *reason)
{
	if (reason == NULL)
		reason = "Restarting system...";
	DebugKVMSH("started to %s on %s (%d) cpu %d\n",
		reason, current->comm, current->pid, smp_processor_id());
	HYPERVISOR_kvm_shutdown(reason, KVM_SHUTDOWN_RESTART);
}
static void e2k_virt_reset_machine(char *reason)
{
	DebugKVMSH("started on %s (%d)\n", current->comm, current->pid);
	e2k_virt_restart_machine("KVM reset");
}

#ifdef CONFIG_SMP
void kvm_clock_off(void)
{
	unsigned long flags;

	/* Make sure we do not race with `callin_go` write */
	raw_all_irq_save(flags);
	if (!cpumask_test_cpu(raw_smp_processor_id(), &callin_go))
		e2k_virt_restart_machine("Restarting from kvm_clock_off()");
	raw_all_irq_restore(flags);
}

void kvm_clock_on(int cpu)
{
	panic("%s(): CPU #%d cannot be called, probably is not implemented\n",
		__func__, cpu);
}
#endif

/*
 * Panicing.
 */

#define KVM_PANIC_TIMER_STEP	100
#define KVM_PANIC_BLINK_SPD	6
#define	KVM_PANIC_TIMEOUT	1

static long no_blink(int state)
{
	return 0;
}

static int kvm_panic(struct notifier_block *nb, unsigned long event, void *msg)
{
	long i, i_next = 0;
	int state = 0;

	DebugKVMSH("started: %s\n", (char *)msg);
	host_printk("%s\n", msg);
	host_dump_stack();

	/*
	 * Delay some times before rebooting the guest to wait
	 * for flush to console all important messages of kernel
	 * Here can't be used the "normal" timers since kernel just panicked.
	 */
	suppress_printk = 1;
	if (!panic_blink)
		panic_blink = no_blink;
	local_irq_enable();
	for (i = 0; i < KVM_PANIC_TIMEOUT * 1000; i += KVM_PANIC_TIMER_STEP) {
		touch_softlockup_watchdog();
		if (i >= i_next) {
			i += panic_blink(state ^= 1);
			i_next = i + 3600 / KVM_PANIC_BLINK_SPD;
		}
		msleep_interruptible(KVM_PANIC_TIMER_STEP);
	}

	e2k_virt_shutdown();
	HYPERVISOR_kvm_shutdown(msg, KVM_SHUTDOWN_PANIC);
	/* The hypercall won't return, but to keep gcc happy, we're "done". */
	return NOTIFY_DONE;
}

struct notifier_block kvm_paniced = {
	.notifier_call = kvm_panic
};

void __init
e2k_virt_setup_arch(void)
{
	machine.setup_cpu_info = e2k_virt_setup_cpu_info;
	kvm_sort_main_extable();

	/* call only to set IP to goto in case of page fault on user address */
	kvm_fast_tagged_memory_copy_user(NULL, NULL, 0, NULL,
			(ldst_rec_op_t) { .word = 0 }, (ldst_rec_op_t) { .word = 0 }, 0);
	kvm_fast_tagged_memory_set_user(NULL, 0, 0, 0, NULL, 0);
	kvm_recovery_faulted_tagged_store(0, 0, 0, 0, 0, 0, 0, 0, 0, 0);
	kvm_recovery_faulted_load(0, NULL, NULL, 0, 0, (tc_cond_t) { .word = 0 });
	kvm_recovery_faulted_move(0, 0, 0, 0, 0, 0, 0, 0, 0, (tc_cond_t) { .word = 0 });
	kvm_recovery_faulted_load_to_greg(0, 0, 0, 0, 0, 0, 0, NULL, NULL,
					  (tc_cond_t) { .word = 0 });
}

int e2k_virt_get_vector_apic(void)
{
	int vector;

	vector = arch_apic_read(APIC_VECT);
	if (vector < 0)
		return vector;

	vector = APIC_VECT_VECTOR(vector);
	if (vector == KVM_NMI_APIC_VECTOR) {
		/* on guest NMI IPI implemented as general Local APIC */
		/* interrupt with vector KVM_NMI_APIC_VECTOR */
		/* but nmi_call_function_interrupt() should be called */
		/* under NMI disabled */
		KVM_INIT_KERNEL_IRQ_MASK_REG(false,	/* enable IRQs */
					     true	/* disable NMIs */);
		entering_ack_irq();
	}
	return vector;
}

#ifdef CONFIG_EPIC
int e2k_virt_get_vector_epic(void)
{
	union cepic_vect_inta reg_inta;

	reg_inta.raw = epic_read_w(CEPIC_VECT_INTA);
	if (reg_inta.bits.vect < 0)
		return reg_inta.raw;
	if (reg_inta.bits.vect == KVM_NMI_EPIC_VECTOR) {
		/* on guest NMI IPI implemented as general Local APIC */
		/* interrupt with vector KVM_NMI_APIC_VECTOR */
		/* but nmi_call_function_interrupt() should be called */
		/* under NMI disabled */
		KVM_INIT_KERNEL_IRQ_MASK_REG(false,	/* enable IRQs */
					     true	/* disable NMIs */);
		irq_enter();
		ack_epic_irq();
	}
	return reg_inta.raw;
}
#endif

#ifdef CONFIG_IOHUB_DOMAINS
/*
 * This e2k virtual machine has not IO link and is connect to VIRTIO controller
 * through virtual North breadge, so it has only one IO bus and PCI domain # 0
 */
void __init
e2k_virt_create_io_config(void)
{
	char src_buffer[80];
	char *buffer = src_buffer;

	iolinks_num = 1;
	iohub_set(0, iolink_iohub_map);
	iohub_set(0, iolink_online_iohub_map);
	iolink_iohub_num = 1;
	iolink_online_iohub_num = 1;
	buffer += iolinkmask_scnprintf(buffer, 80, iolink_online_iohub_map);
	buffer[0] = '\0';
}
#endif /* CONFIG_IOHUB_DOMAINS */

__init
void setup_guest_interface(void)
{
	if (machine.native_iset_ver >= E2K_ISET_V5) {
		machine.save_gregs = save_glob_regs_v5;
		machine.save_gregs_dirty_bgr = save_glob_regs_dirty_bgr_v5;
		machine.save_local_gregs = save_local_glob_regs_v5;
		machine.restore_gregs = restore_glob_regs_v5;
		machine.restore_local_gregs = restore_local_glob_regs_v5;
	} else if (machine.native_iset_ver >= E2K_ISET_V3) {
		machine.save_gregs = save_glob_regs_v3;
		machine.save_gregs_dirty_bgr = save_glob_regs_dirty_bgr_v3;
		machine.save_local_gregs = save_local_glob_regs_v3;
		machine.restore_gregs = restore_glob_regs_v3;
		machine.restore_local_gregs = restore_local_glob_regs_v3;
	} else {
		BUG_ON(true);
	}

	if (IS_HV_GM()) {
		if (machine.native_iset_ver < E2K_ISET_V6) {
			panic("%s(): native host ISET version #%d is "
				"too old to support hardware "
				"virtualization\n",
				__func__, machine.native_iset_ver);
		}
	} else {
	}
}

/*
 * virtual machine is not NUMA type machine
 */
void __init
e2k_virt_setup_machine(void)
{
	BUILD_BUG_ON(IS_ENABLED(CONFIG_E2K_MACHINE) && !IS_ENABLED(CONFIG_KVM_GUEST_KERNEL));

	machine.setup_arch	= e2k_virt_setup_arch;
	machine.init_IRQ	= e2k_init_IRQ;
	machine.restart		= e2k_virt_restart_machine;
	machine.power_off	= e2k_virt_power_off;
	machine.show_cpuinfo	= e2k_virt_show_cpuinfo;
	machine.halt		= e2k_virt_power_off;
	machine.arch_reset	= e2k_virt_reset_machine;
	machine.arch_halt	= e2k_virt_power_off;
	machine.get_irq_vector	= e2k_virt_get_vector;

#ifdef CONFIG_SMP
	machine.clk_off = kvm_clock_off;
	machine.clk_on = kvm_clock_on;
#endif

	setup_guest_interface();

#ifdef CONFIG_IOHUB_DOMAINS
	e2k_virt_create_io_config();
#endif /* CONFIG_IOHUB_DOMAINS */

	/* Hook in our special panic hypercall code. */
	atomic_notifier_chain_register(&panic_notifier_list, &kvm_paniced);
}

void kvm_print_machine_type_info(void)
{
	const char *mach_type = "?????????????";
	const char *cpu_type = "?????????????";

	mach_type = kvm_get_mach_type_name();
	cpu_type = kvm_get_cpu_type_name();
	pr_cont("GUEST  MACHINE TYPE: %s-%s, ID %04x, REVISION: %03x, ISET #%d "
		"VIRTIO\n",
		mach_type, cpu_type,
		guest_machine_id,
		machine.guest.rev, machine.guest.iset_ver);
	native_print_machine_type_info();
}

static int e2k_virt_show_cpuinfo(struct seq_file *m, void *v)
{
	struct cpuinfo_e2k *c = v;
	u8 cputype;

#ifdef CONFIG_SMP
#	define cpunum	(c->cpu)
#else
#	define cpunum	0
#endif

#ifdef CONFIG_SMP
	if (!cpu_online(cpunum))
		return 0;
#endif

	/*
	 * Boot is brain-dead and takes cpu_type from RAM, so one should use
	 * cpu_type from boot in borderline case only ("fake" cpu).
	 */
	cputype = c->model;

	seq_printf(m,	"VCPU\t\t: %d\n"
			"native CPUs\t: %s\n"
			"vendor_id\t: %s\n"
			"cpu family\t: %d\n"
			"model\t\t: %d\n"
			"model name\t: %s\n"
			"revision\t: %u\n"
			"cpu MHz\t\t: %llu.%02llu\n",
			cpunum, native_get_mach_type_name(), c->vendor,
			c->family, c->model, GET_CPU_TYPE_NAME(cputype),
			c->revision, c->proc_freq / 1000000,
			c->proc_freq % 1000000);
	seq_printf(m,	"bogomips\t: %lu.%02lu\n\n",
			loops_per_jiffy / (500000 / HZ),
			(loops_per_jiffy / (5000 / HZ)) % 100);

	return 0;
}

/* Sort the guest kernel's built-in exception table */
/* Guest exception table can be protected on write into kernel image, */
/* so it need sort by 'physical' addresses of image */
static void __init kvm_sort_main_extable(void)
{
	struct exception_table_entry *start = __start___ex_table;
	struct exception_table_entry *end = __stop___ex_table;

	if (main_extable_sort_needed && start < end) {
		start = (struct exception_table_entry *)
				kernel_address_to_pva((e2k_addr_t)start);
		end = (struct exception_table_entry *)
				kernel_address_to_pva((e2k_addr_t)end);
		pr_notice("Sorting __ex_table from %px to %px ...\n",
			start, end);
		sort_extable(start, end);
		main_extable_sort_needed = 0;
	}
}
