/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#include <linux/clockchips.h>
#include <linux/irq.h>
#include <linux/syscore_ops.h>

#include <asm/epic.h>
#include <asm/smp.h>
#include <asm/irq_regs.h>
#include <asm/hw_irq.h>
#include <asm/thread_info.h>
#include <asm/sic_regs.h>
#include <asm/io_epic.h>
#include <asm/apic.h>
#ifdef CONFIG_E2K
#include <linux/kvm_host.h>
#include <asm/e2k-iommu.h>
#include <asm/kvm/async_pf.h>
#include <asm/traps.h>
#include <asm/nmi.h>
#endif

/*
 * TODO Although boot_cpu_physical_apicid and phys_cpu_present_map are defined
 * in apic.c, they are used in several other files. Since EPIC is always
 * compiled along with APIC, those variables are referenced here directly
 */

static unsigned int epic_num_processors;

/* Disable CEPIC timer from kernel cmdline */
bool disable_epic_timer;

/* Enable CEPIC debugging from kernel cmdline */
bool epic_debug = false;

bool epic_bgi_mode;

/* Enable pcsm_adjust daemon from kernel cmdline */
bool pcsm_adjust_enable;
EXPORT_SYMBOL(pcsm_adjust_enable);

/*
 * The value written to CEPIC_TIMER_INIT register, that corresponds to HZ timer
 * interrupt frequency
 */
static unsigned int cepic_timer_freq;

#define	EPIC_DIVISOR	1

/* Accessing PREPIC registers */
unsigned int early_prepic_node_read_w(int node, unsigned int reg)
{
	return early_sic_read_node_nbsr_reg(node, reg);
}

void early_prepic_node_write_w(int node, unsigned int reg, unsigned int v)
{
	early_sic_write_node_nbsr_reg(node, reg, v);
}

/* FIXME Use early_sic_read in guest to avoid mas 0x13 reads/writes in guest */
unsigned int prepic_node_read_w(int node, unsigned int reg)
{
	if (paravirt_enabled())
		return early_prepic_node_read_w(node, reg);
	else
		return sic_read_node_nbsr_reg(node, reg);
}

void prepic_node_write_w(int node, unsigned int reg, unsigned int v)
{
	if (paravirt_enabled())
		early_prepic_node_write_w(node, reg, v);
	else
		sic_write_node_nbsr_reg(node, reg, v);
}

#if 0
static inline unsigned int prepic_read_w(unsigned int reg)
{
	if (paravirt_enabled())
		return early_prepic_read_w(reg);
	else
		return sic_read_nbsr_reg(reg);
}

static inline void prepic_write_w(unsigned int reg, unsigned int v)
{
	if (paravirt_enabled())
		early_prepic_write_w(reg, v);
	else
		sic_write_nbsr_reg(reg, v);
}
#endif

static int cepic_timer_set_periodic(struct clock_event_device *evt)
{
	union cepic_timer_lvtt reg_lvtt;
	union cepic_timer_div reg_div;

	reg_lvtt.raw = 0;
	reg_lvtt.bits.mode = 1;
	reg_lvtt.bits.vect = CEPIC_TIMER_VECTOR;
	epic_write_w(CEPIC_TIMER_LVTT, reg_lvtt.raw);

	/* Do not divide EPIC timer frequency */
	reg_div.raw = 0;
	reg_div.bits.divider = CEPIC_TIMER_DIV_1;
	epic_write_w(CEPIC_TIMER_DIV, reg_div.raw);

	epic_write_w(CEPIC_TIMER_INIT, cepic_timer_freq / HZ);

	epic_printk("set EPIC timer to periodic mode on CPU #%d: HZ %d Mhz",
		smp_processor_id(), HZ);

	return 0;
}

static int cepic_timer_set_oneshot(struct clock_event_device *evt)
{
	union cepic_timer_lvtt reg_lvtt;
	union cepic_timer_div reg_div;

	reg_lvtt.raw = 0;
	reg_lvtt.bits.vect = CEPIC_TIMER_VECTOR;
	epic_write_w(CEPIC_TIMER_LVTT, reg_lvtt.raw);

	/* Do not divide EPIC timer frequency */
	reg_div.raw = 0;
	reg_div.bits.divider = CEPIC_TIMER_DIV_1;
	epic_write_w(CEPIC_TIMER_DIV, reg_div.raw);

	epic_printk("set EPIC timer to oneshot mode on CPU #%d",
		smp_processor_id());

	return 0;
}

/*
 * Program the next event, relative to now
 */
static int cepic_next_event(unsigned long delta,
			    struct clock_event_device *evt)
{
	epic_write_w(CEPIC_TIMER_INIT, delta);
	return 0;
}

/* Stop generating timer interrupts and mask them */
static int cepic_timer_shutdown(struct clock_event_device *evt)
{
	union cepic_timer_lvtt reg;

	reg.raw = epic_read_w(CEPIC_TIMER_LVTT);
	reg.bits.mask = 1;
	epic_write_w(CEPIC_TIMER_LVTT, reg.raw);
	epic_write_w(CEPIC_TIMER_INIT, 0);

	return 0;
}

/*
 * The cepic timer can be used for any function which is CPU local.
 * Broadcast is not supported
 */
static struct clock_event_device cepic_clockevent = {
	.name		= "cepic",
	.features	= CLOCK_EVT_FEAT_ONESHOT | CLOCK_EVT_FEAT_PERIODIC,
	.shift		= 32,
	.set_state_shutdown	= cepic_timer_shutdown,
	.set_state_periodic	= cepic_timer_set_periodic,
	.set_state_oneshot	= cepic_timer_set_oneshot,
	.set_next_event		= cepic_next_event,
	.broadcast		= NULL,
	.rating			= 100,
	.irq			= -1,
};
static DEFINE_PER_CPU(struct clock_event_device, cepic_events);

/*
 * Setup the CEPIC timer for this CPU. Copy the initialized values
 * of the boot CPU and register the clock event in the framework.
 */
static void setup_epic_timer(void)
{
	struct clock_event_device *levt = this_cpu_ptr(&cepic_events);

	memcpy(levt, &cepic_clockevent, sizeof(*levt));
	levt->cpumask = cpumask_of(smp_processor_id());
	clockevents_config_and_register(levt, cepic_timer_freq,
		0xF, 0xFFFFFFFF);
}

/*
 * Setup the boot EPIC timer
 *
 * cepic_timer_freq is set from MP table. No need for calibration
 */
void __init setup_boot_epic_clock(void)
{
	/*
	 * The CEPIC timer can be disabled via the kernel cmdline. Ignore it.
	 */
	if (disable_epic_timer) {
		pr_info("Disabling EPIC timer\n");
		return;
	}

	/* Register CEPIC timer clockevent */
	setup_epic_timer();
}

void setup_secondary_epic_clock(void)
{
	if (disable_epic_timer)
		pr_info("Disabling EPIC timer\n");
	else
		setup_epic_timer();
}

static void __epic_smp_spurious_interrupt(void)
{
	ack_epic_irq();
	inc_irq_stat(irq_spurious_count);

	pr_info("Spurious EPIC interrupt on CPU#%d\n", smp_processor_id());
}

__visible void epic_smp_spurious_interrupt(struct pt_regs *regs)
{
	l_irq_enter();
	__epic_smp_spurious_interrupt();
	l_irq_exit();
}

/* Write 0 to CEPIC_ESR before reading it */
static void __epic_smp_error_interrupt(void)
{
	union cepic_esr reg;

	epic_write_w(CEPIC_ESR, 0);
	reg.raw = epic_read_w(CEPIC_ESR);

	ack_epic_irq();
	atomic_inc(&irq_err_count);

	printk(KERN_INFO "EPIC error on CPU%d: 0x%x", smp_processor_id(), reg.raw);

	if (reg.bits.rq_addr_err)
		printk(KERN_CONT " : Illegal regsiter address");

	if (reg.bits.rq_virt_err)
		printk(KERN_CONT " : Illegal virt request (virt disabled)");

	if (reg.bits.rq_cop_err)
		printk(KERN_CONT " : Illegal opcode");

	if (reg.bits.ms_gstid_err)
		printk(KERN_CONT " : Illegal guest id");

	if (reg.bits.ms_virt_err)
		printk(KERN_CONT " : Illegal virt message (virt disabled)");

	if (reg.bits.ms_err)
		printk(KERN_CONT " : Illegal message");

	if (reg.bits.ms_icr_err)
		printk(KERN_CONT " : Illegal write to CEPIC_ICR");

	printk(KERN_CONT "\n");
}

__visible void epic_smp_error_interrupt(struct pt_regs *regs)
{
	l_irq_enter();
	__epic_smp_error_interrupt();
	l_irq_exit();
}

static void __prepic_smp_error_interrupt(void)
{
	unsigned int stat, msg_hi, msg_lo;
	int node;
	for_each_online_node(node) {
		stat = prepic_node_read_w(node, SIC_prepic_err_stat);
		if (!stat)
			continue;

		msg_hi = prepic_node_read_w(node, SIC_prepic_err_msg_hi);
		msg_lo = prepic_node_read_w(node, SIC_prepic_err_msg_lo);
		prepic_node_write_w(node, SIC_prepic_err_stat, stat);

		pr_err("PREPIC#%d err: stat 0x%x, msg_hi 0x%x, msg_lo 0x%x\n",
			node, stat, msg_hi, msg_lo);
	}

	ack_epic_irq();
	atomic_inc(&irq_err_count);
}

__visible void prepic_smp_error_interrupt(struct pt_regs *regs)
{
	l_irq_enter();
	__prepic_smp_error_interrupt();
	l_irq_exit();
}

#ifdef CONFIG_KVM_ASYNC_PF
__visible void epic_pv_apf_wake(struct pt_regs *regs)
{
	l_irq_enter();

	if (pv_apf_read_and_reset_reason() == KVM_APF_PAGE_READY)
		pv_apf_wake();
	else
		pr_err("Guest: async_pf, got spurious "
			"ASYNC_PF_WAKE_VECTOR exception\n");

	ack_epic_irq();

	l_irq_exit();
}
#endif /* CONFIG_KVM_ASYNC_PF */

static void set_cepic_timer_frequency(unsigned int freq)
{
	/*
	 * Boot should have passed CEPIC timer frequency in MP table
	 * Assume 100 MHz, if it didn't, and passed 0 instead
	 */
	if (!freq) {
		pr_warn("Boot did not pass CEPIC timer frequency\n");
		freq = 100000000; /* 100 MHz */
	}

	pr_info_once("EPIC timer frequency is %d.%d MHz\n",
			freq / 1000000, freq % 1000000 / 100000);
	cepic_timer_freq = freq;
}

int get_cepic_timer_frequency(void)
{
	return cepic_timer_freq;
}

/*
 * E2K depends on the "hard" cpu number to determine NUMA node,
 * so we must exclude the influence of the order in which all
 * processors get here.
 */
void epic_processor_info(int epicid, int version, unsigned int cepic_freq)
{
	unsigned int bsp_id = read_epic_id();
	bool boot_cpu_detected = physid_isset(bsp_id, phys_cpu_present_map);
	int cpu;

	boot_cpu_physical_apicid = bsp_id;

	/*
	 * If boot cpu has not been detected yet, then only allow upto
	 * nr_cpu_ids - 1 processors and keep one slot free for boot cpu
	 */
	if (!boot_cpu_detected && epic_num_processors >= nr_cpu_ids - 1 &&
	    epicid != bsp_id) {
		pr_warn("NR_CPUS=%d limit was reached", nr_cpu_ids);
		pr_warn("Ignoring CPU#%d to keep a slot for boot CPU", epicid);
		return;
	}

	if (epic_num_processors >= nr_cpu_ids) {
		pr_warn("NR_CPUS=%d limit was reached", nr_cpu_ids);
		pr_warn("Ignoring CPU#%d", epicid);
		return;
	}

	epic_num_processors++;

	if (epicid == boot_cpu_physical_apicid) {
		/* Logical cpuid 0 is reserved for BSP. */
		cpu = 0;
		cpuid_to_picid[0] = epicid;
	} else {
		cpu = allocate_logical_cpuid(epicid);
	}

	if (epicid >= MAX_PHYSID_NUM)
		panic("EPIC id from MP table exceeds %d\n", MAX_PHYSID_NUM);

	physid_set(epicid, phys_cpu_present_map);

	early_per_cpu(cpu_to_picid, cpu) = epicid;

	set_cpu_possible(cpu, true);
	set_cpu_present(cpu, true);

	set_cepic_timer_frequency(cepic_freq);
}

/*
 * The guts of the cepic timer interrupt
 */
void cepic_timer_interrupt(void)
{
	int cpu = smp_processor_id();
	struct clock_event_device *evt = &per_cpu(cepic_events, cpu);

	/*
	 * the NMI deadlock-detector uses this.
	 */
	inc_irq_stat(apic_timer_irqs);

	evt->event_handler(evt);
}

#define DELTA_NS	(NSEC_PER_SEC / HZ / 2)

/*
 * CEPIC timer interrupt. This is the most natural way for doing
 * local interrupts, but local timer interrupts can be emulated by
 * broadcast interrupts too. [in case the hw doesn't support CEPIC timers]
 *
 * [ if a single-CPU system runs an SMP kernel then we call the local
 *   interrupt as well. Thus we cannot inline the local irq ... ]
 */
__visible void __irq_entry epic_smp_timer_interrupt(struct pt_regs *regs)
{
	struct pt_regs *old_regs = set_irq_regs(regs);
	int cpu;
	long long cur_time;
	long long next_time;

	cpu = smp_processor_id();
	next_time = per_cpu(next_rt_intr, cpu);
	if (next_time) {
		cur_time = ktime_to_ns(ktime_get());
		if (cur_time > next_time + DELTA_NS) {
			per_cpu(next_rt_intr, cpu) = 0;
		} else if (cur_time > next_time - DELTA_NS &&
				cur_time < next_time + DELTA_NS) {
			/*
			 * set 1 -- must do timer later
			 * in do_postpone_tick()
			 */
			per_cpu(next_rt_intr, cpu) = 1;
			set_irq_regs(old_regs);
			ack_epic_irq();
			/* if do_postpone_tick() will not called: */
			epic_write_w(CEPIC_TIMER_INIT,
				usecs_2cycles(USEC_PER_SEC / HZ));
			return;
		}
	}

	/*
	 * NOTE! We'd better ACK the irq immediately,
	 * because timer handling can be slow.
	 *
	 * update_process_times() expects us to have done l_irq_enter().
	 * Besides, if we don't timer interrupts ignore the global
	 * interrupt lock, which is the WrongThing (tm) to do.
	 */
	l_irq_enter();
	ack_epic_irq();
	cepic_timer_interrupt();
	l_irq_exit();

	set_irq_regs(old_regs);
}

/*
 * TODO clear_cepic - shutdown CEPIC
 *
 * This is called, when a CPU is disabled and before rebooting, so the state of
 * the CEPIC has no dangling leftovers. Also used to cleanout any BIOS
 * leftovers during boot.
 */
void clear_cepic(void)
{
}

/*
 * A fake APIC driver, provided by EPIC for compatibility with existing code
 * (mostly IOAPIC). The uninitialized fields should not be used
 */
static struct apic epic	= {
	.name				= "epic",

	.irq_delivery_mode		= dest_Fixed,
	.irq_dest_mode			= 0,

	.target_cpus			= online_target_cpus,
	.check_apicid_used		= default_check_apicid_used,

	.vector_allocation_domain	= default_vector_allocation_domain,

	.ioapic_phys_id_map		= default_ioapic_phys_id_map,
	.apicid_to_cpu_present		= physid_set_mask_of_physid,
	.check_phys_apicid_present	= default_check_phys_apicid_present,

	.cpu_mask_to_apicid_and		= default_cpu_mask_to_apicid_and,

	.send_IPI_mask			= epic_send_IPI_mask,
	.send_IPI_self			= epic_send_IPI_self,
	.send_IPI_mask_allbutself	= epic_send_IPI_mask_allbutself
};

/*
 * TODO Placeholder for various EPIC sanity checks
 */
void __init_recv verify_epic(void)
{
}

/*
 * Used to setup CEPIC while initializing BSP or bringing up APs
 * Always called with preemption disabled
 */
void setup_cepic(void)
{
	union cepic_ctrl reg_ctrl;
	union cepic_svr reg_svr;
	union cepic_esr2 reg_esr2;
	unsigned int epic_id = read_epic_id();

	/* Enable CEPIC */
	reg_ctrl.raw = epic_read_w(CEPIC_CTRL);
	reg_ctrl.bits.soft_en = 1;
	epic_write_w(CEPIC_CTRL, reg_ctrl.raw);

	/* Set up spurious IRQ vector */
	reg_svr.raw = 0;
	reg_svr.bits.vect = SPURIOUS_EPIC_VECTOR;
	epic_write_w(CEPIC_SVR, reg_svr.raw);

	/* Set up Error Status Register */
	reg_esr2.raw = 0;
	reg_esr2.bits.vect = ERROR_EPIC_VECTOR;
	epic_write_w(CEPIC_ESR2, reg_esr2.raw);

	epic_printk("CEPIC %d is set up\n", epic_id);
}

/* Set first cepic on node as destination for LINP and ERR and unmask them */
static void __init_recv __setup_prepic(unsigned int node)
{
#ifdef CONFIG_E2K
	union prepic_linpn reg;
	union prepic_err_int reg_err;
	unsigned int dest = cpumask_first(cpumask_of_node(node));

	if (dest >= nr_cpu_ids) {
		pr_err("Failed to find online cpu on node %d. PREPIC err and linp are routed to bsp\n",
			node);
		dest = boot_cpu_physical_apicid;
	}

	dest = cpu_to_full_cepic_id(dest);

	/*
	 * Setting up and unmasking PREPIC interrupts:
	 * - PREPIC error interrupt
	 * - LINP0 - emergency interrupt from HC
	 * - LINP1 - IOMMU interrupt
	 * - LINP2 - Uncore interrupt
	 * - LINP3 - IPCC interrupt
	 * - LINP4 - non-emergency interrupt from HC
	 * - LINP5 - Power Control (PCS) interrupt
	 */

	reg_err.raw = 0;
	reg_err.bits.dst = dest;
	reg_err.bits.vect = PREPIC_ERROR_VECTOR;
	prepic_node_write_w(node, SIC_prepic_err_int, reg_err.raw);

	reg.raw = 0;
	reg.bits.dst = dest;
	reg.bits.vect = LINP0_INTERRUPT_VECTOR;
	prepic_node_write_w(node, SIC_prepic_linp0, reg.raw);

	reg.raw = 0;
	reg.bits.dst = dest;
	reg.bits.vect = LINP1_INTERRUPT_VECTOR;
	prepic_node_write_w(node, SIC_prepic_linp1, reg.raw);

	reg.raw = 0;
	reg.bits.dst = dest;
	reg.bits.vect = LINP2_INTERRUPT_VECTOR;
	prepic_node_write_w(node, SIC_prepic_linp2, reg.raw);

	reg.raw = 0;
	reg.bits.dst = dest;
	reg.bits.vect = LINP3_INTERRUPT_VECTOR;
	prepic_node_write_w(node, SIC_prepic_linp3, reg.raw);

	reg.raw = 0;
	reg.bits.dst = dest;
	reg.bits.vect = LINP4_INTERRUPT_VECTOR;
	prepic_node_write_w(node, SIC_prepic_linp4, reg.raw);

	reg.raw = 0;
	reg.bits.dst = dest;
	reg.bits.vect = LINP5_INTERRUPT_VECTOR;
	prepic_node_write_w(node, SIC_prepic_linp5, reg.raw);
#endif
	epic_printk("PREPIC %d is set up\n", node);
}

void __init_recv setup_prepic(void)
{
	unsigned int node;

	for_each_online_node(node)
		__setup_prepic(node);
}

void __init setup_bsp_epic(void)
{
	/*
	 * Fake APIC driver for compatibility with existing IOAPIC code
	 */
	apic = &epic;

	/* Various EPIC sanity checks */
	verify_epic();

	setup_cepic();
}

struct saved_cepic_regs {
	bool valid;
	u32 cepic_id;
	u32 cepic_cpr;
	u32 cepic_esr;
	u32 cepic_esr2;
	u32 cepic_cir;
	u32 cepic_icr;
	u32 cepic_icr2;
	u32 cepic_timer_lvtt;
	u32 cepic_timer_init;
	u32 cepic_timer_cur;
	u32 cepic_timer_div;
	u32 cepic_nm_timer_lvtt;
	u32 cepic_nm_timer_init;
	u32 cepic_nm_timer_cur;
	u32 cepic_nm_timer_div;
	u32 cepic_svr;
	u32 cepic_pnmirr_mask;
};

static void save_cepic(void *cepic_regs)
{
	struct saved_cepic_regs *regs = cepic_regs;

	regs->cepic_id = epic_read_w(CEPIC_ID);
	regs->cepic_cpr = epic_read_w(CEPIC_CPR);
	regs->cepic_esr = epic_read_w(CEPIC_ESR);
	regs->cepic_esr2 = epic_read_w(CEPIC_ESR2);

	/* CEPIC_EOI is write-only */

	regs->cepic_cir = epic_read_w(CEPIC_CIR);

	/* Reading CEPIC_PNMIRR starts NMI handling */

	regs->cepic_icr = epic_read_w(CEPIC_ICR);
	regs->cepic_icr2 = epic_read_w(CEPIC_ICR2);
	regs->cepic_timer_lvtt = epic_read_w(CEPIC_TIMER_LVTT);
	regs->cepic_timer_init = epic_read_w(CEPIC_TIMER_INIT);
	regs->cepic_timer_cur = epic_read_w(CEPIC_TIMER_CUR);
	regs->cepic_timer_div = epic_read_w(CEPIC_TIMER_DIV);
	regs->cepic_nm_timer_lvtt = epic_read_w(CEPIC_NM_TIMER_LVTT);
	regs->cepic_nm_timer_init = epic_read_w(CEPIC_NM_TIMER_INIT);
	regs->cepic_nm_timer_cur = epic_read_w(CEPIC_NM_TIMER_CUR);
	regs->cepic_nm_timer_div = epic_read_w(CEPIC_NM_TIMER_DIV);
	regs->cepic_svr = epic_read_w(CEPIC_SVR);
	regs->cepic_pnmirr_mask = epic_read_w(CEPIC_PNMIRR_MASK);

	regs->valid = true;
}

static void print_saved_cepic(int cpu, struct saved_cepic_regs *regs)
{
	pr_info("Printing CEPIC contents on CPU#%d:\n", cpu);
	pr_info("... CEPIC_ID: 0x%x\n", regs->cepic_id);
	pr_info("... CEPIC_CPR: 0x%x\n", regs->cepic_cpr);
	pr_info("... CEPIC_ESR: 0x%x\n", regs->cepic_esr);
	pr_info("... CEPIC_ESR2: 0x%x\n", regs->cepic_esr2);

	/* CEPIC_EOI is write-only */

	pr_info("... CEPIC_CIR: 0x%x\n", regs->cepic_cir);

	/* Reading CEPIC_PNMIRR starts NMI handling */

	pr_info("... CEPIC_ICR: 0x%x\n", regs->cepic_icr);
	pr_info("... CEPIC_ICR2: 0x%x\n", regs->cepic_icr2);
	pr_info("... CEPIC_TIMER_LVTT: 0x%x\n", regs->cepic_timer_lvtt);
	pr_info("... CEPIC_TIMER_INIT: 0x%x\n", regs->cepic_timer_init);
	pr_info("... CEPIC_TIMER_CUR: 0x%x\n", regs->cepic_timer_cur);
	pr_info("... CEPIC_TIMER_DIV: 0x%x\n", regs->cepic_timer_div);
	pr_info("... CEPIC_NM_TIMER_LVTT: 0x%x\n",
			regs->cepic_nm_timer_lvtt);
	pr_info("... CEPIC_NM_TIMER_INIT: 0x%x\n",
			regs->cepic_nm_timer_init);
	pr_info("... CEPIC_NM_TIMER_CUR: 0x%x\n", regs->cepic_nm_timer_cur);
	pr_info("... CEPIC_NM_TIMER_DIV: 0x%x\n", regs->cepic_nm_timer_div);
	pr_info("... CEPIC_SVR: 0x%x\n", regs->cepic_svr);
	pr_info("... CEPIC_PNMIRR_MASK: 0x%x\n", regs->cepic_pnmirr_mask);
}

static void print_cepic(void *dummy)
{
	unsigned int v;

	pr_info("Printing CEPIC contents on CPU#%d:\n",
		smp_processor_id());
	v = epic_read_w(CEPIC_ID);
	pr_info("... CEPIC_ID: 0x%x\n", v);

	v = epic_read_w(CEPIC_CPR);
	pr_info("... CEPIC_CPR: 0x%x\n", v);

	v = epic_read_w(CEPIC_ESR);
	pr_info("... CEPIC_ESR: 0x%x\n", v);

	v = epic_read_w(CEPIC_ESR2);
	pr_info("... CEPIC_ESR2: 0x%x\n", v);

	/* CEPIC_EOI is write-only */

	v = epic_read_w(CEPIC_CIR);
	pr_info("... CEPIC_CIR: 0x%x\n", v);

	/* Reading CEPIC_PNMIRR starts NMI handling */

	v = epic_read_w(CEPIC_ICR);
	pr_info("... CEPIC_ICR: 0x%x\n", v);

	v = epic_read_w(CEPIC_ICR2);
	pr_info("... CEPIC_ICR2: 0x%x\n", v);

	v = epic_read_w(CEPIC_TIMER_LVTT);
	pr_info("... CEPIC_TIMER_LVTT: 0x%x\n", v);

	v = epic_read_w(CEPIC_TIMER_INIT);
	pr_info("... CEPIC_TIMER_INIT: 0x%x\n", v);

	v = epic_read_w(CEPIC_TIMER_CUR);
	pr_info("... CEPIC_TIMER_CUR: 0x%x\n", v);

	v = epic_read_w(CEPIC_TIMER_DIV);
	pr_info("... CEPIC_TIMER_DIV: 0x%x\n", v);

	v = epic_read_w(CEPIC_NM_TIMER_LVTT);
	pr_info("... CEPIC_NM_TIMER_LVTT: 0x%x\n", v);

	v = epic_read_w(CEPIC_NM_TIMER_INIT);
	pr_info("... CEPIC_NM_TIMER_INIT: 0x%x\n", v);

	v = epic_read_w(CEPIC_NM_TIMER_CUR);
	pr_info("... CEPIC_NM_TIMER_CUR: 0x%x\n", v);

	v = epic_read_w(CEPIC_NM_TIMER_DIV);
	pr_info("... CEPIC_NM_TIMER_DIV: 0x%x\n", v);

	v = epic_read_w(CEPIC_SVR);
	pr_info("... CEPIC_SVR: 0x%x\n", v);

	v = epic_read_w(CEPIC_PNMIRR_MASK);
	pr_info("... CEPIC_PNMIRR_MASK: 0x%x\n", v);
}

static void print_prepics(void)
{
	int node;
	unsigned int v;

	for_each_online_node(node) {
		pr_info("Printing PREPIC#%d:\n", node);

		v = prepic_node_read_w(node, SIC_prepic_version);
		pr_info("... PREPIC_VERSION: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_ctrl);
		pr_info("... PREPIC_CTRL: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_id);
		pr_info("... PREPIC_ID: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_ctrl2);
		pr_info("... PREPIC_CTRL2: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_err_int);
		pr_info("... PREPIC_ERR_INT: 0x%x\n", v);
#ifdef CONFIG_E2K
		v = prepic_node_read_w(node, SIC_prepic_linp0);
		pr_info("... PREPIC_LINP0: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_linp1);
		pr_info("... PREPIC_LINP1: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_linp2);
		pr_info("... PREPIC_LINP2: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_linp3);
		pr_info("... PREPIC_LINP3: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_linp4);
		pr_info("... PREPIC_LINP4: 0x%x\n", v);

		v = prepic_node_read_w(node, SIC_prepic_linp5);
		pr_info("... PREPIC_LINP5: 0x%x\n", v);
#endif
	}
}

int print_epics(bool force)
{
	int cpu;

	if (!force && !epic_debug)
		return 1;

	preempt_disable();
	for_each_online_cpu(cpu) {
		struct saved_cepic_regs regs;

		if (cpu == smp_processor_id()) {
			print_cepic(NULL);
			continue;
		}

		regs.valid = false;
#ifdef CONFIG_E2K
		/* This function can be called through SysRq under
		 * disabled interrupts, so we have to be careful
		 * and use nmi_call_function() with a timeout
		 * instead of smp_call_function(). */
		nmi_call_function_single(cpu, save_cepic, &regs, 1, 30000);
#else
		smp_call_function_single(cpu, save_cepic, &regs, 1);
#endif
		if (regs.valid)
			print_saved_cepic(cpu, &regs);
	}
	preempt_enable();

	print_prepics();

	return 0;
}

static int __init epic_set_debug(char *arg)
{
	epic_debug = true;
	return 0;
}
early_param("epic_debug", epic_set_debug);

static int __init epic_set_bgi_mode(char *arg)
{
	epic_bgi_mode = true;
	return 0;
}
early_param("epic_bgi_mode", epic_set_bgi_mode);

static int __init pcsm_set_adjust(char *arg)
{
	pcsm_adjust_enable = true;
	return 0;
}
early_param("pcsm_adjust", pcsm_set_adjust);

/*
 * EPIC Masked interrupt handling starts with reading CEPIC_VECT_INTA.
 * Value read from CEPIC_VECT_INTA also contains Core Priority bits,
 * which have to be saved to be written to CEPIC_EOI later
 */
int epic_get_vector(void)
{
	union cepic_vect_inta reg;

	reg.raw = epic_read_w(CEPIC_VECT_INTA);

	set_current_epic_core_priority(reg.bits.cpr);

	return reg.bits.vect;
}

/* Core priority is read from CEPIC_VECT_INTA in native_do_interrupt */
void ack_epic_irq(void)
{
	union cepic_eoi reg;

	reg.raw = 0;
	reg.bits.rcpr = get_current_epic_core_priority();
	epic_write_w(CEPIC_EOI, reg.raw);
}

__visible void __irq_entry cepic_epic_interrupt(struct pt_regs *regs)
{
	l_irq_enter();

#ifdef CONFIG_E2K
	kvm_deliver_cepic_epic_interrupt();
#endif
	ack_epic_irq();
	l_irq_exit();
}

__visible void epic_hc_emerg_interrupt(struct pt_regs *regs)
{
	l_irq_enter();

	pr_err("EPIC: received emergency hc interrupt on core %d\n",
		smp_processor_id());

	ack_epic_irq();
	l_irq_exit();
}

__visible void epic_uncore_interrupt(struct pt_regs *regs)
{
	l_irq_enter();

#ifdef CONFIG_E2K
	do_sic_error_interrupt();
#endif

	ack_epic_irq();
	l_irq_exit();

	panic("EPIC: received uncore interrupt on core %d\n",
		smp_processor_id());
}

__visible void epic_ipcc_interrupt(struct pt_regs *regs)
{
	l_irq_enter();

	pr_err("EPIC: received ipcc interrupt on core %d\n",
		smp_processor_id());

	ack_epic_irq();
	l_irq_exit();
}

__visible void epic_hc_interrupt(struct pt_regs *regs)
{
	l_irq_enter();

	pr_err("EPIC: received hc interrupt on core %d\n",
		smp_processor_id());

	ack_epic_irq();
	l_irq_exit();
}

static const struct pcs_handle *pcs_handle_epic;

void register_pcs_handle(const struct pcs_handle *handle)
{
	if (pcs_handle_epic) {
	    pr_err("PCS: handle is already registered\n");
	    return;
	}

	pcs_handle_epic = handle;
}
EXPORT_SYMBOL(register_pcs_handle);

void unregister_pcs_handle(void)
{
	pcs_handle_epic = NULL;
}
EXPORT_SYMBOL(unregister_pcs_handle);

__visible void epic_pcs_interrupt(struct pt_regs *regs)
{
	l_irq_enter();

	if (pcs_handle_epic)
		pcs_handle_epic->pcs_interrupt();

	if (epic_debug)
		pr_err("EPIC: received pcs interrupt on core %d\n",
			smp_processor_id());

	ack_epic_irq();
	l_irq_exit();
}


/*
 * Power management
 */

static int cepic_suspend(void)
{
	union cepic_ctrl reg_ctrl;
	unsigned long flags;

	local_irq_save(flags);

	/* Disable CEPIC */
	reg_ctrl.raw = epic_read_w(CEPIC_CTRL);
	reg_ctrl.bits.soft_en = 0;
	epic_write_w(CEPIC_CTRL, reg_ctrl.raw);

	local_irq_restore(flags);

	return 0;
}

#ifdef CONFIG_PM
static void cepic_resume(void)
{
	union cepic_ctrl reg_ctrl;
	unsigned long flags;

	local_irq_save(flags);

	/* Enable CEPIC */
	reg_ctrl.raw = epic_read_w(CEPIC_CTRL);
	reg_ctrl.bits.soft_en = 1;
	epic_write_w(CEPIC_CTRL, reg_ctrl.raw);

	local_irq_restore(flags);
}

static struct syscore_ops cepic_syscore_ops = {
	.resume		= cepic_resume,
	.suspend	= cepic_suspend,
};

static int __init init_cepic_sysfs(void)
{
	/* XXX: remove suspend/resume procs if !apic_pm_state.active? */
	if (cpu_has_epic())
		register_syscore_ops(&cepic_syscore_ops);

	return 0;
}

/* local apic needs to resume before other devices access its registers. */
core_initcall(init_cepic_sysfs);
#endif	/* CONFIG_PM */

void cepic_disable(void)
{
	cepic_timer_shutdown(NULL);
	cepic_suspend();
}
