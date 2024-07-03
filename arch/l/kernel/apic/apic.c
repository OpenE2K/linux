/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * Local APIC handling, local APIC timers
 */

#include <linux/atomic.h>
#include <linux/perf_event.h>
#include <linux/kernel_stat.h>
#include <linux/mc146818rtc.h>
#include <linux/acpi_pmtmr.h>
#include <linux/clockchips.h>
#include <linux/interrupt.h>
#include <linux/ftrace.h>
#include <linux/ioport.h>
#include <linux/export.h>
#include <linux/syscore_ops.h>
#include <linux/delay.h>
#include <linux/timex.h>
#include <linux/clockchips.h>
#include <linux/init.h>
#include <linux/cpu.h>
#include <linux/dmi.h>
#include <linux/smp.h>
#include <linux/mm.h>

#include <asm/acpi.h>
#include <asm/perf_event.h>
#include <asm/pgalloc.h>
#include <asm/mpspec.h>
#include <asm/apic.h>
#include <asm/io_apic.h>
#include <asm/smp.h>
#include <asm/epic.h>

#include <asm/irq_regs.h>
#include <asm/hw_irq.h>
#include <asm/l_timer.h>
#include <asm/l-iommu.h>

#include <asm-l/idle.h>

unsigned int num_processors;

unsigned disabled_cpus;

/* Processor that is doing the boot up */
unsigned int boot_cpu_physical_apicid = -1U;
EXPORT_SYMBOL_GPL(boot_cpu_physical_apicid);

/*
 * The highest APIC ID seen during enumeration.
 */
unsigned int max_physical_apicid;

/*
 * Bitmask of physically existing CPUs:
 */
physid_mask_t phys_cpu_present_map;
/* it can be used before clearing the bss section */
physid_mask_t phys_cpu_offline_map = PHYSID_MASK_ALL;

/*
 * Processor to be disabled specified by kernel parameter
 * disable_cpu_apicid=<int>, mostly used for the kdump 2nd kernel to
 * avoid undefined behaviour caused by sending INIT from AP to BSP.
 */
static unsigned int disabled_cpu_apicid __read_mostly = BAD_APICID;

/*
 * Map cpu index to physical APIC ID
 */
DEFINE_EARLY_PER_CPU_READ_MOSTLY(u16, cpu_to_picid, BAD_APICID);

bool default_check_phys_apicid_online(void)
{
	/* use only raw functions as it is supposed
	 * to be called at booting stage */
	unsigned long id = cpu_has_epic() ?
			cepic_id_full_to_short(epic_read_w(CEPIC_ID)) :
				GET_APIC_ID(native_apic_mem_read(APIC_ID));
	return !physid_isset(id, phys_cpu_offline_map);
}

unsigned long mp_lapic_addr;
/* Disable local APIC timer from the kernel commandline or via dmi quirk */
#ifndef	CONFIG_VIRTUALIZATION
static __initdata bool disable_apic_timer;
#else	/* CONFIG_VIRTUALIZATION */
/* Variable should be global to can to disable on guest kernel */
__initdata bool disable_apic_timer;
#endif	/* ! CONFIG_VIRTUALIZATION */

/*
 * Debug level, exported for io_apic.c
 */
unsigned int apic_verbosity;

int pic_mode;

/* Have we found an MP table */
int smp_found_config;

static struct resource lapic_resource = {
	.name = "Local APIC",
	.flags = IORESOURCE_MEM | IORESOURCE_BUSY,
};

static unsigned int lapic_timer_frequency = 0;

static void apic_pm_activate(void);

static unsigned long apic_phys;

void native_apic_wait_icr_idle(void)
{
	while (apic_read(APIC_ICR) & APIC_ICR_BUSY)
		cpu_relax();
}

u32 native_safe_apic_wait_icr_idle(void)
{
	u32 send_status;
	int timeout;

	timeout = 0;
	do {
		send_status = apic_read(APIC_ICR) & APIC_ICR_BUSY;
		if (!send_status)
			break;
		inc_irq_stat(icr_read_retry_count);
		udelay(100);
	} while (timeout++ < 1000);

	return send_status;
}

void native_apic_icr_write(u32 low, u32 id)
{
	apic_write(APIC_ICR2, SET_APIC_DEST_FIELD(id));
	apic_write(APIC_ICR, low);
}

u64 native_apic_icr_read(void)
{
	u32 icr1, icr2;

	icr2 = apic_read(APIC_ICR2);
	icr1 = apic_read(APIC_ICR);

	return icr1 | ((u64)icr2 << 32);
}

/**
 * lapic_get_maxlvt - get the maximum number of local vector table entries
 */
int lapic_get_maxlvt(void)
{
	return GET_APIC_MAXLVT(apic_read(APIC_LVR));
}

/*
 * Local APIC timer
 */

/*
 * Clock divisor.
 *
 * APIC clock speed is approximated by two integers: 'mult' and
 * 'shift'. They work as follows:
 *
 * APIC_clocks = (mult * nanoseconds) >> shift
 *
 * Thus the inherent error of this computation is:
 *
 * error = 0.5 / mult = nanoseconds / (2 * (APIC_clocks << shift))
 *
 * Now let's denote the ratio of APIC bus speed to CPU clock speed
 * as X. Then:
 *
 * APIC_clocks = X * nanoseconds
 *
 * nanoseconds = APIC_clocks / X
 *
 * error = APIC_clocks / (2 * X * (APIC_clocks << shift)) =
 *       = APIC_clocks / (2 * X * APIC_clocks * (2^shift)) =
 *       = 1 / (2 * X * (2^shift))
 *
 * Thus increasing X (which is backwards proportional to APIC_DIVISOR)
 * or shift will reduce the approximation error.
 *
 * Reducing APIC_DIVISOR will decrease the max_delta_ns. But when
 * increasing the shift we must make sure that nothing will overflow
 * 64-bits values.
 *
 *   log2(mult * nanoseconds) = log2(APIC_clocks << shift) <= 64
 *
 * (Actually under log2() here and below I mean rounded up
 * logarythm, i.e. the number of bits needed to hold the value).
 * After simple conversion we get:
 *
 *   log2(APIC_clocks) + shift <= 64
 *
 * Maximum value of log2(APIC_clocks) is 32 as TMICT and TMCCT
 * registers are 32-bits long. We want to use the maximum value
 * to allow the system to go idle for a long times, so we get:
 *
 *   shift <= 32
 *
 * So if we increase the shift we will have to decrease APIC_clocks,
 * that is, decrease max_delta_ns.
 *
 * In other words - nothing can be done...
 *
 * Some numbers:
 *
 * APIC clock (MHz) | APIC_DIVISOR | max delta (seconds)
 * -----------------------------------------------------
 *      10 (LMS)    |      16      |      6871
 *      10 (LMS)    |       1      |       429
 *    1000 (E90S)   |      16      |        69
 *    1000 (E90S)   |       1      |         4
 *
 * So it is OK to have divisor of 1
 */
#define APIC_DIVISOR 1
#define TSC_DIVISOR  32

/*
 * This function sets up the local APIC timer, with a timeout of
 * 'clocks' APIC bus clock. During calibration we actually call
 * this function twice on the boot CPU, once with a bogus timeout
 * value, second time for real. The other (noncalibrating) CPUs
 * call this function only once, with the real, calibrated value.
 *
 * We do reads before writes even if unnecessary, to get around the
 * P5 APIC double write bug.
 */
static void __setup_APIC_LVTT(unsigned int clocks, int oneshot, int irqen)
{
	unsigned int lvtt_value, tmp_value;

	lvtt_value = LOCAL_TIMER_VECTOR;
	if (!oneshot)
		lvtt_value |= APIC_LVT_TIMER_PERIODIC;

	if (!irqen)
		lvtt_value |= APIC_LVT_MASKED;

	apic_write(APIC_LVTT, lvtt_value);
	apic_printk(APIC_DEBUG, KERN_DEBUG "__setup_APIC_LVTT() APIC_LVTT == "
		"0x%x (w) 0x%x (r)\n", lvtt_value, (int) apic_read(APIC_LVTT));

	/*
	 * Do not divide APIC clock.
	 */
	tmp_value = apic_read(APIC_TDCR);
	apic_write(APIC_TDCR,
		(tmp_value & ~APIC_TDR_DIV_TMBASE) | APIC_TDR_DIV_1);
	apic_printk(APIC_DEBUG, KERN_DEBUG "__setup_APIC_LVTT() APIC_TDCR == 0x%x\n",
			(int) apic_read(APIC_TDCR));

	if (!oneshot)
		apic_write(APIC_TMICT, clocks / APIC_DIVISOR);

	apic_printk(APIC_DEBUG, KERN_DEBUG "__setup_APIC_LVTT() APIC_TMICT == %d\n",
			(int) apic_read(APIC_TMICT));
}

/*
 * Program the next event, relative to now
 */
static int lapic_next_event(unsigned long delta,
			    struct clock_event_device *evt)
{
	apic_write(APIC_TMICT, delta);
	return 0;
}

static int lapic_timer_shutdown(struct clock_event_device *evt)
{
	unsigned int v;

	v = apic_read(APIC_LVTT);
	v |= (APIC_LVT_MASKED | LOCAL_TIMER_VECTOR);
	apic_write(APIC_LVTT, v);
	apic_write(APIC_TMICT, 0);
	return 0;
}

static inline int
lapic_timer_set_periodic_oneshot(struct clock_event_device *evt, bool oneshot)
{
	__setup_APIC_LVTT(lapic_timer_frequency, oneshot, 1);
	return 0;
}

static int lapic_timer_set_periodic(struct clock_event_device *evt)
{
	return lapic_timer_set_periodic_oneshot(evt, false);
}

static int lapic_timer_set_oneshot(struct clock_event_device *evt)
{
	return lapic_timer_set_periodic_oneshot(evt, true);
}

/*
 * Local APIC timer broadcast function
 */
static void lapic_timer_broadcast(const struct cpumask *mask)
{
#ifdef CONFIG_SMP
	apic->send_IPI_mask(mask, LOCAL_TIMER_VECTOR);
#endif
}


/*
 * The local apic timer can be used for any function which is CPU local.
 */
static struct clock_event_device lapic_clockevent = {
	.name		= "lapic",
	.features	= CLOCK_EVT_FEAT_PERIODIC | CLOCK_EVT_FEAT_ONESHOT,
	.shift		= 32,
	.set_state_shutdown	= lapic_timer_shutdown,
	.set_state_periodic	= lapic_timer_set_periodic,
	.set_state_oneshot	= lapic_timer_set_oneshot,
	.set_next_event		= lapic_next_event,
	.broadcast		= lapic_timer_broadcast,
	.rating			= 100,
	.irq			= -1,
};
static DEFINE_PER_CPU(struct clock_event_device, lapic_events);

/*
 * In this functions we calibrate APIC bus clocks to the external timer.
 *
 * We want to do the calibration only once since we want to have local timer
 * irqs syncron. CPUs connected by the same APIC bus have the very same bus
 * frequency.
 *
 * This was previously done by reading the PIT/HPET and waiting for a wrap
 * around to find out, that a tick has elapsed. I have a box, where the PIT
 * readout is broken, so it never gets out of the wait loop again. This was
 * also reported by others.
 *
 * Monitoring the jiffies value is inaccurate and the clockevents
 * infrastructure allows us to do a simple substitution of the interrupt
 * handler.
 *
 * The calibration routine also uses the pm_timer when possible, as the PIT
 * happens to run way too slow (factor 2.3 on my VAIO CoreDuo, which goes
 * back to normal later in the boot process).
 */

/* Prototypes can have HZ set to 10, so use at least HZ/5 */
#define LAPIC_CAL_LOOPS		(HZ/5)

static __initdata int lapic_cal_loops = -1;
static __initdata long lapic_cal_t1, lapic_cal_t2;
static __initdata unsigned long long lapic_cal_tsc1, lapic_cal_tsc2;
static __initdata unsigned long lapic_cal_pm1, lapic_cal_pm2;
static __initdata unsigned long lapic_cal_j1, lapic_cal_j2;
static u32 levt_freq;

void (*real_handler)(struct clock_event_device *dev);

/*
 * Setup the local APIC timer for this CPU. Copy the initialized values
 * of the boot CPU and register the clock event in the framework.
 */
static void setup_APIC_timer(void)
{
	struct clock_event_device *levt = this_cpu_ptr(&lapic_events);

	memcpy(levt, &lapic_clockevent, sizeof(*levt));
	levt->cpumask = cpumask_of(smp_processor_id());

	clockevents_config_and_register(levt, levt_freq, 0xF, 0xFFFFFFFF);
}

/*
 * Temporary interrupt handler.
 */
static noinline void __init lapic_cal_handler(struct clock_event_device *dev)
{
	unsigned long long tsc = 0;
	long tapic = apic_read(APIC_TMCCT);
	unsigned long pm = acpi_pm_read_early();

	if (paravirt_enabled()) {
		/* real handler should be called too */
		/* restore handler into structure, because of */
		/* tick_handle_periodic() check handler function */
		/* see kernel/time/tick-common.c */
		dev->event_handler = real_handler;
		real_handler(dev);
		dev->event_handler = lapic_cal_handler;
	}

	tsc = get_cycles();

	switch (lapic_cal_loops++) {
	case 0:
		lapic_cal_t1 = tapic;
		lapic_cal_tsc1 = tsc;
		lapic_cal_pm1 = pm;
		lapic_cal_j1 = jiffies;
		break;

	case LAPIC_CAL_LOOPS:
		lapic_cal_t2 = tapic;
		lapic_cal_tsc2 = tsc;
		if (pm < lapic_cal_pm1)
			pm += ACPI_PM_OVRRUN;
		lapic_cal_pm2 = pm;
		lapic_cal_j2 = jiffies;
		break;
	}
}

static int __init calibrate_APIC_clock(void)
{
	long delta, deltatsc;

	/**
	 * check if lapic timer has already been calibrated by platform
	 * specific routine, such as tsc calibration code. if so, we just fill
	 * in the clockevent structure and return.
	 */
	if (lapic_timer_frequency) {
		apic_printk(APIC_VERBOSE, "lapic timer already calibrated %d\n",
				lapic_timer_frequency);
		lapic_clockevent.mult = div_sc(lapic_timer_frequency/APIC_DIVISOR,
					TICK_NSEC, lapic_clockevent.shift);
		lapic_clockevent.max_delta_ns =
			clockevent_delta2ns(0x7FFFFF, &lapic_clockevent);
		lapic_clockevent.min_delta_ns =
			clockevent_delta2ns(0xF, &lapic_clockevent);
		return 0;
	}

	apic_printk(APIC_VERBOSE, "Using local APIC timer interrupts.\n"
		    "calibrating APIC timer ...\n");

	local_irq_disable();

	/*
	 * Setup the APIC counter to maximum. There is no way the lapic
	 * can underflow in the 100ms detection time frame
	 */
	__setup_APIC_LVTT(0xffffffff, 0, 0);

	/* Replace the global interrupt handler */
	real_handler = global_clock_event->event_handler;
	global_clock_event->event_handler = lapic_cal_handler;

	/* Let the interrupts run */
	local_irq_enable();

	while (lapic_cal_loops <= LAPIC_CAL_LOOPS)
		cpu_relax();

	local_irq_disable();

	/* Restore the real event handler */
	global_clock_event->event_handler = real_handler;

	/* Build delta t1-t2 as apic timer counts down */
	delta = lapic_cal_t1 - lapic_cal_t2;
	apic_printk(APIC_VERBOSE, "... lapic delta = %ld\n", delta);

	deltatsc = (long)(lapic_cal_tsc2 - lapic_cal_tsc1);

	lapic_timer_frequency = (delta * APIC_DIVISOR) / LAPIC_CAL_LOOPS;
	levt_freq = (lapic_cal_t1 - lapic_cal_t2) * (HZ / LAPIC_CAL_LOOPS);

	apic_printk(APIC_VERBOSE, "..... delta %ld\n", delta);
	apic_printk(APIC_VERBOSE, "..... mult: %u\n", lapic_clockevent.mult);
	apic_printk(APIC_VERBOSE, "..... shift: %u\n", lapic_clockevent.shift);
	apic_printk(APIC_VERBOSE, "..... calibration result: %u\n",
		    lapic_timer_frequency);

	apic_printk(APIC_VERBOSE, "..... CPU clock speed is %ld.%04ld MHz.\n",
		    (deltatsc / LAPIC_CAL_LOOPS) / (1000000 / HZ),
		    (deltatsc / LAPIC_CAL_LOOPS) % (1000000 / HZ));

	apic_printk(APIC_VERBOSE, "..... host bus clock speed is "
		    "%u.%04u MHz.\n",
		    lapic_timer_frequency / (1000000 / HZ),
		    lapic_timer_frequency % (1000000 / HZ));

	/*
	 * Do a sanity check on the APIC calibration result
	 */
	if (lapic_timer_frequency < (1000000 / HZ)) {
		local_irq_enable();
		pr_warn("APIC frequency too slow, disabling apic timer\n");
		return -1;
	}

	local_irq_enable();

	return 0;
}

/*
 * Setup the boot APIC
 *
 * Calibrate and verify the result.
 */
void __init setup_boot_APIC_clock(void)
{
	/*
	 * The local apic timer can be disabled via the kernel
	 * commandline or from the CPU detection code. Register the lapic
	 * timer as a dummy clock event source on SMP systems, so the
	 * broadcast mechanism is used. On UP systems simply ignore it.
	 */
	if (disable_apic_timer) {
		pr_info("Disabling APIC timer\n");
		/* No broadcast on UP ! */
		/* Local APIC support on guest is not ready at present time */
		if (num_possible_cpus() > 1 && !paravirt_enabled()) {
			lapic_clockevent.mult = 1;
			setup_APIC_timer();
		}
		return;
	}

	if (calibrate_APIC_clock()) {
		/* No broadcast on UP ! */
		if (num_possible_cpus() > 1)
			setup_APIC_timer();
		return;
	}

	/* Setup the lapic or request the broadcast */
	setup_APIC_timer();
}

void setup_secondary_APIC_clock(void)
{
	setup_APIC_timer();
}

#ifdef CONFIG_L_WDT
void (*wd_reset_ask)(void) = NULL;
#endif

/*
 * The guts of the apic timer interrupt
 */
void local_apic_timer_interrupt(void)
{
	int cpu = smp_processor_id();
	struct clock_event_device *evt = &per_cpu(lapic_events, cpu);

#ifdef CONFIG_L_WDT
	if (wd_reset_ask)
		wd_reset_ask();
#endif

	/*
	 * Normally we should not be here till LAPIC has been initialized but
	 * in some cases like kdump, its possible that there is a pending LAPIC
	 * timer interrupt from previous kernel's context and is delivered in
	 * new kernel the moment interrupts are enabled.
	 *
	 * Interrupts are enabled early and LAPIC is setup much later, hence
	 * its possible that when we get here evt->event_handler is NULL.
	 * Check for event_handler being NULL and discard the interrupt as
	 * spurious.
	 */
	if (!evt->event_handler) {
		pr_warn("Spurious LAPIC timer interrupt on cpu %d\n", cpu);
		/* Switch it off */
		lapic_timer_shutdown(evt);
		return;
	}

	/*
	 * the NMI deadlock-detector uses this.
	 */
	inc_irq_stat(apic_timer_irqs);

	evt->event_handler(evt);
}

#ifdef CONFIG_MCST
#define DELTA_NS	(NSEC_PER_SEC / HZ / 2)
#endif

/*
 * Local APIC timer interrupt. This is the most natural way for doing
 * local interrupts, but local timer interrupts can be emulated by
 * broadcast interrupts too. [in case the hw doesn't support APIC timers]
 *
 * [ if a single-CPU system runs an SMP kernel then we call the local
 *   interrupt as well. Thus we cannot inline the local irq ... ]
 */
__visible void __irq_entry smp_apic_timer_interrupt(struct pt_regs *regs)
{
	struct pt_regs *old_regs = set_irq_regs(regs);
#ifdef CONFIG_MCST
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
			/* set 1 -- must do timer later
			 * in do_postpone_tick() */
			per_cpu(next_rt_intr, cpu) = 1;
			set_irq_regs(old_regs);
			ack_APIC_irq();
			/* if do_postpone_tick() will not called: */
			apic_write(APIC_TMICT,
				usecs_2cycles(USEC_PER_SEC / HZ));
			return;
		}
	}
#endif

	/*
	 * NOTE! We'd better ACK the irq immediately,
	 * because timer handling can be slow.
	 *
	 * update_process_times() expects us to have done l_irq_enter().
	 * Besides, if we don't timer interrupts ignore the global
	 * interrupt lock, which is the WrongThing (tm) to do.
	 */
	entering_ack_irq();
	local_apic_timer_interrupt();
	exiting_irq();

	set_irq_regs(old_regs);
}

int setup_profiling_timer(unsigned int multiplier)
{
	return -EINVAL;
}

/*
 * Local APIC start and shutdown
 */

/**
 * clear_local_APIC - shutdown the local APIC
 *
 * This is called, when a CPU is disabled and before rebooting, so the state of
 * the local APIC has no dangling leftovers. Also used to cleanout any BIOS
 * leftovers during boot.
 */
void clear_local_APIC(void)
{
	int maxlvt;
	u32 v;
#ifdef CONFIG_E2K
	int cpu = boot_smp_processor_id();
#endif

	/* APIC hasn't been mapped yet */
	if (!apic_phys)
		return;

	maxlvt = lapic_get_maxlvt();
	/*
	 * Masking an LVT entry can trigger a local APIC error
	 * if the vector is zero. Mask LVTERR first to prevent this.
	 */
	if (maxlvt >= 3) {
		v = ERROR_APIC_VECTOR; /* any non-zero vector will do */
		apic_write(APIC_LVTERR, v | APIC_LVT_MASKED);
	}
	/*
	 * Careful: we have to set masks only first to deassert
	 * any level-triggered sources.
	 */
	v = apic_read(APIC_LVTT);
	apic_write(APIC_LVTT, v | APIC_LVT_MASKED);
	v = apic_read(APIC_LVT0);
	apic_write(APIC_LVT0, v | APIC_LVT_MASKED);
	v = apic_read(APIC_LVT1);
	apic_write(APIC_LVT1, v | APIC_LVT_MASKED);
	if (maxlvt >= 4) {
		v = apic_read(APIC_LVTPC);
		apic_write(APIC_LVTPC, v | APIC_LVT_MASKED);
	}

	/*
	 * Clean APIC state for other OSs:
	 */
	apic_write(APIC_LVTT, APIC_LVT_MASKED);
	apic_write(APIC_LVT0, APIC_LVT_MASKED);
	apic_write(APIC_LVT1, APIC_LVT_MASKED);
	if (maxlvt >= 3)
		apic_write(APIC_LVTERR, APIC_LVT_MASKED);
	if (maxlvt >= 4)
		apic_write(APIC_LVTPC, APIC_LVT_MASKED);

	if (maxlvt > 3) {
		/* Clear ESR due to Pentium errata 3AP and 11AP */
		apic_write(APIC_ESR, 0);
	}
	apic_read(APIC_ESR);
}

/**
 * disable_local_APIC - clear and disable the local APIC
 */
void disable_local_APIC(void)
{
	unsigned int value;

	/* APIC hasn't been mapped yet */
	if (!apic_phys)
		return;

	clear_local_APIC();

	/*
	 * Disable APIC (implies clearing of registers
	 * for 82489DX!).
	 */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_SPIV_APIC_ENABLED;
	apic_write(APIC_SPIV, value);
}

/*
 * This is to verify that we're looking at a real local APIC.
 * Check these against your board if the CPUs aren't getting
 * started for no apparent reason.
 */
int __init_recv verify_local_APIC(void)
{
	unsigned int reg0, reg1;

	/*
	 * The version register is read-only in a real APIC.
	 */
	reg0 = apic_read(APIC_LVR);
	apic_printk(APIC_DEBUG, "Getting VERSION: %x\n", reg0);
	apic_write(APIC_LVR, reg0 ^ APIC_LVR_MASK);
	reg1 = apic_read(APIC_LVR);
	apic_printk(APIC_DEBUG, "Getting VERSION: %x\n", reg1);

	/*
	 * The two version reads above should print the same
	 * numbers.  If the second one is different, then we
	 * poke at a non-APIC.
	 */
	if (reg1 != reg0)
		return 0;

	/*
	 * Check if the version looks reasonably.
	 */
	reg1 = GET_APIC_VERSION(reg0);
	if (reg1 == 0x00 || reg1 == 0xff)
		return 0;
	reg1 = lapic_get_maxlvt();
	if (reg1 < 0x02 || reg1 == 0xff)
		return 0;

	/* The following check might break our LAPIC
	 * (bug 46759 comment 44, bug 47853) */
#if 0
	/*
	 * The ID register is read/write in a real APIC.
	 */
	reg0 = apic_read(APIC_ID);
	apic_printk(APIC_DEBUG, "Getting ID: %x\n", reg0);
	apic_write(APIC_ID, reg0 ^ apic->apic_id_mask);
	reg1 = apic_read(APIC_ID);
	apic_printk(APIC_DEBUG, "Getting ID: %x\n", reg1);
	apic_write(APIC_ID, reg0);
	if (reg1 != (reg0 ^ apic->apic_id_mask))
		return 0;
#endif

	return 1;
}

/*
 * An initial setup of the virtual wire mode.
 */
void __init_recv init_bsp_APIC(void)
{
	unsigned int value;

	/*
	 * Don't do the setup now if we have a SMP BIOS as the
	 * through-I/O-APIC virtual wire mode might be active.
	 */
	if (smp_found_config)
		return;

	/*
	 * Do not trust the local APIC being empty at bootup.
	 */
	clear_local_APIC();

	/*
	 * Enable APIC.
	 */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_VECTOR_MASK;
	value |= APIC_SPIV_APIC_ENABLED | APIC_SPIV_FOCUS_DISABLED | SPURIOUS_APIC_VECTOR;
	apic_write(APIC_SPIV, value);

	/*
	 * Set up the virtual wire mode.
	 */
	apic_write(APIC_LVT0, APIC_DM_EXTINT);
	value = APIC_DM_NMI;
	apic_write(APIC_LVT1, value);
}

static void lapic_setup_esr(void)
{
	unsigned int oldvalue, value, maxlvt;

	maxlvt = lapic_get_maxlvt();
	if (maxlvt > 3)		/* Due to the Pentium erratum 3AP. */
		apic_write(APIC_ESR, 0);
	oldvalue = apic_read(APIC_ESR);

	/* enables sending errors */
	value = ERROR_APIC_VECTOR;
	apic_write(APIC_LVTERR, value);

	/*
	 * spec says clear errors after enabling vector.
	 */
	if (maxlvt > 3)
		apic_write(APIC_ESR, 0);
	value = apic_read(APIC_ESR);
	if (value != oldvalue)
		apic_printk(APIC_VERBOSE, "ESR value before enabling "
			"vector: 0x%08x  after: 0x%08x\n",
			oldvalue, value);
}

int apic_get_vector(void)
{
	int vector;

	vector = arch_apic_read(APIC_VECT);

	if (unlikely(APIC_VECT_IS_EXTINT(vector))) {
		pr_emerg("Received ExtINT interrupt on kernel without PIC! "
				"Read vector is %x\n", vector);
		vector = SPURIOUS_APIC_VECTOR;
	}

	return APIC_VECT_VECTOR(vector);
}

/**
 * setup_local_APIC - setup the local APIC
 *
 * Used to setup local APIC while initializing BSP or bringin up APs.
 * Always called with preemption disabled.
 */
void setup_local_APIC(void)
{
	int cpu = smp_processor_id();
	unsigned int value;
	int i, j, acked = 0;

	/*
	 * If this comes from kexec/kcrash the APIC might be enabled in
	 * SPIV. Soft disable it before doing further initialization.
	 */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_SPIV_APIC_ENABLED;
	apic_write(APIC_SPIV, value);

	/*
	 * Double-check whether this APIC is really registered.
	 * This is meaningless in clustered apic mode, so we skip it.
	 */
	BUG_ON(!apic->apic_id_registered());

	/*
	 * After a crash, we no longer service the interrupts and a pending
	 * interrupt from previous kernel might still have ISR bit set.
	 */
	for (i = APIC_ISR_NR - 1; i >= 0; i--) {
		value = apic_read(APIC_ISR + i*0x10);
		if (!value)
			continue;
		for (j = 31; j >= 0; j--) {
			if (value & (1<<j)) {
				ack_APIC_irq();
				acked++;
			}
		}
	}

	do {
		value = 0;
		for (i = APIC_ISR_NR - 1; i >= 0; i--) {
			if ((value = apic_read(APIC_IRR + i*0x10)))
				break;
		}
		if (value) {
			apic_get_vector();
			ack_APIC_irq();
			acked++;
		}
	} while (value && acked <= 256);

	if (acked > 256)
		pr_err("LAPIC pending interrupts after %d EOI\n", acked);

	/*
	 * Set Task Priority to 'accept all'. We never change this
	 * later on.
	 */
	value = apic_read(APIC_TASKPRI);
	value &= ~APIC_TPRI_MASK;
	apic_write(APIC_TASKPRI, value);

	/*
	 * Now that we are all set up, enable the APIC
	 */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_VECTOR_MASK;
	/*
	 * Enable APIC
	 */
	value |= APIC_SPIV_APIC_ENABLED;

	/*
	 * Set spurious IRQ vector
	 */
	value |= SPURIOUS_APIC_VECTOR;
	apic_write(APIC_SPIV, value);

	/*
	 * Set up LVT0, LVT1:
	 *
	 * set up through-local-APIC on the BP's LINT0. This is not
	 * strictly necessary in pure symmetric-IO mode, but sometimes
	 * we delegate interrupts to the 8259A.
	 */
	/*
	 * TODO: set up through-local-APIC from through-I/O-APIC? --macro
	 */
	value = apic_read(APIC_LVT0) & APIC_LVT_MASKED;

	/* For some reason on E2K a spurious ExtINT interrupt arrives
	 * if we do not mask it now... Probably configuration
	 * option X86_REROUTE_FOR_BROKEN_BOOT_IRQS has something
	 * to do with it (but our PCI code does not have any of
	 * the necessary workarounds and this spurious interrupt
	 * is most likely unharmful anyway). */
	value = APIC_DM_EXTINT | APIC_LVT_MASKED;
	apic_printk(APIC_VERBOSE, "masked ExtINT on CPU#%d\n", cpu);

#ifdef CONFIG_E90S
	/*e90s uses vector field */
	value |= apic_read(APIC_LVT0);
#endif
	apic_write(APIC_LVT0, value);

#if (defined(CONFIG_RDMA) || defined(CONFIG_RDMA_MODULE) || \
     defined(CONFIG_RDMA_SIC) || defined(CONFIG_RDMA_SIC_MODULE))
	if ((!smp_processor_id() || HAS_MACHINE_E2K_FULL_SIC)
#if defined(CONFIG_E90S)
		&& (e90s_get_cpu_type() == E90S_CPU_R1000)
#endif
	   ) {
		unsigned int value_lvt2;
		unsigned int apic_id, cpu;
		int node;

		value_lvt2 = apic_read(APIC_LVT2);
#ifdef CONFIG_E2K
		if (!HAS_MACHINE_E2K_FULL_SIC && value_lvt2 != 0x00018000) {
			rdma_apic_init = 0;
		} else {
#endif
			cpu = smp_processor_id();
			node = cpu_to_node(cpu);
			rdma_apic_init = 1;
			if (!rdma_node[node]) {
				apic_id = GET_APIC_ID(apic_read(APIC_ID));
				/* Enable LVT2 */
				value_lvt2 = APIC_LVT_LEVEL_TRIGGER |
						APIC_DM_FIXED |
						RDMA_INTERRUPT_VECTOR |
						SET_APIC_DEST_FIELD(apic_id);
#ifdef CONFIG_E2K
				if (IS_MACHINE_E2S)
					rdma_node[node] = 1;
#endif				
			} else {
				/* Disable LVT2 */
				value_lvt2 = APIC_LVT_MASKED;
			}
			apic_write(APIC_LVT2, value_lvt2);
#ifdef CONFIG_E2K
		}
#endif
	}
#endif

#ifdef CONFIG_E2K
	if (l_iommu_supported() || HAS_MACHINE_E2K_IOMMU) {
		unsigned int value;
		unsigned int apic_id;

		value = apic_read(APIC_LVT3);
		apic_id = read_apic_id();
		value = APIC_LVT_LEVEL_TRIGGER | APIC_DM_FIXED |
				LVT3_INTERRUPT_VECTOR |
				SET_APIC_DEST_FIELD(apic_id);
		apic_write(APIC_LVT3, value);
	}

	if (IS_MACHINE_E2S || IS_MACHINE_E1CP || IS_MACHINE_E8C ||
						IS_MACHINE_E8C2) {
		unsigned int value;
		unsigned int apic_id;

		value = apic_read(APIC_LVT4);
		apic_id = read_apic_id();
		value = APIC_LVT_LEVEL_TRIGGER | APIC_DM_FIXED |
				LVT4_INTERRUPT_VECTOR |
				SET_APIC_DEST_FIELD(apic_id);
		apic_write(APIC_LVT4, value);
	}
#endif	/* CONFIG_E2K */

	/*
	 * only the BP should see the LINT1 NMI signal, obviously.
	 */
	if (!cpu)
		value = APIC_DM_NMI;
	else
		value = APIC_DM_NMI | APIC_LVT_MASKED;
	apic_write(APIC_LVT1, value);
}

void end_local_APIC_setup(void)
{
	lapic_setup_esr();

	apic_pm_activate();
}

void __init_recv bsp_end_local_APIC_setup(void)
{
	end_local_APIC_setup();
}

/*
 * Detect and enable local APICs on non-SMP boards.
 * Original code written by Keir Fraser.
 * On AMD64 we trust the BIOS - if it says no APIC it is likely
 * not correctly set up (usually the APIC timer won't work etc.)
 */
static int __init detect_init_APIC(void)
{
	mp_lapic_addr = APIC_DEFAULT_PHYS_BASE;
	return 0;
}

/**
 * init_apic_mappings - initialize APIC mappings
 */
void __init init_apic_mappings(void)
{
	unsigned int new_apicid;

	/* If no local APIC can be found return early */
	if (!smp_found_config && detect_init_APIC()) {
		panic("No APIC?!");
	} else {
		apic_phys = mp_lapic_addr;

		/*
		 * acpi lapic path already maps that address in
		 * acpi_register_lapic_address()
		 */
		if (!acpi_lapic && !smp_found_config)
			register_lapic_address(apic_phys);
	}

	/*
	 * Fetch the APIC ID of the BSP in case we have a
	 * default configuration (or the MP table is broken).
	 */
	new_apicid = read_apic_id();
	if (boot_cpu_physical_apicid != new_apicid) {
		boot_cpu_physical_apicid = new_apicid;
		/*
		 * yeah -- we lie about apic_version
		 * in case if apic was disabled via boot option
		 * but it's not a problem for SMP compiled kernel
		 * since smp_sanity_check is prepared for such a case
		 * and disable smp mode
		 */
		apic_version[new_apicid] =
			 GET_APIC_VERSION(apic_read(APIC_LVR));
	}
}

void __init register_lapic_address(unsigned long address)
{
	mp_lapic_addr = address;

	apic_printk(APIC_VERBOSE, "mapped APIC to %16lx (%16lx)\n",
		    APIC_BASE, mp_lapic_addr);
	if (boot_cpu_physical_apicid == -1U) {
		boot_cpu_physical_apicid  = read_apic_id();
		apic_version[boot_cpu_physical_apicid] =
			 GET_APIC_VERSION(apic_read(APIC_LVR));
	}
}

/*
 * This initializes the IO-APIC and APIC hardware if this is
 * a UP kernel.
 */
int apic_version[MAX_LOCAL_APIC];

/*
 * Local APIC interrupts
 */

/*
 * This interrupt should _never_ happen with our APIC/SMP architecture
 */
static inline void __smp_spurious_interrupt(void)
{
	u32 v;

	/*
	 * Check if this really is a spurious interrupt and ACK it
	 * if it is a vectored one.  Just in case...
	 * Spurious interrupts should not be ACKed.
	 */
	v = apic_read(APIC_ISR + ((SPURIOUS_APIC_VECTOR & ~0x1f) >> 1));
	if (v & (1 << (SPURIOUS_APIC_VECTOR & 0x1f)))
		ack_APIC_irq();

	inc_irq_stat(irq_spurious_count);

	/* see sw-dev-man vol 3, chapter 7.4.13.5 */
	pr_info("spurious APIC interrupt on CPU#%d, "
		"should never happen.\n", smp_processor_id());
}

__visible void smp_spurious_interrupt(struct pt_regs *regs)
{
	entering_irq();
	__smp_spurious_interrupt();
	exiting_irq();
}

/*
 * This interrupt should never happen with our APIC/SMP architecture
 */
static inline void __smp_error_interrupt(void)
{
	u32 v;
	u32 i = 0;
	static const char * const error_interrupt_reason[] = {
		"Send CS error",		/* APIC Error Bit 0 */
		"Receive CS error",		/* APIC Error Bit 1 */
		"Send accept error",		/* APIC Error Bit 2 */
		"Receive accept error",		/* APIC Error Bit 3 */
		"Redirectable IPI",		/* APIC Error Bit 4 */
		"Send illegal vector",		/* APIC Error Bit 5 */
		"Received illegal vector",	/* APIC Error Bit 6 */
		"Illegal register address",	/* APIC Error Bit 7 */
	};

	/* First tickle the hardware, only then report what went on. -- REW */
	apic_write(APIC_ESR, 0);
	v = apic_read(APIC_ESR);
	ack_APIC_irq();
	atomic_inc(&irq_err_count);

	apic_printk(APIC_DEBUG, KERN_DEBUG "APIC error on CPU%d: %02x",
		    smp_processor_id(), v);

	v = v & 0xff;
	while (v) {
		if (v & 0x1)
			apic_printk(APIC_DEBUG, KERN_CONT " : %s", error_interrupt_reason[i]);
		i++;
		v >>= 1;
	}

	apic_printk(APIC_DEBUG, KERN_CONT "\n");
}

__visible void smp_error_interrupt(struct pt_regs *regs)
{
	entering_irq();
	__smp_error_interrupt();
	exiting_irq();
}

/**
 * disconnect_bsp_APIC - detach the APIC from the interrupt system
 * @virt_wire_setup:	indicates, whether virtual wire mode is selected
 *
 * Virtual wire mode is necessary to deliver legacy interrupts even when the
 * APIC is disabled.
 */
void disconnect_bsp_APIC(int virt_wire_setup)
{
	unsigned int value;

	/* Go back to Virtual Wire compatibility mode */

	/* For the spurious interrupt use vector F, and enable it */
	value = apic_read(APIC_SPIV);
	value &= ~APIC_VECTOR_MASK;
	value |= APIC_SPIV_APIC_ENABLED;
	value |= 0xf;
	apic_write(APIC_SPIV, value);

	if (!virt_wire_setup) {
		/*
		 * For LVT0 make it edge triggered, active high,
		 * external and enabled
		 */
		value = apic_read(APIC_LVT0);
		value &= ~(APIC_MODE_MASK | APIC_SEND_PENDING |
			APIC_INPUT_POLARITY | APIC_LVT_REMOTE_IRR |
			APIC_LVT_LEVEL_TRIGGER | APIC_LVT_MASKED);
		value |= APIC_LVT_REMOTE_IRR | APIC_SEND_PENDING;
		value = SET_APIC_DELIVERY_MODE(value, APIC_MODE_EXTINT);
		apic_write(APIC_LVT0, value);
	} else {
		/* Disable LVT0 */
		apic_write(APIC_LVT0, APIC_LVT_MASKED);
	}

	/*
	 * For LVT1 make it edge triggered, active high,
	 * nmi and enabled
	 */
	value = apic_read(APIC_LVT1);
	value &= ~(APIC_MODE_MASK | APIC_SEND_PENDING |
			APIC_INPUT_POLARITY | APIC_LVT_REMOTE_IRR |
			APIC_LVT_LEVEL_TRIGGER | APIC_LVT_MASKED);
	value |= APIC_LVT_REMOTE_IRR | APIC_SEND_PENDING;
	value = SET_APIC_DELIVERY_MODE(value, APIC_MODE_NMI);
	apic_write(APIC_LVT1, value);
}

int generic_processor_info(int apicid, int version)
{
	int cpu, max = nr_cpu_ids;
	bool boot_cpu_detected = physid_isset(boot_cpu_physical_apicid,
				phys_cpu_present_map);

	/*
	 * boot_cpu_physical_apicid is designed to have the apicid
	 * returned by read_apic_id(), i.e, the apicid of the
	 * currently booting-up processor. However, on some platforms,
	 * it is temporarily modified by the apicid reported as BSP
	 * through MP table.
	 *
	 * This function is executed with the modified
	 * boot_cpu_physical_apicid. So, disabled_cpu_apicid kernel
	 * parameter doesn't work to disable APs on kdump 2nd kernel.
	 *
	 * Since fixing handling of boot_cpu_physical_apicid requires
	 * another discussion and tests on each platform, we leave it
	 * for now and here we use read_apic_id() directly in this
	 * function, generic_processor_info().
	 */
	if (disabled_cpu_apicid != BAD_APICID &&
	    disabled_cpu_apicid != read_apic_id() &&
	    disabled_cpu_apicid == apicid) {
		int thiscpu = num_processors + disabled_cpus;

		pr_warn("APIC: Disabling requested cpu."
			   " Processor %d/0x%x ignored.\n",
			   thiscpu, apicid);

		disabled_cpus++;
		return -ENODEV;
	}

	/*
	 * If boot cpu has not been detected yet, then only allow upto
	 * nr_cpu_ids - 1 processors and keep one slot free for boot cpu
	 */
	if (!boot_cpu_detected && num_processors >= nr_cpu_ids - 1 &&
	    apicid != boot_cpu_physical_apicid) {
		int thiscpu = max + disabled_cpus - 1;

		pr_warn(
			"ACPI: NR_CPUS/possible_cpus limit of %i almost"
			" reached. Keeping one slot for boot cpu."
			"  Processor %d/0x%x ignored.\n", max, thiscpu, apicid);

		disabled_cpus++;
		return -ENODEV;
	}

	if (num_processors >= nr_cpu_ids) {
		int thiscpu = max + disabled_cpus;

		pr_warn(
			"ACPI: NR_CPUS/possible_cpus limit of %i reached."
			"  Processor %d/0x%x ignored.\n", max, thiscpu, apicid);

		disabled_cpus++;
		return -EINVAL;
	}

	num_processors++;

	if (apicid == boot_cpu_physical_apicid) {
		/* Logical cpuid 0 is reserved for BSP. */
		cpu = 0;
		cpuid_to_picid[0] = apicid;
	} else {
		cpu = allocate_logical_cpuid(apicid);
	}

	/*
	 * Validate version
	 */
	if (version == 0x0) {
		pr_warn("BIOS bug: APIC version is 0 for CPU %d/0x%x, fixing up to 0x10\n",
			   cpu, apicid);
		version = APIC_VERSION;
	}
	apic_version[apicid] = version;

	if (version != apic_version[boot_cpu_physical_apicid]) {
		pr_warn("BIOS bug: APIC version mismatch, boot CPU: %x, CPU %d: version %x\n",
			apic_version[boot_cpu_physical_apicid], cpu, version);
	}

	physid_set(apicid, phys_cpu_present_map);
	if (apicid > max_physical_apicid)
		max_physical_apicid = apicid;

	early_per_cpu(cpu_to_picid, cpu) = apicid;

	set_cpu_possible(cpu, true);
	set_cpu_present(cpu, true);

	return cpu;
}

int default_cpu_mask_to_apicid_and(const struct cpumask *cpumask,
				   const struct cpumask *andmask,
				   unsigned int *apicid)
{
	unsigned int cpu;

	for_each_cpu_and(cpu, cpumask, andmask) {
		if (cpumask_test_cpu(cpu, cpu_online_mask))
			break;
	}

	if (likely(cpu < nr_cpu_ids)) {
		*apicid = per_cpu(cpu_to_picid, cpu);
		return 0;
	}

	return -EINVAL;
}

/*
 * Power management
 */
#ifdef CONFIG_PM

static struct {
	/*
	 * 'active' is true if the local APIC was enabled by us and
	 * not the BIOS; this signifies that we are also responsible
	 * for disabling it before entering apm/acpi suspend
	 */
	int active;
	/* r/w apic fields */
	unsigned int apic_id;
	unsigned int apic_taskpri;
	unsigned int apic_ldr;
	unsigned int apic_dfr;
	unsigned int apic_spiv;
	unsigned int apic_lvtt;
	unsigned int apic_lvtpc;
	unsigned int apic_lvt0;
	unsigned int apic_lvt1;
	unsigned int apic_lvterr;
	unsigned int apic_tmict;
	unsigned int apic_tdcr;
	unsigned int apic_thmr;
} apic_pm_state;

static int lapic_suspend(void)
{
	unsigned long flags;
	int maxlvt;

	if (!apic_pm_state.active)
		return 0;

	maxlvt = lapic_get_maxlvt();

	apic_pm_state.apic_id = apic_read(APIC_ID);
	apic_pm_state.apic_taskpri = apic_read(APIC_TASKPRI);
	apic_pm_state.apic_ldr = apic_read(APIC_LDR);
	apic_pm_state.apic_dfr = apic_read(APIC_DFR);
	apic_pm_state.apic_spiv = apic_read(APIC_SPIV);
	apic_pm_state.apic_lvtt = apic_read(APIC_LVTT);
	if (maxlvt >= 4)
		apic_pm_state.apic_lvtpc = apic_read(APIC_LVTPC);
	apic_pm_state.apic_lvt0 = apic_read(APIC_LVT0);
	apic_pm_state.apic_lvt1 = apic_read(APIC_LVT1);
	apic_pm_state.apic_lvterr = apic_read(APIC_LVTERR);
	apic_pm_state.apic_tmict = apic_read(APIC_TMICT);
	apic_pm_state.apic_tdcr = apic_read(APIC_TDCR);

	local_irq_save(flags);
	mask_ioapic_entries();
	disable_local_APIC();
	local_irq_restore(flags);

	return 0;
}

static void lapic_resume(void)
{
	unsigned long flags;
	int maxlvt;

	if (!apic_pm_state.active)
		return;

	local_irq_save(flags);

	/*
	 * IO-APIC and PIC have their own resume routines.
	 * We just mask them here to make sure the interrupt
	 * subsystem is completely quiet while we enable x2apic
	 * and interrupt-remapping.
	 */
	mask_ioapic_entries();

	maxlvt = lapic_get_maxlvt();
	apic_write(APIC_LVTERR, ERROR_APIC_VECTOR | APIC_LVT_MASKED);
	apic_write(APIC_ID, apic_pm_state.apic_id);
	apic_write(APIC_DFR, apic_pm_state.apic_dfr);
	apic_write(APIC_LDR, apic_pm_state.apic_ldr);
	apic_write(APIC_TASKPRI, apic_pm_state.apic_taskpri);
	apic_write(APIC_SPIV, apic_pm_state.apic_spiv);
	apic_write(APIC_LVT0, apic_pm_state.apic_lvt0);
	apic_write(APIC_LVT1, apic_pm_state.apic_lvt1);
	if (maxlvt >= 4)
		apic_write(APIC_LVTPC, apic_pm_state.apic_lvtpc);
	apic_write(APIC_LVTT, apic_pm_state.apic_lvtt);
	apic_write(APIC_TDCR, apic_pm_state.apic_tdcr);
	apic_write(APIC_TMICT, apic_pm_state.apic_tmict);
	apic_write(APIC_ESR, 0);
	apic_read(APIC_ESR);
	apic_write(APIC_LVTERR, apic_pm_state.apic_lvterr);
	apic_write(APIC_ESR, 0);
	apic_read(APIC_ESR);

	local_irq_restore(flags);
}

/*
 * This device has no shutdown method - fully functioning local APICs
 * are needed on every CPU up until machine_halt/restart/poweroff.
 */

static struct syscore_ops lapic_syscore_ops = {
	.resume		= lapic_resume,
	.suspend	= lapic_suspend,
};

static void apic_pm_activate(void)
{
	apic_pm_state.active = 1;
}

static int __init init_lapic_sysfs(void)
{
	/* XXX: remove suspend/resume procs if !apic_pm_state.active? */
	register_syscore_ops(&lapic_syscore_ops);

	return 0;
}

/* local apic needs to resume before other devices access its registers. */
core_initcall(init_lapic_sysfs);

#else	/* CONFIG_PM */

static void apic_pm_activate(void) { }

#endif	/* CONFIG_PM */


static int __init parse_disable_apic_timer(char *arg)
{
	disable_apic_timer = true;
	return 0;
}
early_param("noapictimer", parse_disable_apic_timer);

static int __init parse_nolapic_timer(char *arg)
{
	disable_apic_timer = true;
	return 0;
}
early_param("nolapic_timer", parse_nolapic_timer);

static int __init apic_set_verbosity(char *arg)
{
	if (!arg)  {
		return 0;
	}

	if (strcmp("debug", arg) == 0)
		apic_verbosity = APIC_DEBUG;
	else if (strcmp("verbose", arg) == 0)
		apic_verbosity = APIC_VERBOSE;
	else {
		pr_warn("APIC Verbosity level %s not recognised"
			" use apic=verbose or apic=debug\n", arg);
		return -EINVAL;
	}

	return 0;
}
early_param("apic", apic_set_verbosity);

static int __init lapic_insert_resource(void)
{
	if (!apic_phys)
		return -1;

	/* Put local APIC into the resource map. */
	lapic_resource.start = apic_phys;
	lapic_resource.end = lapic_resource.start + PAGE_SIZE - 1;
	insert_resource(&iomem_resource, &lapic_resource);

	return 0;
}

/*
 * need call insert after e820_reserve_resources()
 * that is using request_resource
 */
late_initcall(lapic_insert_resource);

static int __init apic_set_disabled_cpu_apicid(char *arg)
{
	if (!arg || !get_option(&arg, &disabled_cpu_apicid))
		return -EINVAL;

	return 0;
}
early_param("disable_cpu_apicid", apic_set_disabled_cpu_apicid);
