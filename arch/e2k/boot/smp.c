
#include <linux/types.h>

#include <asm/atomic.h>
#include <asm/head.h>
#include <asm/apic.h>
#include <asm/bootinfo.h>

#include <asm/e2k_api.h>
#include <asm/e2k_debug.h>
#include <asm/e2k.h>

#undef	DEBUG_BOOT_MODE
#undef	Dprintk
#define	DEBUG_BOOT_MODE		0	/* SMP CPU boot */
#define	Dprintk			if (DEBUG_BOOT_MODE) rom_printk

extern char __apstartup_start, __apstartup_end;

atomic_t cpu_count = ATOMIC_INIT(0);
unsigned int all_apic_ids[NR_CPUS];

volatile int		phys_cpu_count = 0;
volatile int		phys_cpu_num = 0;
volatile unsigned long	cpu_callin_map = 0;
volatile unsigned long	cpu_callout_map = 0;
volatile unsigned long	phys_cpu_pres_map = 0;

extern void set_kernel_image_pointers(void);
extern bootblock_struct_t *bootblock;

extern inline void scall2(bootblock_struct_t *bootblock);

extern void setup_local_apic(int cpu);
extern void print_local_APIC(int cpu, int cpu_id);

inline unsigned long
__atomic_test_mask(unsigned long mask, volatile unsigned long *val)
{
	return ((*val) & mask) != 0;
}

#define	atomic_test_bit(num, val)	__atomic_test_mask((1 << num), &val)
#define	atomic_set_bit(num, val)	__atomic_set_mask((1 << num), &val)
#define	atomic_clear_bit(num, val)	__atomic_clear_mask((1 << num), &val)

static void
simulate_udelay(long utime)
{
	long usec;
	long clock;
	for (usec = 0; usec < utime; usec ++) {
		for (clock = 0; clock < 10; clock++)
			cpu_relax();
	}
}

#define	E2K_APSTARTUP_BASE	0xe2000

static unsigned long
setup_trampoline(void)
{
	e2k_addr_t apstartup;
	int apstartup_size;

	apstartup = (e2k_addr_t)_PAGE_ALIGN_DOWN(E2K_APSTARTUP_BASE,
							E2K_EOS_RAM_PAGE_SIZE);

	apstartup_size = (e2k_addr_t)&__apstartup_end -
				(e2k_addr_t)&__apstartup_start;

	Dprintk("The application CPU stratup code started from addr 0x%X "
		"size 0x%X bytes\n",
		(e2k_addr_t)&__apstartup_start, apstartup_size);
	return apstartup;
}

static atomic_t smp_commenced = ATOMIC_INIT(0);

void
do_smp_commence(void)
{
	/*
	 * Lets the callins below out of their loop.
	 */
	Dprintk("Setting commenced=1, go go go\n");

	atomic_set(&cpu_count, 0);
	cpu_callin_map = 0;
	cpu_callout_map = 0;
	atomic_set(&smp_commenced, 1);
}

static int
do_boot_cpu(int apicid)
{
	unsigned long send_status, accept_status, boot_status;
	int timeout, num_starts, j, cpu;
	unsigned long start_addr;
	int ret = 0;

	cpu = ++phys_cpu_count;

	start_addr = setup_trampoline();

	/* So we see what's up   */
	rom_printk("Booting processor #%d (APIC ID %d) start addr 0x%X\n",
		cpu, apicid, start_addr);

	/*
	 * Status is now clean
	 */
	send_status = 0;
	accept_status = 0;
	boot_status = 0;

	num_starts = 1;

	/*
	 * Run STARTUP IPI loop.
	 */
	Dprintk("#startup loops: %d.\n", num_starts);

	for (j = 1; j <= num_starts; j++) {
		Dprintk("Sending STARTUP #%d.\n",j);
		arch_apic_read(APIC_SPIV);
		arch_apic_write(APIC_ESR, 0);
		arch_apic_read(APIC_ESR);
		Dprintk("After apic_write.\n");

		/*
		 * STARTUP IPI
		 */

		/* Target chip */
		arch_apic_write(APIC_ICR2, SET_APIC_DEST_FIELD(apicid));

		/* Boot on the stack */
		/* Kick the second */
		arch_apic_write(APIC_ICR, APIC_DM_STARTUP
					| (start_addr >> 12));

		/*
		 * Give the other CPU some time to accept the IPI.
		 */
		simulate_udelay(300);

		Dprintk("Startup point 1.\n");

		Dprintk("Waiting for send to finish...\n");
		timeout = 0;
		do {
			Dprintk("+");
			simulate_udelay(100);
			send_status = arch_apic_read(APIC_ICR);
			Dprintk("APIC ICR value : 0x%x busy bit %d\n",
				send_status, (send_status & APIC_ICR_BUSY) != 0);
			send_status &= APIC_ICR_BUSY;
		} while (send_status && (timeout++ < 1000));

		/*
		 * Give the other CPU some time to accept the IPI.
		 */
		simulate_udelay(200);
		accept_status = arch_apic_read(APIC_ESR);
		Dprintk("APIC ESR value : 0x%x accept field 0x%x\n",
			send_status, (accept_status & 0xEF));
		accept_status &= 0xEF;

		{
			unsigned int apic_value;
			int cpu = 0;
			apic_value = arch_apic_read(APIC_NM);
			arch_apic_write(APIC_NM, APIC_NM_BIT_MASK);
			Dprintk("CPU #%d : APIC_NM : 0x%x interrupt bits 0x%x, "
				"startup addr 0x%x\n",
				cpu, apic_value, GET_APIC_NM_BITS(apic_value),
				GET_APIC_STARTUP_ADDR(apic_value));
		}

		if (send_status || accept_status)
			break;
	}
	Dprintk("After Startup loop.\n");

	if (send_status)
		rom_printk("APIC never delivered???\n");
	if (accept_status)
		rom_printk("APIC delivery error (0x%X).\n", accept_status);

	if (!send_status && !accept_status) {
		/*
		 * allow APs to start initializing.
		 */
		Dprintk("Before Callout %d, cpu_callout_map = 0x%x, &cpu_callout_map = 0x%X\n", 
				cpu, cpu_callout_map, &cpu_callout_map);
		atomic_set_bit(cpu, cpu_callout_map);
		Dprintk("After Callout %d, cpu_callout_map = 0x%x\n", cpu, cpu_callout_map);

		/*
		 * Wait 5s total for a response
		 */
		for (timeout = 0; timeout < 5000; timeout++) {
			if (atomic_test_bit(cpu, cpu_callin_map))
				break;	/* It has booted */
			simulate_udelay(100);
		}

		if (atomic_test_bit(cpu, cpu_callin_map)) {
			/* number CPUs logically, starting from 1 (BSP is 0) */
			Dprintk("CPU has booted.\n");
		} else {
			boot_status = 1;
			rom_printk("Not responding.\n");
			print_local_APIC(0, all_apic_ids[0]);
		}
	}
	if (send_status || accept_status || boot_status) {
		phys_cpu_count--;
		ret = -1;
	}

	return ret;
}

/*
 * Cycle through the processors sending APIC STARTUP to boot each.
 */

void
smp_start_cpus(void)
{
	int apicid, cpu;
	int live_cpu_num;
	int ret;

	atomic_set(&smp_commenced, 0);
	phys_cpu_pres_map = 0;
	phys_cpu_count = 0;
	live_cpu_num = atomic_read(&cpu_count);
	if (live_cpu_num > 1)
		rom_printk("Total number of live processors is %d\n",
			live_cpu_num);
	else
		rom_printk("Only one live processor is booting\n");
	for (cpu = 0; cpu < live_cpu_num; cpu ++) {
		phys_cpu_pres_map |= (1 << all_apic_ids[cpu]);
		rom_printk("   CPU #%d %s APIC ID %d\n",
			cpu, (cpu == 0) ? "BSP" : "AP ", all_apic_ids[cpu]);
	}

	if (live_cpu_num > 1)
		setup_local_apic(all_apic_ids[0]);
	else {
#ifdef	CONFIG_L_LOCAL_APIC
		setup_local_apic(all_apic_ids[0]);
#endif	/* CONFIG_L_LOCAL_APIC */
	}

	/*
	 * Now scan the CPU present map and fire up the other CPUs.
	 */
	rom_printk("CPU present map: 0x%X\n", phys_cpu_pres_map);

	for (cpu = 1; cpu < live_cpu_num; cpu ++) {

		apicid = all_apic_ids[cpu];

		ret = do_boot_cpu(apicid);

		/*
		 * Make sure we unmap all failed CPUs
		 */
		if (ret != 0) {
			phys_cpu_pres_map &= ~(1 << apicid);
			rom_printk("phys CPU #%d not responding - "
				"cannot use it.\n",
				apicid);
		}
	}
	phys_cpu_num = phys_cpu_count + 1;

	Dprintk("All CPU boot done.\n");

}

static void
do_smp_callin(int cpuid)
{
	int phys_id;
	unsigned long timeout;

	/*
	 * (This works even if the APIC is not enabled.)
	 */
	phys_id = READ_APIC_ID();

	/*
	 * STARTUP IPIs are fragile beasts as they might sometimes
	 * trigger some glue motherboard logic. Complete APIC bus
	 * silence for 1 second, this overestimates the time the
	 * boot CPU is spending to send the up to 2 STARTUP IPIs
	 * by a factor of two. This should be enough.
	 */

	/*
	 * Waiting 2s total for startup (udelay is not yet working)
	 */
	Dprintk("CPU#%d (APIC ID: %d) waiting for CALLOUT\n", cpuid, phys_id);
	for (timeout = 0; timeout < 20000; timeout++) {
		if (atomic_test_bit(cpuid, cpu_callout_map))
			break;
		simulate_udelay(10);
	}

	if (!atomic_test_bit(cpuid, cpu_callout_map)) {
		rom_printk("BUG: CPU#%d (APIC ID: %d) started up but did "
			"not get a callout!, cpu_callout_map = 0x%x\n",
			cpuid, phys_id, cpu_callout_map);
		do { } while (1);
	}

	/*
	 * the boot CPU has finished the init stage and is spinning
	 * on callin_map until we finish. We are free to set up this
	 * CPU, first the APIC. (this is probably redundant on most
	 * boards)
	 */

	Dprintk("CALLIN, before setup_local_apic().\n");
	setup_local_apic(phys_id);

	/*
	 * Allow the master to continue.
	 */
	atomic_set_bit(cpuid, cpu_callin_map);
}

/*
 * Activate a secondary processor.
 */
void
start_secondary(void *unused)
{
	e2k_psp_hi_t psp_hi;
	e2k_psp_lo_t psp_lo;
	e2k_pcsp_hi_t pcsp_hi;
	e2k_pcsp_lo_t pcsp_lo;
	int	cpu;
	int	cpu_id;
	unsigned int apic_value;
	register unsigned long TIR_hi, TIR_lo;

	cpu = phys_cpu_count;
	cpu_id = all_apic_ids[cpu];

	apic_value = arch_apic_read(APIC_NM);
	TIR_hi = E2K_GET_DSREG(tir.hi);		// order is
        TIR_lo = E2K_GET_DSREG(tir.lo);		// significant
	E2K_SET_DSREG(tir.lo, TIR_lo);      	// un-freeze the TIR's LIFO
	Dprintk("CPU #%d : APIC_NM : 0x%x interrupt bits 0x%x, startup addr "
		"0x%x\n",
		cpu_id, apic_value, GET_APIC_NM_BITS(apic_value),
		GET_APIC_STARTUP_ADDR(apic_value));
	if (GET_APIC_NM_BITS(apic_value) == 0) {
		rom_printk("CPU #%d : ERROR : APIC_NM does not receive any "
			"not masked interrupt\n", cpu_id);
	} else if (!APIC_NM_IS_STRATUP(apic_value)) {
		rom_printk("CPU #%d : ERROR : APIC_NM does not receive STARTUP "
			"interrupt\n", cpu_id);
	} else {
		if (GET_APIC_STARTUP_ADDR(apic_value) != 
						E2K_APSTARTUP_BASE >> 12) {
			rom_printk("CPU #%d : ERROR : APIC_NM received invalid "
				"startup addr 0x%x (should be 0x%x)\n",
				cpu_id, GET_APIC_STARTUP_ADDR(apic_value),
				E2K_APSTARTUP_BASE >> 12);
		}
		Dprintk("CPU #%d : APIC_NM received STARTUP interrupt with "
			"startup addr 0x%x\n",
			cpu, GET_APIC_STARTUP_ADDR(apic_value));
	}
	if ((APIC_NM_MASK(apic_value) & ~APIC_NM_STARTUP) != 0) {
		rom_printk("CPU #%d : ERROR : APIC_NM received unexpected "
			"not masked interrupt 0x%x\n",
			cpu_id, APIC_NM_MASK(apic_value) & ~APIC_NM_STARTUP);
	}
	arch_apic_write(APIC_NM, APIC_NM_BIT_MASK);
	apic_value = arch_apic_read(APIC_NM);
	arch_apic_write(APIC_NM, APIC_NM_BIT_MASK);
	Dprintk("CPU #%d : APIC_NM : 0x%x interrupt bits 0x%x, startup addr "
		"0x%x\n",
		cpu_id, apic_value, GET_APIC_NM_BITS(apic_value),
		GET_APIC_STARTUP_ADDR(apic_value));
	arch_apic_write(APIC_EOI, APIC_EOI_ACK);

	psp_hi = READ_PSP_HI_REG();
	psp_lo = READ_PSP_LO_REG();

	rom_printk("CPU #%d Proc. Stack (PSP) at: 0x%X,",
		cpu_id, AS_STRUCT(psp_lo).base);
	rom_printk(" size: 0x%X,", AS_STRUCT(psp_hi).size);
	rom_printk(" direction: %s.\n", "upward");

	pcsp_hi = READ_PCSP_HI_REG();
	pcsp_lo = READ_PCSP_LO_REG();

	rom_printk("CPU #%d Proc. Chain Stack (PCSP) at: 0x%X,", 
		cpu_id, AS_STRUCT(pcsp_lo).base);
	rom_printk(" size: 0x%X,", AS_STRUCT(pcsp_hi).size);
	rom_printk(" direction: %s.\n", "upward");
	rom_printk("CPU #%d GNU C Stack at: 0x%X,",
		cpu_id, READ_USBR_REG().USBR_base);
	rom_printk(" size: 0x%X, ", E2K_BOOT_KERNEL_US_SIZE);
	rom_printk(" direction: %s.\n", "downward");

	/*
	 * Dont put anything before do_smp_callin(), SMP
	 * booting is too fragile that we want to limit the
	 * things done here to the most necessary things.
	 */
	do_smp_callin(cpu);
	while (!atomic_read(&smp_commenced))
		cpu_relax();

	set_kernel_image_pointers();

	scall2(bootblock);

	E2K_LMS_HALT_OK;
}
