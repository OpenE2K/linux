/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */


#include <linux/types.h>

#include <asm/glob_regs.h>
#include <asm/head.h>
#include <asm/bootinfo.h>
#include <asm/e2k_api.h>
#include <asm/e2k.h>

#include "boot_io.h"
#include "pic.h"

#undef	DEBUG_BOOT_MODE
#undef	Dprintk
#define	DEBUG_BOOT_MODE		0	/* SMP CPU boot */
#define	Dprintk			if (DEBUG_BOOT_MODE) rom_printk

extern char __apstartup_start, __apstartup_end;

atomic_t cpu_count = ATOMIC_INIT(0);
unsigned int all_pic_ids[NR_CPUS];

volatile int		phys_cpu_count = 0;
volatile int		phys_cpu_num = 0;
volatile unsigned long	cpu_callin_map = 0;
volatile unsigned long	cpu_callout_map = 0;
volatile unsigned long	phys_cpu_pres_map = 0;

extern void set_kernel_image_pointers(void);
extern bootblock_struct_t *bootblock;

extern void scall2(bootblock_struct_t *bootblock);

inline unsigned long
__atomic_test_mask(unsigned long mask, volatile unsigned long *val)
{
	return ((*val) & mask) != 0;
}

static inline void __atomic_set_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = 1UL << nr;
	__api_atomic_op(mask, addr, d, "ord", RELAXED_MB);
}

static inline void __atomic_clear_bit(int nr, volatile unsigned long *addr)
{
	unsigned long mask = 1UL << nr;
	__api_atomic_op(mask, addr, d, "andnd", RELAXED_MB);
}

#define	atomic_test_bit(num, val)	__atomic_test_mask((1UL << num), &val)
#define	atomic_set_bit(num, val)	__atomic_set_bit(num, &val)
#define	atomic_clear_bit(num, val)	__atomic_clear_bit(num, &val)

static void
simulate_udelay(long utime)
{
	long usec;
	long clock;
	for (usec = 0; usec < utime; usec ++) {
		for (clock = 0; clock < 10; clock ++) {
			E2K_BUBBLE(1);
		}
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
do_boot_cpu(int picid)
{
	unsigned long send_status, accept_status, boot_status;
	int timeout, num_starts, j, cpu;
	unsigned long start_addr;
	int ret = 0;

	cpu = ++phys_cpu_count;

	start_addr = setup_trampoline();

	/* So we see what's up   */
	rom_printk("Booting processor #%d (PIC ID %d) start addr 0x%X\n",
		cpu, picid, start_addr);

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

		native_pic_reset_esr();

		/*
		 * STARTUP IPI
		 */
		native_pic_send_startup(picid, start_addr);

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
			send_status = native_pic_read_icr_busy();
		} while (send_status && (timeout++ < 1000));

		/*
		 * Give the other CPU some time to accept the IPI.
		 */
		simulate_udelay(200);

		accept_status = native_pic_read_esr();

		if (send_status || accept_status)
			break;
	}
	Dprintk("After Startup loop.\n");

	if (send_status)
		rom_printk("PIC never delivered???\n");
	if (accept_status)
		rom_printk("PIC delivery error (0x%X).\n", accept_status);

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
			rom_printk("Printing PIC contents on CPU#%d/PIC#%d:\n",
				0, all_pic_ids[0]);
			print_local_pic();
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
	int picid, cpu;
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
		phys_cpu_pres_map |= (1 << all_pic_ids[cpu]);
		rom_printk("   CPU #%d %s PIC ID %d\n",
			cpu, (cpu == 0) ? "BSP" : "AP ", all_pic_ids[cpu]);
	}

#ifdef	CONFIG_L_LOCAL_APIC
	setup_local_pic(all_pic_ids[0]);
#endif	/* CONFIG_L_LOCAL_APIC */

	/*
	 * Now scan the CPU present map and fire up the other CPUs.
	 */
	rom_printk("CPU present map: 0x%X\n", phys_cpu_pres_map);

	for (cpu = 1; cpu < live_cpu_num; cpu ++) {

		picid = all_pic_ids[cpu];

		ret = do_boot_cpu(picid);

		/*
		 * Make sure we unmap all failed CPUs
		 */
		if (ret != 0) {
			phys_cpu_pres_map &= ~(1 << picid);
			rom_printk("phys CPU #%d not responding - "
				"cannot use it.\n",
				picid);
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
	phys_id = NATIVE_READ_PIC_ID();

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
	Dprintk("CPU#%d (PIC ID: %d) waiting for CALLOUT\n", cpuid, phys_id);
	for (timeout = 0; timeout < 20000; timeout++) {
		if (atomic_test_bit(cpuid, cpu_callout_map))
			break;
		simulate_udelay(10);
	}

	if (!atomic_test_bit(cpuid, cpu_callout_map)) {
		rom_printk("BUG: CPU#%d (PIC ID: %d) started up but did "
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

	Dprintk("CALLIN, before setup_local_pic().\n");
	setup_local_pic(cpuid);

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
	e2k_usbr_t usbr;
	int	cpu;
	int	cpu_id;
	unsigned int value;
	register unsigned long TIR_hi, TIR_lo;

	cpu = phys_cpu_count;
	cpu_id = all_pic_ids[cpu];

	TIR_hi = NATIVE_READ_TIR_HI_REG_VALUE();	/* order is */
	TIR_lo = NATIVE_READ_TIR_LO_REG_VALUE();	/* significant */
	NATIVE_WRITE_TIR_LO_REG_VALUE(TIR_lo);		/* un-freeze TIR's */

	value = native_pic_read_nm();
	native_pic_reset_nm();
	debug_pic_startup(cpu_id, value, E2K_APSTARTUP_BASE);
	native_pic_write_eoi();

	psp_hi.PSP_hi_half = NATIVE_NV_READ_PSP_HI_REG_VALUE();
	psp_lo.PSP_lo_half = NATIVE_NV_READ_PSP_LO_REG_VALUE();

	rom_printk("CPU #%d Proc. Stack (PSP) at: 0x%X,",
		cpu_id, AS_STRUCT(psp_lo).base);
	rom_printk(" size: 0x%X,", AS_STRUCT(psp_hi).size);
	rom_printk(" direction: %s.\n", "upward");

	pcsp_hi.PCSP_hi_half = NATIVE_NV_READ_PCSP_HI_REG_VALUE();
	pcsp_lo.PCSP_lo_half = NATIVE_NV_READ_PCSP_LO_REG_VALUE();

	rom_printk("CPU #%d Proc. Chain Stack (PCSP) at: 0x%X,", 
		cpu_id, AS_STRUCT(pcsp_lo).base);
	rom_printk(" size: 0x%X,", AS_STRUCT(pcsp_hi).size);
	rom_printk(" direction: %s.\n", "upward");
	usbr.USBR_reg = NATIVE_NV_READ_USBR_REG_VALUE();
	rom_printk("CPU #%d GNU C Stack at: 0x%X,",
		cpu_id, usbr.USBR_base);
	rom_printk(" size: 0x%X, ", E2K_BOOT_KERNEL_US_SIZE);
	rom_printk(" direction: %s.\n", "downward");

	/*
	 * Dont put anything before do_smp_callin(), SMP
	 * booting is too fragile that we want to limit the
	 * things done here to the most necessary things.
	 */
	do_smp_callin(cpu);
	while (!atomic_read(&smp_commenced)) {
		E2K_BUBBLE(1);
	}

	set_kernel_image_pointers();

	scall2(bootblock);

	E2K_LMS_HALT_OK;
}
