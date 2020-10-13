/*
 *	Local APIC handling, local APIC timers
 */

#include <linux/init.h>

#include <linux/mm.h>
#include <linux/irq.h>
#include <linux/types.h>

#include <asm/atomic.h>
#include <asm/head.h>
#include <asm/apic.h>
#include <asm/bootinfo.h>
#include <asm/e2k_debug.h>

#include <asm/e2k_api.h>
/**************************** DEBUG DEFINES *****************************/
#undef	DEBUG_BOOT_MODE
#undef	Dprintk
#define	DEBUG_BOOT_MODE		0	/* SMP CPU boot */
#define	Dprintk			if (DEBUG_BOOT_MODE) rom_printk
/************************************************************************/

void
setup_local_apic(int cpu)
{
	unsigned int value, ver;

	value = arch_apic_read(APIC_LVR);
	ver = GET_APIC_VERSION(value);
	Dprintk("APIC_LVR : 0x%x version 0x%x maxlvt 0x%x\n",
		value, ver, GET_APIC_MAXLVT(value));

	/*
	 * Put the APIC into flat delivery mode.
	 * Must be "all ones" explicitly for 82489DX.
	 */
	value = arch_apic_read(APIC_DFR);
	Dprintk("APIC_DFR before setup : 0x%x delivery mode 0x%x\n",
		value, GET_APIC_DLVR_MODE(value));
	arch_apic_write(APIC_DFR, 0xffffffff);
	value = arch_apic_read(APIC_DFR);
	Dprintk("APIC_DFR after setup : 0x%x delivery mode 0x%x\n",
		value, GET_APIC_DLVR_MODE(value));

	/*
	 * Set up the logical destination ID.
	 */
	value = arch_apic_read(APIC_LDR);
	Dprintk("APIC_LDR before setup : 0x%x logical ID 0x%x\n",
		value, GET_APIC_LOGICAL_ID(value));
	value &= ~APIC_LDR_MASK;
	value |= SET_APIC_LOGICAL_ID(cpu);
	arch_apic_write(APIC_LDR, value);
	value = arch_apic_read(APIC_LDR);
	Dprintk("APIC_LDR after setup : 0x%x logical ID 0x%x\n",
		value, GET_APIC_LOGICAL_ID(value));

	/*
	 * Reset all not masked interrupts
	 */

	value = arch_apic_read(APIC_NM);
	Dprintk("APIC_NM before setup : 0x%x\n",
		value);
	arch_apic_write(APIC_NM, APIC_NM_BIT_MASK);
#if DEBUG_BOOT_MODE
	value = arch_apic_read(APIC_NM);
	arch_apic_write(APIC_NM, APIC_NM_BIT_MASK);
	Dprintk("APIC_NM after setup : 0x%x\n", value);
#endif

	/*
	 * Now that we are all set up, enable the APIC
	 */
	value = arch_apic_read(APIC_BSP);
	Dprintk("APIC_BSP before setup : 0x%x apic enable %d, BSP flag %d\n",
		value, APIC_ENABLE(value) != 0, BootStrap(value) != 0);
	value |= APIC_BSP_ENABLE;
	arch_apic_write(APIC_BSP, value);
	value = arch_apic_read(APIC_BSP);
	Dprintk("APIC_BSP after setup : 0x%x apic enable %d, BSP flag %d\n",
		value, APIC_ENABLE(value) != 0, BootStrap(value) != 0);

	value = arch_apic_read(APIC_SPIV);
	Dprintk("APIC_SPIV before setup : 0x%x apic soft enabled %d, "
		"focus processor disabled %d, spurious vector 0x%x\n",
		value, APIC_SOFT_ENABLED(value) != 0,
		APIC_FOCUS_DISABLED(value) != 0,
		GET_SPURIOUS_VECTOR(value));
//	value &= ~APIC_VECTOR_MASK;
	/*
	 * Enable APIC
	 */
	value |= APIC_SPIV_APIC_ENABLED;

	/*
	 * Some unknown Intel IO/APIC (or APIC) errata is biting us with
	 * certain networking cards. If high frequency interrupts are
	 * happening on a particular IOAPIC pin, plus the IOAPIC routing
	 * entry is masked/unmasked at a high rate as well then sooner or
	 * later IOAPIC line gets 'stuck', no more interrupts are received
	 * from the device. If focus CPU is disabled then the hang goes
	 * away, oh well :-(
	 *
	 * [ This bug can be reproduced easily with a level-triggered
	 *   PCI Ne2000 networking cards and PII/PIII processors, dual
	 *   BX chipset. ]
	 */
	/* Disable focus processor (bit==1) */
	value |= APIC_SPIV_FOCUS_DISABLED;
	arch_apic_write(APIC_SPIV, value);
	
	Dprintk("APIC_SPIV after setup : 0x%x apic soft enabled %d, "
		"focus processor disabled %d, spurious vector 0x%x\n",
		value, APIC_SOFT_ENABLED(value) != 0,
		APIC_FOCUS_DISABLED(value) != 0,
		GET_SPURIOUS_VECTOR(value));

	value = arch_apic_read(APIC_LVT0);
	Dprintk("APIC_LVT0 before setup : 0x%x apic lvt masked %d\n",
		value, (value & APIC_LVT_MASKED) != 0);
	if (!cpu) {
		value = APIC_DM_EXTINT;
	} else {
		value = APIC_DM_EXTINT | APIC_LVT_MASKED;
	}
	arch_apic_write(APIC_LVT0, value);
	Dprintk("APIC_LVT0 after setup : 0x%x apic lvt masked %d, "
		"Ext Int enabled 0x%d\n",
		value, (value & APIC_LVT_MASKED) != 0,
		(value & APIC_DM_EXTINT) != 0);

	/*
	 * only the BP should see the LINT1 NMI signal, obviously.
	 */
	if (!cpu)
		value = APIC_DM_NMI;
	else
		value = APIC_DM_NMI | APIC_LVT_MASKED;
	arch_apic_write(APIC_LVT1, value);
}

void
clear_local_apic(void)
{
	arch_apic_write(APIC_BSP, 0);
	arch_apic_write(APIC_SPIV, 0);
}

void
print_local_APIC(int cpu, int cpu_id)
{
	unsigned int v, ver, maxlvt;

	rom_printk("\n" "printing local APIC contents on CPU#%d/%d:\n",
		cpu, cpu_id);
	v = arch_apic_read(APIC_BSP);
	if (!APIC_ENABLE(v)) {
		rom_printk(" APIC disable\n");
		return;
	}
	if (BootStrap(v))
		rom_printk("... BootStrap processor\n");
	else
		rom_printk("... Aplication processor\n");
	v = arch_apic_read(APIC_ID);
	rom_printk("... APIC ID:      %08x (%01x)\n", v, GET_APIC_ID(v));
	v = arch_apic_read(APIC_LVR);
	rom_printk("... APIC VERSION: %08x\n", v);
	ver = GET_APIC_VERSION(v);
	maxlvt = GET_APIC_MAXLVT(v);

	v = arch_apic_read(APIC_TASKPRI);
	rom_printk("... APIC TASKPRI: %08x (%02x)\n", v, v & APIC_TPRI_MASK);

	if (APIC_INTEGRATED(ver)) {			/* !82489DX */
		v = arch_apic_read(APIC_ARBPRI);
		rom_printk( "... APIC ARBPRI: %08x (%02x)\n", v,
			v & APIC_ARBPRI_MASK);
		v = arch_apic_read(APIC_PROCPRI);
		rom_printk( "... APIC PROCPRI: %08x\n", v);
	}

//	v = arch_apic_read(APIC_EOI);
//	rom_printk( "... APIC EOI: %08x\n", v);
	v = arch_apic_read(APIC_LDR);
	rom_printk( "... APIC LDR: %08x\n", v);
	v = arch_apic_read(APIC_DFR);
	rom_printk( "... APIC DFR: %08x\n", v);
	v = arch_apic_read(APIC_SPIV);
	rom_printk( "... APIC SPIV: %08x\n", v);

	if (APIC_INTEGRATED(ver)) {		/* !82489DX */
		if (maxlvt > 3)		/* Due to the Pentium erratum 3AP. */
			arch_apic_write(APIC_ESR, 0);
		v = arch_apic_read(APIC_ESR);
		rom_printk( "... APIC ESR: %08x\n", v);
	}

	v = arch_apic_read(APIC_ICR);
	rom_printk( "... APIC ICR: %08x\n", v);
	v = arch_apic_read(APIC_ICR2);
	rom_printk( "... APIC ICR2: %08x\n", v);

	v = arch_apic_read(APIC_LVTT);
	rom_printk( "... APIC LVTT: %08x\n", v);

	if (maxlvt > 3) {                       /* PC is LVT#4. */
		v = arch_apic_read(APIC_LVTPC);
		rom_printk( "... APIC LVTPC: %08x\n", v);
	}
	v = arch_apic_read(APIC_LVT0);
	rom_printk( "... APIC LVT0: %08x\n", v);
	v = arch_apic_read(APIC_LVT1);
	rom_printk( "... APIC LVT1: %08x\n", v);

	if (maxlvt > 2) {			/* ERR is LVT#3. */
		v = arch_apic_read(APIC_LVTERR);
		rom_printk( "... APIC LVTERR: %08x\n", v);
	}

	v = arch_apic_read(APIC_TMICT);
	rom_printk( "... APIC TMICT: %08x\n", v);
	v = arch_apic_read(APIC_TMCCT);
	rom_printk( "... APIC TMCCT: %08x\n", v);
	v = arch_apic_read(APIC_TDCR);
	rom_printk( "... APIC TDCR: %08x\n", v);
	v = arch_apic_read(APIC_M_ERM);
	rom_printk( "... APIC_M_ERM: %08x\n", v);
	v = arch_apic_read(APIC_NM);
	arch_apic_write(APIC_NM, APIC_NM_BIT_MASK);
	rom_printk( "... APIC_NM: %08x\n", v);
	rom_printk("\n");

}
