#ifndef _ASM_L_ACPI_H
#define _ASM_L_ACPI_H

/*
 *  Copyright (C) 2001 Paul Diefenbaugh <paul.s.diefenbaugh@intel.com>
 *  Copyright (C) 2001 Patrick Mochel <mochel@osdl.org>
 *  Copuright (C) 2012 Evgeny Kravtsunov <kravtsunov_e@mcst.ru>
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 *
 *  This program is free software; you can redistribute it and/or modify
 *  it under the terms of the GNU General Public License as published by
 *  the Free Software Foundation; either version 2 of the License, or
 *  (at your option) any later version.
 *
 *  This program is distributed in the hope that it will be useful,
 *  but WITHOUT ANY WARRANTY; without even the implied warranty of
 *  MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 *  GNU General Public License for more details.
 *
 *  You should have received a copy of the GNU General Public License
 *  along with this program; if not, write to the Free Software
 *  Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 * ~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~~
 */
#include <asm/mpspec.h>
#include <asm/irqflags.h>

#include <acpi/pdc_intel.h>

#define COMPILER_DEPENDENT_INT64   long
#define COMPILER_DEPENDENT_UINT64  unsigned long

/*
 * Calling conventions:
 *
 * ACPI_SYSTEM_XFACE        - Interfaces to host OS (handlers, threads)
 * ACPI_EXTERNAL_XFACE      - External ACPI interfaces
 * ACPI_INTERNAL_XFACE      - Internal ACPI interfaces
 * ACPI_INTERNAL_VAR_XFACE  - Internal variable-parameter list interfaces
 */
#define ACPI_SYSTEM_XFACE
#define ACPI_EXTERNAL_XFACE
#define ACPI_INTERNAL_XFACE
#define ACPI_INTERNAL_VAR_XFACE

/* Asm macros */

#define ACPI_ASM_MACROS
#define BREAKPOINT3
#define ACPI_DISABLE_IRQS() raw_local_irq_disable()
#define ACPI_ENABLE_IRQS()  raw_local_irq_enable()



#ifdef CONFIG_ACPI
#include <asm/acenv.h>
enum idle_boot_override {IDLE_NO_OVERRIDE=0, IDLE_HALT, IDLE_NOMWAIT,
			 IDLE_POLL};

extern int acpi_lapic;
extern int acpi_ioapic;
extern int acpi_noirq;
extern int acpi_strict;
extern int acpi_disabled;
extern int acpi_ht;
extern int acpi_pci_disabled;
extern int acpi_skip_timer_override;
extern int acpi_use_timer_override;
extern int acpi_fix_pin2_polarity;

extern u8 acpi_sci_flags;
extern int acpi_sci_override_gsi;
void acpi_pic_sci_set_trigger(unsigned int, u16);

static inline void disable_acpi(void)
{
	acpi_disabled = 1;
	acpi_ht = 0;
	acpi_pci_disabled = 1;
	acpi_noirq = 1;
}

extern int acpi_gsi_to_irq(u32 gsi, unsigned int *irq);

static inline void acpi_noirq_set(void) { acpi_noirq = 1; }
static inline void acpi_disable_pci(void)
{
	acpi_pci_disabled = 1;
	acpi_noirq_set();
}

/* routines for saving/restoring kernel state */
extern int acpi_save_state_mem(void);
extern void acpi_restore_state_mem(void);

extern unsigned long acpi_wakeup_address;

/*
 * Check if the CPU can handle C2 and deeper
 */
static inline unsigned int acpi_processor_cstate_check(unsigned int max_cstate)
{
	/* here check machine type taken from mptable */
	return 1;
}

/*
 * Elbrus won't implement _PDC as it is deprecated in ACPI4.0 in favor of _OSC
 */
static inline bool arch_has_acpi_pdc(void)
{
	return 0;
}

static inline void arch_acpi_set_pdc_bits(u32 *buf)
{
	return;
}

#else /* !CONFIG_ACPI */

#define acpi_lapic 0
#define acpi_ioapic 0
#define acpi_disable_cmcff 0
static inline void acpi_noirq_set(void) { }
static inline void acpi_disable_pci(void) { }
static inline void disable_acpi(void) { }

#endif /* !CONFIG_ACPI */

#define ARCH_HAS_POWER_INIT	0

#define acpi_unlazy_tlb(x)

#endif /* _ASM_L_ACPI_H */
