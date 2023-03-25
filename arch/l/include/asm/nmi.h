#ifndef _ASM_L_NMI_H
#define _ASM_L_NMI_H

#include <asm/irq.h>
#include <asm/io.h>

#ifdef ARCH_HAS_NMI_WATCHDOG
extern unsigned int nmi_watchdog;
#define NMI_NONE	0
#define NMI_IO_APIC	1
#define NMI_LOCAL_APIC	2
#define NMI_INVALID	3
#endif

void lapic_watchdog_stop(void);
int lapic_watchdog_init(unsigned nmi_hz);
int lapic_wd_event(unsigned nmi_hz);
unsigned lapic_adjust_nmi_hz(unsigned hz);
void stop_nmi(void);
void restart_nmi(void);

#endif /* _ASM_L_NMI_H */
