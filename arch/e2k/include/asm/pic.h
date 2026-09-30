/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_E2K_PIC_H
#define __ASM_E2K_PIC_H

#include <linux/cpumask.h>
#include <linux/clockchips.h>
#include <linux/delay.h>
#include <asm/cpu_features.h>

static __always_inline bool cpu_has_epic(void)
{
	return cpu_has(CPU_FEAT_EPIC);
}

unsigned int read_pic_id(void);
int pic_get_vector(void);
void ack_pic_irq(void);
void fixup_irqs_pic(void);
void get_io_pic_msi(int node, u32 *lo, u32 *hi);

bool boot_early_pic_is_bsp(void);
unsigned int boot_early_pic_read_id(void);
void pic_processor_info(int picid, int picver, unsigned int freq);

bool read_pic_bsp(void);

int pic_send_nmi(const struct cpumask *target);

/* For do_postpone_tick() */
extern void cepic_timer_interrupt(struct clock_event_device *evt);
extern void local_apic_timer_interrupt(struct clock_event_device *evt);

static inline void local_pic_timer_interrupt(void)
{
	if (cpu_has_epic())
		cepic_timer_interrupt(NULL);
	else
		local_apic_timer_interrupt(NULL);
}


extern u32 lapic_save_and_clear_nmi(void);
extern u32 cepic_save_and_clear_nmi(void);

/**
 * save_pic_nmi - saves NMI bits from interrupt controller to pt_regs
 *
 * We must keep NMIs closed between entering trap and getting
 * NMI interrupts from the NMI regiser.  Otherwise we would
 * enter handler again immediately after opening interrupts
 * in %psr (because nm_interrupt signal in controller is not
 * cleared until explicit NMI register write).
 */
static __always_inline __must_check u32 pic_save_and_clear_nmi(void)
{
	if (cpu_has_epic())
		return cepic_save_and_clear_nmi();
	else
		return lapic_save_and_clear_nmi();
}


extern void cepic_disable(void);
extern void disable_local_APIC(void);

static inline void pic_disable(void)
{
	if (cpu_has_epic())
		cepic_disable();
	else
		disable_local_APIC();
}

struct seq_file;
struct iopic;

#ifdef CONFIG_EPIC
extern void cpuinfo_epic(struct seq_file *);
extern void print_epics(void) __cold;
extern void print_cepic(void) __cold;
extern void print_IO_EPIC(struct iopic *pic) __cold;
#else
static inline void cpuinfo_epic(struct seq_file *m) { }
static inline void print_epics(void) { }
static inline void print_cepic(void) { }
static inline void print_IO_EPIC(struct iopic *pic) { }
#endif

#ifdef CONFIG_L_LOCAL_APIC
extern void cpuinfo_apic(struct seq_file *);
extern void print_local_APICs(void) __cold;
extern void print_local_APIC(void) __cold;
extern void print_IO_APIC(struct iopic *pic) __cold;
#else
static inline void cpuinfo_apic(struct seq_file *m) { }
static inline void print_local_APICs(void) { }
static inline void print_local_APIC(void) { }
static inline void print_IO_APIC(struct iopic *pic) { };
#endif

static inline void cpuinfo_pic(struct seq_file *m)
{
	cpuinfo_epic(m);
	cpuinfo_apic(m);
}

static inline void print_local_pic(void)
{
	if (cpu_has_epic())
		return print_cepic();
	else
		return print_local_APIC();
}

static inline void print_local_pics(void)
{
	if (cpu_has_epic())
		return print_epics();
	else
		return print_local_APICs();
}

static inline void print_IO_PIC(struct iopic *pic, int pic_idx)
{
	if (cpu_has_epic())
		return print_IO_EPIC(pic);
	else
		return print_IO_APIC(pic);
}

extern void __cold print_IO_PICs(void);

#endif	/* __ASM_E2K_PIC_H */
