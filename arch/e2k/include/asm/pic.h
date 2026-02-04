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

static inline bool cpu_has_epic(void)
{
	if (cpu_has(CPU_FEAT_EPIC))
		return true;
	else
		return false;
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

#ifdef CONFIG_EPIC
extern void cpuinfo_epic(struct seq_file *);
#else
static inline void cpuinfo_epic(struct seq_file *m) { }
#endif

#ifdef CONFIG_L_LOCAL_APIC
extern void cpuinfo_apic(struct seq_file *);
#else
static inline void cpuinfo_apic(struct seq_file *m) { }
#endif

static inline void cpuinfo_pic(struct seq_file *m)
{
	cpuinfo_epic(m);
	cpuinfo_apic(m);
}

#endif	/* __ASM_E2K_PIC_H */
