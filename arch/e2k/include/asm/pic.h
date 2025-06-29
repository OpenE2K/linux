/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_E2K_PIC_H
#define __ASM_E2K_PIC_H

#include <linux/cpumask.h>
#include <linux/clockchips.h>
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
#endif	/* __ASM_E2K_PIC_H */
