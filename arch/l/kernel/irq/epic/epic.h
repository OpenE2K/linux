/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_L_EPIC_H
#define __ASM_L_EPIC_H

#ifdef __KERNEL__

#include <asm/io.h>

#include "epicdef.h"
#include "epic_regs.h"
#include "../pic.h"


static inline unsigned get_current_epic_core_priority(void)
{
#ifdef	CONFIG_EPIC
	return current_thread_info()->pt_regs->epic_core_priority;
#else
	return 0;
#endif
}

static inline void set_current_epic_core_priority(unsigned p)
{
#ifdef	CONFIG_EPIC
	current_thread_info()->pt_regs->epic_core_priority = p;
#endif
}

#ifdef CONFIG_E2K
/*
 * Basic functions accessing EPICs.
 */
static inline void epic_write_w(unsigned int reg, u32 v)
{
	boot_writel(v, (void __iomem *) (EPIC_DEFAULT_PHYS_BASE + reg));
}

static inline u32 epic_read_w(unsigned int reg)
{
	return boot_readl((void __iomem *) (EPIC_DEFAULT_PHYS_BASE + reg));
}

static inline void epic_write_d(unsigned int reg, u64 v)
{
	boot_writeq(v, (void __iomem *) (EPIC_DEFAULT_PHYS_BASE + reg));
}

static inline u64 epic_read_d(unsigned int reg)
{
	return boot_readq((void __iomem *) (EPIC_DEFAULT_PHYS_BASE + reg));
}

static inline void boot_epic_write_w(unsigned int reg, u32 v)
{
	epic_write_w(reg, v);
}

static inline u32 boot_epic_read_w(unsigned int reg)
{
	return epic_read_w(reg);
}

static inline void epic_write_guest_w(unsigned int reg, unsigned int v)
{
	epic_write_w(CEPIC_GUEST + reg, v);
}

static inline unsigned int epic_read_guest_w(unsigned int reg)
{
	return epic_read_w(CEPIC_GUEST + reg);
}

static inline void epic_write_guest_d(unsigned int reg, unsigned long v)
{
	epic_write_d(CEPIC_GUEST + reg, v);
}

static inline unsigned long epic_read_guest_d(unsigned int reg)
{
	return epic_read_d(CEPIC_GUEST + reg);
}
#else /*CONFIG_E2K*/
#error define your arch
#endif

extern unsigned int early_prepic_node_read_w(int node, unsigned int reg);
extern void early_prepic_node_write_w(int node, unsigned int reg,
					unsigned int v);
extern unsigned int prepic_node_read_w(int node, unsigned int reg);
extern void prepic_node_write_w(int node, unsigned int reg, unsigned int v);

/*
 * Verbosity can be turned on by passing 'epic_debug' cmdline parameter
 * epic_debug is defined in epic.c
 */
extern bool epic_debug;
#define	epic_printk(s, a...) do {		\
		if (epic_debug)			\
			printk(s, ##a);		\
	} while (0)

extern bool epic_bgi_mode;
extern unsigned int cepic_timer_delta;
extern void setup_boot_epic_clock(void);
extern void __init setup_bsp_epic(void);

/*
 * Tiny boot support
 */
#if defined(CONFIG_E16C) || defined(CONFIG_E2C3) || defined(CONFIG_E12C)
# define EPIC_MAX_NODE_CPUS	E16C_MAX_NR_NODE_CPUS
#elif defined(CONFIG_E8V7)
# define EPIC_MAX_NODE_CPUS	E8V7_MAX_NR_NODE_CPUS
# else
# define EPIC_MAX_NODE_CPUS	(machine.max_nr_node_cpus)
#endif

#define BOOT_EPIC_MAX_NODE_CPUS	(boot_machine.max_nr_node_cpus)

/*
 * CEPIC_ID register has 10 valid bits: 2 for prepicn (node) and 8 for cepicn (core in
 * node). Since currently kernel uses only log2(machine.max_nr_node_cpus) bits of cepicn
 *
 *
 * For example, for e16c machine core 0 on node 1 will have full cepic id = 256 and short
 * cepic id = 16.
 */

static inline unsigned int cepic_id_full_to_short(unsigned int reg_value)
{
	union cepic_id reg_id;

	reg_id.raw = reg_value;
	reg_id.cepicn_reserved = 0;

	return reg_id.prepicn << (bits_per(EPIC_MAX_NODE_CPUS - 1)) |
	       reg_id.cepicn;
}

static inline unsigned int boot_cepic_id_full_to_short(unsigned int reg_value)
{
	union cepic_id reg_id;

	reg_id.raw = reg_value;
	reg_id.cepicn_reserved = 0;

	return reg_id.prepicn << (bits_per(BOOT_EPIC_MAX_NODE_CPUS - 1)) |
	       reg_id.cepicn;
}

static inline unsigned int cepic_id_short_to_full(unsigned int cepic_id)
{
	union cepic_id reg_id;

	reg_id.raw = 0;
	reg_id.cepicn = cepic_id & (roundup_pow_of_two(EPIC_MAX_NODE_CPUS) - 1);
	reg_id.prepicn = cepic_id >> (bits_per(EPIC_MAX_NODE_CPUS - 1));

	return reg_id.raw;
}

/* Convert logical CPU ID to full physical EPIC ID (ID < 1024) */
static inline unsigned int cpu_to_full_cepic_id(unsigned int cpu)
{
	return cepic_id_short_to_full(cpu_to_short_picid(cpu));
}

static inline unsigned int read_epic_id(void)
{
	return cepic_id_full_to_short(epic_read_w(CEPIC_ID));
}

static inline bool read_epic_bsp(void)
{
	union cepic_ctrl reg;

	reg.raw = epic_read_w(CEPIC_CTRL);
	return reg.bsp_core;
}

static inline u32 epic_vector_prio(u32 vector)
{
	return 1 + ((vector >> 8) & 0x3);
}

extern void ack_epic_irq(void);
extern void epic_wait_icr_idle(void);
extern void epic_send_IPI(unsigned int dest_id, int vector);
extern void epic_send_IPI_mask(const struct cpumask *mask, int vector);
extern void epic_send_IPI_self(int vector);
extern void epic_send_IPI_mask_allbutself(const struct cpumask *mask, int vector);

extern int epic_get_vector(void);

extern int epic_processor_info(int epicid, int version, unsigned int cepic_freq);
extern unsigned long cepic_timer_freq;

#endif	/* __KERNEL__ */
#endif	/* __ASM_L_EPIC_H */
