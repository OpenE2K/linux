/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef __ASM_L_EPIC_H
#define __ASM_L_EPIC_H

#ifdef __KERNEL__
#include <asm/epicdef.h>
#include <asm/epic_regs.h>
#include <asm-l/pic_common.h>

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
#elif defined(CONFIG_E48C) || defined(CONFIG_E8V7)
# define EPIC_MAX_NODE_CPUS	E48C_MAX_NR_NODE_CPUS
# else
# define EPIC_MAX_NODE_CPUS	(machine.max_nr_node_cpus)
#endif

#define BOOT_EPIC_MAX_NODE_CPUS	(boot_machine.max_nr_node_cpus)

/*
 * CEPIC_ID register has 10 valid bits: 2 for prepicn (node) and 8 for cepicn (core in
 * node). Since currently kernel uses only log2(machine.max_nr_node_cpus) bits of cepicn
 * bits.
 *
 * For example, for e16c machine core 0 on node 1 will have full cepic id = 256 and short
 * cepic id = 16.
 */

static inline unsigned int cepic_id_full_to_short(unsigned int reg_value)
{
	union cepic_id reg_id;

	reg_id.raw = reg_value;
	reg_id.bits.cepicn_reserved = 0;

	return reg_id.bits.prepicn << (bits_per(EPIC_MAX_NODE_CPUS - 1)) |
	       reg_id.bits.cepicn;
}

static inline unsigned int boot_cepic_id_full_to_short(unsigned int reg_value)
{
	union cepic_id reg_id;

	reg_id.raw = reg_value;
	reg_id.bits.cepicn_reserved = 0;

	return reg_id.bits.prepicn << (bits_per(BOOT_EPIC_MAX_NODE_CPUS - 1)) |
	       reg_id.bits.cepicn;
}

static inline unsigned int cepic_id_short_to_full(unsigned int cepic_id)
{
	union cepic_id reg_id;

	reg_id.raw = 0;
	reg_id.bits.cepicn = cepic_id & (roundup_pow_of_two(EPIC_MAX_NODE_CPUS) - 1);
	reg_id.bits.prepicn = cepic_id >> (bits_per(EPIC_MAX_NODE_CPUS - 1));

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
	return reg.bits.bsp_core;
}

static inline u32 epic_vector_prio(u32 vector)
{
	return 1 + ((vector >> 8) & 0x3);
}

extern void __init_recv setup_prepic(void);
extern void ack_epic_irq(void);
extern void epic_send_IPI(unsigned int dest_id, int vector);
extern void epic_send_IPI_mask(const struct cpumask *mask, int vector);
extern void epic_send_IPI_self(int vector);
extern void epic_send_IPI_mask_allbutself(const struct cpumask *mask,
						int vector);
extern void epic_wait_icr_idle(void);
extern void clear_cepic(void);

extern bool pcsm_adjust_enable;

struct pcs_handle {
	void (*pcs_interrupt)(void);
};

extern void register_pcs_handle(const struct pcs_handle *handle);
extern void unregister_pcs_handle(void);

extern void cepic_disable(void);

extern __visible void epic_smp_timer_interrupt(struct pt_regs *regs);
extern __visible void epic_smp_spurious_interrupt(struct pt_regs *regs);
extern __visible void epic_smp_error_interrupt(struct pt_regs *regs);
extern __visible void prepic_smp_error_interrupt(struct pt_regs *regs);
extern __visible void epic_smp_irq_work_interrupt(struct pt_regs *regs);
extern __visible void cepic_epic_interrupt(struct pt_regs *regs);
extern __visible void epic_hc_emerg_interrupt(struct pt_regs *regs);
extern __visible void epic_uncore_interrupt(struct pt_regs *regs);
extern __visible void epic_ipcc_interrupt(struct pt_regs *regs);
extern __visible void epic_hc_interrupt(struct pt_regs *regs);
extern __visible void epic_pcs_interrupt(struct pt_regs *regs);
#ifdef CONFIG_KVM_ASYNC_PF
extern __visible void epic_pv_apf_wake(struct pt_regs *regs);
#endif /* CONFIG_KVM_ASYNC_PF */
#ifdef CONFIG_SMP
extern __visible void epic_smp_irq_move_cleanup_interrupt(struct pt_regs *regs);
extern __visible void epic_smp_reschedule_interrupt(struct pt_regs *regs);
extern __visible void epic_smp_call_function_interrupt(struct pt_regs *regs);
extern __visible void epic_smp_call_function_single_interrupt(
						struct pt_regs *regs);
#endif
#endif	/* __KERNEL__ */
#endif	/* __ASM_L_EPIC_H */
