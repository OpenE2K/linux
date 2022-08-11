#ifndef __ASM_L_EPIC_H
#define __ASM_L_EPIC_H

#ifdef __KERNEL__
#include <asm/epicdef.h>
#include <asm/epic_regs.h>

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
 * CEPIC_ID register has 10 valid bits: 2 for prepicn (node) and 8 for
 * cepicn (core in node). Since currently kernel does not support NR_CPUS > 64,
 * we ignore 4 most significant bits of cepicn.
 *
 * For example, core 0 on node 1 will have full cepic id = 256 and short cepic
 * id = 16
 */
static inline unsigned int cepic_id_full_to_short(unsigned int reg_value)
{
	union cepic_id reg_id;

	reg_id.raw = reg_value;
	reg_id.bits.cepicn_reserved = 0;
	return reg_id.bits.prepicn << CEPIC_ID_SHORT_VALID_BITS
			| reg_id.bits.cepicn;
}

static inline unsigned int cepic_id_short_to_full(unsigned int cepic_id)
{
	union cepic_id reg_id;

	reg_id.raw = 0;
	reg_id.bits.cepicn = cepic_id & CEPIC_ID_SHORT_VALID_MASK;
	reg_id.bits.prepicn = cepic_id >> CEPIC_ID_SHORT_VALID_BITS;
	return reg_id.raw;
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

extern __visible void epic_smp_timer_interrupt(struct pt_regs *regs);
extern __visible void epic_smp_spurious_interrupt(struct pt_regs *regs);
extern __visible void epic_smp_error_interrupt(struct pt_regs *regs);
extern __visible void prepic_smp_error_interrupt(struct pt_regs *regs);
extern __visible void epic_smp_irq_work_interrupt(struct pt_regs *regs);
extern __visible void cepic_epic_interrupt(struct pt_regs *regs);
extern __visible void epic_hc_emerg_interrupt(struct pt_regs *regs);
extern __visible void epic_iommu_interrupt(struct pt_regs *regs);
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
