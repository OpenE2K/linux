/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _E2K_MACHDEP_H_
#define _E2K_MACHDEP_H_

#include <linux/init.h>
#include <linux/types.h>

#include <uapi/asm/iset_ver.h>

#include <asm/aau_regs_types.h>
#include <asm/sections.h>
#include <asm/mmu_types.h>
#include <asm/p2v/boot_v2p.h>

#ifdef __KERNEL__

struct cpuinfo_e2k;
struct pt_regs;
struct seq_file;
struct e2k_global_regs;
struct kernel_gregs;
struct local_gregs;
struct e2k_mlt;
struct kvm_vcpu_arch;
struct thread_info;

#include <asm/kvm/machdep.h>	/* virtualization support */

typedef void (*restore_gregs_fn_t)(const struct e2k_global_regs *);
typedef void (*save_gregs_fn_t)(struct e2k_global_regs *);
typedef struct machdep {
	int		native_id;		/* machine Id */
	int		native_rev;		/* cpu revision */
	e2k_iset_ver_t	native_iset_ver;	/* Instruction set version */
	bool		cmdline_iset_ver;	/* iset specified in cmdline */
	bool		L3_enable;		/* cache L3 is enable */
	bool		gmi;			/* is hardware virtualized */
						/* guest VM */
	e2k_addr_t	io_area_base;
	e2k_addr_t	io_area_size;
	u8		max_nr_node_cpus;
	u8		nr_node_cpus;
	u8		node_iolinks;
	e2k_addr_t	pcicfg_area_phys_base;
	e2k_size_t	pcicfg_area_size;
	e2k_addr_t	nsr_area_phys_base;
	u64		tlb_addr_line_num;
	u64		tlb_addr_line_num2;
	u8		tlb_addr_line_num_shift2;
	u8		tlb_addr_set_num;
	u8		tlb_addr_set_num_shift;
	e2k_size_t	sic_mc_size;
	u8		sic_mc_count;
	u32		sic_mc1_ecc;
	u32		sic_io_str1;
	u8		sic_ha_num;
	u8		sic_comms;
	u8		qnr1_offset;


	e2k_addr_t (*get_nsr_area_phys_base)(void);
	void (*setup_apic_vector_handlers)(void);
#ifdef CONFIG_SMP
	void (*clk_off)(void);
	void (*clk_on)(int);
#endif
	void (*C1_enter)(void);
	void (*C3_enter)(void);

	/* Often used pointers are placed close to each other */

	void (*save_kernel_gregs)(struct kernel_gregs *);
	void (*save_gregs)(struct e2k_global_regs *);
	void (*save_local_gregs)(struct local_gregs *, bool is_signal);
	save_gregs_fn_t save_gregs_dirty_bgr;
	restore_gregs_fn_t restore_gregs;
	void (*save_gregs_on_mask)(struct e2k_global_regs *, bool dirty_bgr,
				   unsigned long not_save_gregs_mask);
	void (*restore_local_gregs)(const struct local_gregs *, bool is_signal);
	void (*restore_gregs_on_mask)(struct e2k_global_regs *, bool dirty_bgr,
				      unsigned long not_restore_gregs_mask);
	void (*save_kvm_context)(struct kvm_vcpu_arch *);
	void (*restore_kvm_context)(const struct kvm_vcpu_arch *);

	void (*calculate_aau_aaldis_aaldas)(const struct pt_regs *regs,
					    e2k_aalda_t *aaldas,
					    e2k_aau_t *context);
	void (*do_aau_fault)(int aa_field, struct pt_regs *regs);
	void (*save_aaldi)(u64 *aaldis);
	void (*get_aau_context)(e2k_aau_t *, e2k_aasr_t);
	unsigned long	(*boot_rrd)(int reg);
	void		(*boot_rwd)(int reg, unsigned long value);
#ifdef CONFIG_MLT_STORAGE
	void		(*get_and_invalidate_MLT_context)(struct e2k_mlt *mlt_state);
#endif

	void		(*setup_arch)(void);
	void		(*setup_cpu_info)(struct cpuinfo_e2k *c);
	int		(*show_cpuinfo)(struct seq_file *m, void *v);

	int		(*set_wallclock)(unsigned long nowtime);
	unsigned long	(*get_wallclock)(void);

	void		(*restart)(char *cmd);
	void		(*power_off)(void);
	void		(*halt)(void);
	void		(*arch_reset)(char *cmd);
	void		(*arch_halt)(void);

	int		(*get_irq_vector)(void);

	/* virtualization support: guest kernel and host/hypervisor */
	guest_machdep_t	guest;	/* guest additional fields (used only by */
				/* guest at arch/e2k/kvm/guest/xxx) */
} machdep_t;

extern machdep_t	machine;
extern pt_struct_t	pgtable_struct;

#define	CURRENT_ISET		((u32)machine.native_iset_ver)
#define CURRENT_HA_NUM		(machine.sic_ha_num)
#define CURRENT_HA_MASK		((1 << machine.sic_ha_num) - 1)
#define CURRENT_COMMS_IN_NODE	(machine.sic_comms)

#if defined E2K_P2V && !defined CONFIG_BOOT_E2K
# define boot_machine		(boot_get_vo_value(machine))
# define boot_pgtable_struct	((pt_struct_t)boot_get_vo_value(pgtable_struct))
# define boot_pgtable_struct_p	boot_vp_to_pp(&pgtable_struct)
#else
# define boot_machine		machine
# define boot_pgtable_struct	pgtable_struct
# define boot_pgtable_struct_p	(&pgtable_struct)
#endif

/* Returns true in guest running with hardware virtualization support */
#ifndef E2K_P2V
# define IS_HV_GM()	(cpu_has(CPU_FEAT_ISET_V6) && read_CORE_MODE_reg().gmi)
#else
# define IS_HV_GM()	(machine.gmi)
#endif

#define	IS_IRQ_MASK_GLOBAL()	cpu_has(CPU_FEAT_GLOBAL_IRQ_MASK)

extern void save_kernel_gregs_v3(struct kernel_gregs *);
extern void save_kernel_gregs_v5(struct kernel_gregs *);
extern void save_gregs_v3(struct e2k_global_regs *);
extern void save_gregs_v5(struct e2k_global_regs *);
extern void save_local_gregs_v3(struct local_gregs *, bool is_signal);
extern void save_local_gregs_v5(struct local_gregs *, bool is_signal);
extern void save_gregs_dirty_bgr_v3(struct e2k_global_regs *);
extern void save_gregs_dirty_bgr_v5(struct e2k_global_regs *);
extern void save_gregs_on_mask_v3(struct e2k_global_regs *, bool dirty_bgr,
				  unsigned long mask_not_save);
extern void save_gregs_on_mask_v5(struct e2k_global_regs *, bool dirty_bgr,
				  unsigned long mask_not_save);
extern void restore_gregs_v3(const struct e2k_global_regs *);
extern void restore_gregs_v5(const struct e2k_global_regs *);
extern void restore_local_gregs_v3(const struct local_gregs *, bool is_signal);
extern void restore_local_gregs_v5(const struct local_gregs *, bool is_signal);
extern void restore_gregs_on_mask_v3(struct e2k_global_regs *, bool dirty_bgr,
				     unsigned long mask_not_restore);
extern void restore_gregs_on_mask_v5(struct e2k_global_regs *, bool dirty_bgr,
				     unsigned long mask_not_restore);
extern void save_kvm_context_v6(struct kvm_vcpu_arch *);
extern void save_kvm_context_v7(struct kvm_vcpu_arch *);
extern void restore_kvm_context_v6(const struct kvm_vcpu_arch *);
extern void restore_kvm_context_v7(const struct kvm_vcpu_arch *);
extern void qpswitchd_sm(int);

extern void calculate_aau_aaldis_aaldas_v3(const struct pt_regs *regs,
					   e2k_aalda_t *aaldas, e2k_aau_t *context);
extern void calculate_aau_aaldis_aaldas_v5(const struct pt_regs *regs,
					   e2k_aalda_t *aaldas, e2k_aau_t *context);
extern void calculate_aau_aaldis_aaldas_v6(const struct pt_regs *regs,
					   e2k_aalda_t *aaldas, e2k_aau_t *context);
extern void do_aau_fault_v3(int aa_field, struct pt_regs *regs);
extern void do_aau_fault_v5(int aa_field, struct pt_regs *regs);
extern void do_aau_fault_v6(int aa_field, struct pt_regs *regs);
extern void save_aaldi_v3(u64 *aaldis);
extern void save_aaldi_v5(u64 *aaldis);
extern void get_aau_context_v3(e2k_aau_t*, e2k_aasr_t);
extern void get_aau_context_v5(e2k_aau_t*, e2k_aasr_t);

extern unsigned long boot_native_read_IDR_reg_value(void);

unsigned long rrd_v3(int);
unsigned long rrd_v5(int);
unsigned long rrd_v6(int);
void rwd_v3(int reg, unsigned long value);
void rwd_v5(int reg, unsigned long value);
void rwd_v6(int reg, unsigned long value);
unsigned long boot_rrd_v3(int);
unsigned long boot_rrd_v6(int);
void boot_rwd_v3(int reg, unsigned long value);
void boot_rwd_v6(int reg, unsigned long value);

/* Supported registers for machine->rrd()/rwd() */
enum {
	E2K_REG_CU_HW1,
	E2K_REG_HCEM,
	E2K_REG_HCEB,
	E2K_REG_OSCUTD,
	E2K_REG_OSCUIR,
};

u64 native_get_cu_hw1_v3(void);
u64 native_get_cu_hw1_v5(void);
void native_set_cu_hw1_v3(u64);
void native_set_cu_hw1_v5(u64);

void get_and_invalidate_MLT_context_v3(struct e2k_mlt *mlt_state);
void get_and_invalidate_MLT_context_v6(struct e2k_mlt *mlt_state);

#ifdef CONFIG_SMP
void native_clock_off_v3(void);
void native_clock_on_v3(int cpu);
#endif

void C1_enter_v3(void);
void C1_enter_v6(void);
void C3_enter_v3(void);
void C3_enter_v6(void);
#endif /* __KERNEL__ */

#endif /* _E2K_MACHDEP_H_ */
