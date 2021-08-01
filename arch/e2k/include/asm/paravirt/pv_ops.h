/******************************************************************************
 * Copyright (c) 2008 MCST (C)
 *
 * This program is free software; you can redistribute it and/or modify
 * it under the terms of the GNU General Public License as published by
 * the Free Software Foundation; either version 2 of the License, or
 * (at your option) any later version.
 *
 * This program is distributed in the hope that it will be useful,
 * but WITHOUT ANY WARRANTY; without even the implied warranty of
 * MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
 * GNU General Public License for more details.
 *
 * You should have received a copy of the GNU General Public License
 * along with this program; if not, write to the Free Software
 * Foundation, Inc., 59 Temple Place, Suite 330, Boston, MA  02111-1307  USA
 *
 */


#ifndef __ASM_E2K_PARAVIRT_PV_OPS_H
#define __ASM_E2K_PARAVIRT_PV_OPS_H

#ifdef	CONFIG_PARAVIRT

#ifndef __ASSEMBLY__

#include <linux/threads.h>
#include <linux/init.h>
#include <linux/spinlock_types.h>
#include <linux/irqreturn.h>

#include <asm/p2v/boot_v2p.h>
#include <asm/e2k_api.h>
#include <asm/glob_regs.h>
#include <asm/bootinfo.h>
#include <asm/aau_regs_types.h>
#include <asm/mmu_regs_types.h>
#include <asm/tlb_regs_types.h>
#include <asm/mmu_types.h>


/*
 * Should use call_single_data_t instead, but there is a problem with forward
 * declaration of typedef.
 */
struct __call_single_data;

struct pt_regs;
struct e2k_stacks;
struct hw_stack;
struct hw_stack_area;
struct thread_info;
struct as_sa_handler_arg;
struct global_regs;
struct local_gregs;
struct page;
struct trap_cellar;
struct user_namespace;
enum pte_mem_type;
struct mmu_gather;

#define	INLINE_FUNC_CALL	((void *)-1UL)	/* inline function should be */
						/* called here */

/*
 * booting hooks.
 */

struct node_phys_mem;
struct mm_struct;
struct vm_area_struct;
struct thread_info;
struct timespec;
struct timeval;

typedef struct pv_boot_ops {
	void	(*boot_setup_machine_id)(bootblock_struct_t *bootblock);
	int	(*boot_loader_probe_memory)(
				struct node_phys_mem *nodes_phys_mem,
				boot_info_t *bootblock);
	e2k_size_t (*boot_get_bootblock_size)(boot_info_t *bblock);
	void	(*boot_cpu_relax)(void);
#ifdef	CONFIG_SMP
	int	(*boot_smp_cpu_config)(boot_info_t *bootblock);
	void	(*boot_smp_node_config)(boot_info_t *bootblock);
#endif	/* CONFIG_SMP */
	void	(*boot_reserve_all_bootmem)(bool bsp, boot_info_t *boot_info);
	void	(*boot_map_all_bootmem)(bool bsp, boot_info_t *boot_info);
	void	(*boot_map_needful_to_equal_virt_area)
					(e2k_addr_t stack_top_addr);
	void	(*boot_kernel_switch_to_virt)(bool bsp, int cpuid,
			void (*boot_init_sequel_func)(bool bsp, int cpuid,
							int cpus_to_sync));
	void	(*boot_clear_bss)(void);
	void	(*boot_check_bootblock)(bool bsp,
				bootblock_struct_t *bootblock);

	void	(*init_terminate_boot_init)(bool bsp, int cpuid);
	void	(*boot_parse_param)(bootblock_struct_t *bootblock);
	void	(*boot_debug_cons_outb)(u8 byte, u16 port);
	u8	(*boot_debug_cons_inb)(u16 port);
	u32	(*boot_debug_cons_inl)(u16 port);
	void	(*debug_cons_outb)(u8 byte, u16 port);
	u8	(*debug_cons_inb)(u16 port);
	u32	(*debug_cons_inl)(u16 port);
	void	(*do_boot_panic)(const char *fmt_v, ...);
} pv_boot_ops_t;

extern pv_boot_ops_t pv_boot_ops;
extern pv_boot_ops_t *cur_pv_boot_ops;	/* pointer to boot-time tables of OPs */

#define	BOOT_PARAVIRT_GET_BOOT_FUNC(func_name)				\
		BOOT_PARAVIRT_GET_BOOT_OPS_FUNC(cur_pv_boot_ops, func_name)

#define	BOOT_PARAVIRT_OUT_OP(op_func, value, port)			\
({									\
	BOOT_PARAVIRT_GET_BOOT_FUNC(op_func)(value, port);		\
})
#define	BOOT_PARAVIRT_IN_OP(op_func, port)				\
({									\
	BOOT_PARAVIRT_GET_BOOT_FUNC(op_func)(port);			\
})

/*
 * initialization hooks.
 */

typedef struct pv_init_ops {
	void (*banner)(void);
	void (*set_mach_type_id)(void);
	void (*print_machine_type_info)(void);
} pv_init_ops_t;

extern pv_init_ops_t pv_init_ops;

extern unsigned long return_to_paravirt_guest(unsigned long ret_value);
extern void  done_to_paravirt_guest(void);
extern void __init kvm_init_paravirt_guest(void);

typedef struct pv_cpu_ops {
	unsigned long (*read_OSCUD_lo_reg_value)(void);
	unsigned long (*read_OSCUD_hi_reg_value)(void);
	void (*write_OSCUD_lo_reg_value)(unsigned long reg_value);
	void (*write_OSCUD_hi_reg_value)(unsigned long reg_value);
	unsigned long long (*read_OSGD_lo_reg_value)(void);
	unsigned long long (*read_OSGD_hi_reg_value)(void);
	void (*write_OSGD_lo_reg_value)(unsigned long reg_value);
	void (*write_OSGD_hi_reg_value)(unsigned long reg_value);
	unsigned long long (*read_CUD_lo_reg_value)(void);
	unsigned long long (*read_CUD_hi_reg_value)(void);
	void (*write_CUD_lo_reg_value)(unsigned long reg_value);
	void (*write_CUD_hi_reg_value)(unsigned long reg_value);
	unsigned long long (*read_GD_lo_reg_value)(void);
	unsigned long long (*read_GD_hi_reg_value)(void);
	void (*write_GD_lo_reg_value)(unsigned long reg_value);
	void (*write_GD_hi_reg_value)(unsigned long reg_value);
	unsigned long long (*read_PSP_lo_reg_value)(void);
	unsigned long long (*read_PSP_hi_reg_value)(void);
	void (*write_PSP_lo_reg_value)(unsigned long reg_value);
	void (*write_PSP_hi_reg_value)(unsigned long reg_value);
	unsigned long long (*read_PSHTP_reg_value)(void);
	void (*write_PSHTP_reg_value)(unsigned long reg_value);
	unsigned long long (*read_PCSP_lo_reg_value)(void);
	unsigned long long (*read_PCSP_hi_reg_value)(void);
	void (*write_PCSP_lo_reg_value)(unsigned long reg_value);
	void (*write_PCSP_hi_reg_value)(unsigned long reg_value);
	int (*read_PCSHTP_reg_value)(void);
	void (*write_PCSHTP_reg_value)(int reg_value);
	unsigned long long (*read_CR0_lo_reg_value)(void);
	unsigned long long (*read_CR0_hi_reg_value)(void);
	unsigned long long (*read_CR1_lo_reg_value)(void);
	unsigned long long (*read_CR1_hi_reg_value)(void);
	void (*write_CR0_lo_reg_value)(unsigned long reg_value);
	void (*write_CR0_hi_reg_value)(unsigned long reg_value);
	void (*write_CR1_lo_reg_value)(unsigned long reg_value);
	void (*write_CR1_hi_reg_value)(unsigned long reg_value);
	unsigned long long (*read_CTPR_reg_value)(int reg_no);
	void (*write_CTPR_reg_value)(int reg_no, unsigned long reg_value);
	unsigned long long (*read_USD_lo_reg_value)(void);
	unsigned long long (*read_USD_hi_reg_value)(void);
	void (*write_USD_lo_reg_value)(unsigned long reg_value);
	void (*write_USD_hi_reg_value)(unsigned long reg_value);
	unsigned long long (*read_SBR_reg_value)(void);
	void (*write_SBR_reg_value)(unsigned long reg_value);
	unsigned long long (*read_WD_reg_value)(void);
	void (*write_WD_reg_value)(unsigned long reg_value);
#ifdef	NEED_PARAVIRT_LOOP_REGISTERS
	unsigned long long (*read_LSR_reg_value)(void);
	void (*write_LSR_reg_value)(unsigned long reg_value);
	unsigned long long (*read_ILCR_reg_value)(void);
	void (*write_ILCR_reg_value)(unsigned long reg_value);
#endif	/* NEED_PARAVIRT_LOOP_REGISTERS */
	unsigned long long (*read_OSR0_reg_value)(void);
	void (*write_OSR0_reg_value)(unsigned long reg_value);
	unsigned int (*read_OSEM_reg_value)(void);
	void (*write_OSEM_reg_value)(unsigned int reg_value);
	unsigned int (*read_BGR_reg_value)(void);
	void (*write_BGR_reg_value)(unsigned int reg_value);
	unsigned long long (*read_CLKR_reg_value)(void);
	void (*write_CLKR_reg_value)(void);
	unsigned long long (*read_SCLKR_reg_value)(void);
	void (*write_SCLKR_reg_value)(unsigned long reg_value);
	unsigned long long (*read_SCLKM1_reg_value)(void);
	void (*write_SCLKM1_reg_value)(unsigned long reg_value);
	unsigned long long (*read_SCLKM2_reg_value)(void);
	unsigned long long (*read_SCLKM3_reg_value)(void);
	void (*write_SCLKM2_reg_value)(unsigned long reg_value);
	unsigned long long (*read_CU_HW0_reg_value)(void);
	void (*write_CU_HW0_reg_value)(unsigned long reg_value);
	unsigned long long (*read_CU_HW1_reg_value)(void);
	void (*write_CU_HW1_reg_value)(unsigned long reg_value);
	unsigned long long (*read_RPR_lo_reg_value)(void);
	unsigned long long (*read_RPR_hi_reg_value)(void);
	void (*write_RPR_lo_reg_value)(unsigned long reg_value);
	void (*write_RPR_hi_reg_value)(unsigned long reg_value);
	unsigned long long (*read_SBBP_reg_value)(void);
	unsigned long long (*read_IP_reg_value)(void);
	unsigned int (*read_DIBCR_reg_value)(void);
	unsigned int (*read_DIBSR_reg_value)(void);
	unsigned long long (*read_DIMCR_reg_value)(void);
	unsigned long long (*read_DIBAR0_reg_value)(void);
	unsigned long long (*read_DIBAR1_reg_value)(void);
	unsigned long long (*read_DIBAR2_reg_value)(void);
	unsigned long long (*read_DIBAR3_reg_value)(void);
	unsigned long long (*read_DIMAR0_reg_value)(void);
	unsigned long long (*read_DIMAR1_reg_value)(void);
	void (*write_DIBCR_reg_value)(unsigned int reg_value);
	void (*write_DIBSR_reg_value)(unsigned int reg_value);
	void (*write_DIMCR_reg_value)(unsigned long reg_value);
	void (*write_DIBAR0_reg_value)(unsigned long reg_value);
	void (*write_DIBAR1_reg_value)(unsigned long reg_value);
	void (*write_DIBAR2_reg_value)(unsigned long reg_value);
	void (*write_DIBAR3_reg_value)(unsigned long reg_value);
	void (*write_DIMAR0_reg_value)(unsigned long reg_value);
	void (*write_DIMAR1_reg_value)(unsigned long reg_value);
	unsigned long long (*read_CUTD_reg_value)(void);
	void (*write_CUTD_reg_value)(unsigned long reg_value);
	unsigned int (*read_CUIR_reg_value)(void);
	unsigned int (*read_PSR_reg_value)(void);
	void (*write_PSR_reg_value)(unsigned int reg_value);
	unsigned int (*read_UPSR_reg_value)(void);
	void (*write_UPSR_reg_value)(unsigned int reg_value);
	void (*write_PSR_irq_barrier)(unsigned int reg_value);
	void (*write_UPSR_irq_barrier)(unsigned int reg_value);
	unsigned int (*read_PFPFR_reg_value)(void);
	void (*write_PFPFR_reg_value)(unsigned int reg_value);
	unsigned int (*read_FPCR_reg_value)(void);
	void (*write_FPCR_reg_value)(unsigned int reg_value);
	unsigned int (*read_FPSR_reg_value)(void);
	void (*write_FPSR_reg_value)(unsigned int reg_value);
	unsigned long long (*read_CS_lo_reg_value)(void);
	unsigned long long (*read_CS_hi_reg_value)(void);
	unsigned long long (*read_DS_lo_reg_value)(void);
	unsigned long long (*read_DS_hi_reg_value)(void);
	unsigned long long (*read_ES_lo_reg_value)(void);
	unsigned long long (*read_ES_hi_reg_value)(void);
	unsigned long long (*read_FS_lo_reg_value)(void);
	unsigned long long (*read_FS_hi_reg_value)(void);
	unsigned long long (*read_GS_lo_reg_value)(void);
	unsigned long long (*read_GS_hi_reg_value)(void);
	unsigned long long (*read_SS_lo_reg_value)(void);
	unsigned long long (*read_SS_hi_reg_value)(void);
	void (*write_CS_lo_reg_value)(unsigned long reg_value);
	void (*write_CS_hi_reg_value)(unsigned long reg_value);
	void (*write_DS_lo_reg_value)(unsigned long reg_value);
	void (*write_DS_hi_reg_value)(unsigned long reg_value);
	void (*write_ES_lo_reg_value)(unsigned long reg_value);
	void (*write_ES_hi_reg_value)(unsigned long reg_value);
	void (*write_FS_lo_reg_value)(unsigned long reg_value);
	void (*write_FS_hi_reg_value)(unsigned long reg_value);
	void (*write_GS_lo_reg_value)(unsigned long reg_value);
	void (*write_GS_hi_reg_value)(unsigned long reg_value);
	void (*write_SS_lo_reg_value)(unsigned long reg_value);
	void (*write_SS_hi_reg_value)(unsigned long reg_value);
	unsigned long long (*read_IDR_reg_value)(void);
	unsigned long long (*boot_read_IDR_reg_value)(void);
	unsigned int (*read_CORE_MODE_reg_value)(void);
	unsigned int (*boot_read_CORE_MODE_reg_value)(void);
	void (*write_CORE_MODE_reg_value)(unsigned int modes);
	void (*boot_write_CORE_MODE_reg_value)(unsigned int modes);

	void (*put_updated_cpu_regs_flags)(unsigned long flags);

	unsigned int (*read_aasr_reg_value)(void);
	void (*write_aasr_reg_value)(unsigned int reg_value);
	unsigned int (*read_aafstr_reg_value)(void);
	void (*write_aafstr_reg_value)(unsigned int reg_value);

	void (*flush_stacks)(void);
	void (*flush_regs_stack)(void);
	void (*flush_chain_stack)(void);
	void (*copy_stacks_to_memory)(void);
	unsigned long long (*get_active_cr0_lo_value)(e2k_addr_t base,
							e2k_addr_t cr_ind);
	unsigned long long (*get_active_cr0_hi_value)(e2k_addr_t base,
							e2k_addr_t cr_ind);
	unsigned long long (*get_active_cr1_lo_value)(e2k_addr_t base,
							e2k_addr_t cr_ind);
	unsigned long long (*get_active_cr1_hi_value)(e2k_addr_t base,
							e2k_addr_t cr_ind);
	void (*put_active_cr0_lo_value)(unsigned long cr0_lo_value,
					e2k_addr_t base, e2k_addr_t cr_ind);
	void (*put_active_cr0_hi_value)(unsigned long cr0_hi_value,
					e2k_addr_t base, e2k_addr_t cr_ind);
	void (*put_active_cr1_lo_value)(unsigned long cr1_lo_value,
					e2k_addr_t base, e2k_addr_t cr_ind);
	void (*put_active_cr1_hi_value)(unsigned long cr1_hi_value,
					e2k_addr_t base, e2k_addr_t cr_ind);
	void (*correct_trap_psp_pcsp)(struct pt_regs *regs,
					struct thread_info *thread_info);
	void (*correct_scall_psp_pcsp)(struct pt_regs *regs,
					struct thread_info *thread_info);
	void (*correct_trap_return_ip)(struct pt_regs *regs,
					unsigned long return_ip);
	void *(*nested_kernel_return_address)(int n);
	void (*virt_cpu_thread_init)(struct task_struct *boot_task);
	int (*prepare_start_thread_frames)(unsigned long entry,
						unsigned long sp);
	int (*copy_kernel_stacks)(struct task_struct *new_task,
					unsigned long fn, unsigned long arg);
	int (*copy_user_stacks)(unsigned long clone_flags,
				e2k_addr_t new_stk_base, e2k_size_t new_stk_sz,
				struct task_struct *new_task,
				struct pt_regs *regs);
	void (*define_kernel_hw_stacks_sizes)(struct hw_stack *hw_stacks);
	void (*define_user_hw_stacks_sizes)(struct hw_stack *hw_stacks);
	void (*switch_to_expanded_proc_stack)(long delta_size,
				long delta_offset, bool decr_k_ps);
	void (*switch_to_expanded_chain_stack)(long delta_size,
				long delta_offset, bool decr_k_pcs);
	void (*stack_bounds_trap_enable)(void);
	bool (*is_proc_stack_bounds)(struct thread_info *ti,
					struct pt_regs *regs);
	bool (*is_chain_stack_bounds)(struct thread_info *ti,
					struct pt_regs *regs);

	void (*release_hw_stacks)(struct thread_info *dead_ti);
	void (*release_kernel_stacks)(struct thread_info *dead_ti);
	int (*register_kernel_hw_stack)(e2k_addr_t stack_base,
						e2k_size_t stack_size);
	int (*register_kernel_data_stack)(e2k_addr_t stack_base,
						e2k_size_t stack_size);
	void (*unregister_kernel_hw_stack)(e2k_addr_t stack_base,
						e2k_size_t stack_size);
	void (*unregister_kernel_data_stack)(e2k_addr_t stack_base,
						e2k_size_t stack_size);
	int (*kmem_area_host_chunk)(e2k_addr_t stack_base,
					e2k_size_t stack_size, int hw_stack);
	void (*kmem_area_unhost_chunk)(e2k_addr_t stack_base,
						e2k_size_t stack_size);
	int (*switch_to_new_user)(struct e2k_stacks *stacks,
			struct hw_stack *hw_stacks,
			e2k_addr_t cut_base, e2k_size_t cut_size,
			e2k_addr_t entry_point, int cui,
			unsigned long flags, bool kernel);
	int (*do_map_user_hard_stack_to_kernel)(int nid,
			e2k_addr_t kernel_start, e2k_addr_t user_stack_base,
			e2k_size_t kernel_size);
	int (*do_switch_to_kernel_hardware_stacks)(void);
	void (*free_old_kernel_hardware_stacks)(void);
	void (*instr_page_fault)(struct pt_regs *regs, tc_fault_type_t ftype,
			const int async_instr);
	unsigned long (*mmio_page_fault)(struct pt_regs *regs,
			struct trap_cellar *tcellar);
	int (*do_hw_stack_bounds)(struct pt_regs *regs,
			bool proc_bounds, bool chain_bounds);
	irqreturn_t (*handle_interrupt)(struct pt_regs *regs);
	void (*init_guest_system_handlers_table)(void);
	void (*fix_process_pt_regs)(struct thread_info *ti,
			struct e2k_stacks *stacks, struct pt_regs *regs,
			struct pt_regs *old_regs);
	int (*run_user_handler)(struct as_sa_handler_arg *arg);
	long (*trap_table_entry1)(int sys_num, ...);
	long (*trap_table_entry3)(int sys_num, ...);
	long (*trap_table_entry4)(int sys_num, ...);

	int (*do_fast_clock_gettime)(const clockid_t which_clock,
					struct timespec *tp);
	int (*fast_sys_clock_gettime)(const clockid_t which_clock,
					struct timespec __user *tp);
	int (*do_fast_gettimeofday)(struct timeval *tv);
	int (*fast_sys_siggetmask)(u64 __user *oset, size_t sigsetsize);

	unsigned long (*fast_tagged_memory_copy)(void *dst, const void *src,
			size_t len, unsigned long strd_opcode,
			unsigned long ldrd_opcode, int prefetch);
	unsigned long (*fast_tagged_memory_set)(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode);
	unsigned long (*extract_tags_32)(u16 *dst, const void *src);
	void (*save_local_glob_regs)(struct local_gregs *l_gregs,
					bool is_signal);
	void (*restore_local_glob_regs)(struct local_gregs *l_gregs,
					bool is_signal);
	void (*restore_kernel_gregs_in_syscall)(struct thread_info *ti);
	void (*get_all_user_glob_regs)(struct global_regs *gregs);
	void (*arch_setup_machine)(void);
	void (*cpu_default_idle)(void);
	void (*cpu_relax)(void);
	void (*cpu_relax_no_resched)(void);
#ifdef	CONFIG_SMP
	void (*wait_for_cpu_booting)(void);
	void (*wait_for_cpu_wake_up)(void);
	int (*activate_cpu)(int cpu_id);
	int (*activate_all_cpus)(void);
	void (*csd_lock_wait)(struct __call_single_data *data);
	void (*csd_lock)(struct __call_single_data *data);
	void (*arch_csd_lock_async)(struct __call_single_data *data);
	void (*csd_unlock)(struct __call_single_data *data);
	void (*setup_local_pic_virq)(unsigned int cpuid);
	void (*startup_local_pic_virq)(unsigned int cpuid);
	void (*smp_flush_tlb_all)(void);
	void (*smp_flush_tlb_mm)(struct mm_struct *mm);
	void (*smp_flush_tlb_page)(struct vm_area_struct *vma,
			e2k_addr_t addr);
	void (*smp_flush_tlb_range)(struct mm_struct *mm,
			e2k_addr_t start, e2k_addr_t end);
	void (*smp_flush_pmd_tlb_range)(struct mm_struct *mm,
			e2k_addr_t start, e2k_addr_t end);
	void (*smp_flush_tlb_range_and_pgtables)(struct mm_struct *mm,
			e2k_addr_t start, e2k_addr_t end);
	void (*smp_flush_icache_range)(e2k_addr_t start, e2k_addr_t end);
	void (*smp_flush_icache_range_array)(
			void *icache_range_arr);
	void (*smp_flush_icache_page)(struct vm_area_struct *vma,
			struct page *page);
	void (*smp_flush_icache_all)(void);
	void (*smp_flush_icache_kernel_line)(e2k_addr_t addr);
#endif	/* CONFIG_SMP */
	int  (*host_printk)(const char *fmt, ...);

	void (*arch_spin_lock_slow)(void *lock);
	void (*arch_spin_locked_slow)(void *lock);
	void (*arch_spin_unlock_slow)(void *lock);

	void (*ord_wait_read_lock_slow)(arch_rwlock_t *rw);
	void (*ord_wait_write_lock_slow)(arch_rwlock_t *rw);
	void (*ord_arch_read_locked_slow)(arch_rwlock_t *rw);
	void (*ord_arch_write_locked_slow)(arch_rwlock_t *rw);
	void (*ord_arch_read_unlock_slow)(arch_rwlock_t *rw);
	void (*ord_arch_write_unlock_slow)(arch_rwlock_t *rw);
} pv_cpu_ops_t;

extern pv_cpu_ops_t pv_cpu_ops;
extern pv_cpu_ops_t *cur_pv_cpu_ops;

/* FIXME: this include should be deleted, paravirt_enable() should migrate */
/* from processor.h to some other common include */
#include <asm/paravirt/processor.h>

#define	PATCH_GOTO_AND_RETURN_CTPR_NO	1	/* ctpr1 */

#define	GOTO_FUNC_PATCH(patch_addr, return_addr_greg_no,		\
					ctpr_no, PRE, POST)		\
		E2K_GOTO_PATCH_AND_RETURN(patch_addr, return_addr_greg_no, \
						ctpr_no, PRE, POST)
#define	GOTO_CPU_FUNC_PATCH(patch_addr, return_addr_greg_no,		\
					ctpr_no, PRE, POST)		\
		GOTO_FUNC_PATCH(pv_cpu_ops.patch_addr, return_addr_greg_no, \
						ctpr_no, PRE, POST)
#define	DEF_GOTO_CPU_FUNC_PATCH(patch_addr)				\
		GOTO_CPU_FUNC_PATCH(patch_addr,				\
					PATCH_RETURN_ADDR_GREG,		\
					PATCH_GOTO_AND_RETURN_CTPR_NO,	\
					"", "")

#define	GOTO_READ_SREG_PATCH(patch_addr, return_addr_greg_no,		\
					ctpr_no, POST)			\
		E2K_GOTO_PATCH_AND_RETURN(patch_addr, return_addr_greg_no, \
						ctpr_no, "", POST)
#define	GOTO_WRITE_SREG_PATCH(patch_addr, return_addr_greg_no,		\
					ctpr_no, PRE)			\
		E2K_GOTO_PATCH_AND_RETURN(patch_addr, return_addr_greg_no, \
						ctpr_no, PRE, "")
#define	GOTO_SET_UPDATED_FLAGS_PATCH(patch_addr, return_addr_greg_no,	\
					ctpr_no, PRE)			\
		E2K_GOTO_PATCH_AND_RETURN(patch_addr, return_addr_greg_no, \
						ctpr_no, PRE, "")
#define	READ_SREG_PATCH_POST(reg_value_greg_no, res)			\
		E2K_MOVE_GREG_TO_REG(reg_value_greg_no, res)
#define	READ_DSREG_PATCH_POST(reg_value_greg_no, res)			\
		E2K_MOVE_DGREG_TO_DREG(reg_value_greg_no, res)
#define	DEF_READ_SREG_PATCH_POST(res)					\
		READ_SREG_PATCH_POST(PATCH_RES_GREG, res)
#define	DEF_READ_DSREG_PATCH_POST(res)					\
		READ_DSREG_PATCH_POST(PATCH_RES_GREG, res)

#define	PV_WRITE_SREG_PATCH_PRE(reg_value_greg_no, reg_value)		\
		E2K_MOVE_REG_TO_GREG(reg_value_greg_no, reg_value)
#define	PV_WRITE_DSREG_PATCH_PRE(reg_value_greg_no, reg_value)		\
		E2K_MOVE_DREG_TO_DGREG(reg_value_greg_no, reg_value)
#define	DEF_WRITE_SREG_PATCH_PRE(reg_value)				\
		PV_WRITE_SREG_PATCH_PRE(PATCH_ARG_GREG, reg_value)
#define	DEF_WRITE_DSREG_PATCH_PRE(reg_value)				\
		PV_WRITE_DSREG_PATCH_PRE(PATCH_ARG_GREG, reg_value)

#define	BOOT_PARAVIRT_GET_CPU_FUNC(func_name)				\
		BOOT_PARAVIRT_GET_BOOT_OPS_FUNC(cur_pv_cpu_ops, func_name)
#define	BOOT_PARAVIRT_READ_REG(reg_func)				\
		(BOOT_PARAVIRT_GET_CPU_FUNC(reg_func)())
#define	BOOT_PARAVIRT_WRITE_REG(reg_func, reg_value)			\
		(BOOT_PARAVIRT_GET_CPU_FUNC(reg_func)(reg_value))
#define	BOOT_GET_CPU_PATCH_LABEL(patch_addr)				\
		BOOT_PARAVIRT_GET_BOOT_OPS_FUNC(cur_pv_cpu_ops, patch_addr)

#define	BOOT_PARAVIRT_FLUSH(reg_func)					\
		(BOOT_PARAVIRT_GET_CPU_FUNC(reg_func)())

typedef struct pv_apic_ops {
	void (*apic_write)(unsigned int reg, unsigned int v);
	unsigned int (*apic_read) (unsigned int reg);
	void (*boot_apic_write)(unsigned int reg, unsigned int v);
	unsigned int (*boot_apic_read) (unsigned int reg);
} pv_apic_ops_t;

extern pv_apic_ops_t pv_apic_ops;
extern pv_apic_ops_t *cur_pv_apic_ops;

#define	BOOT_PARAVIRT_GET_APIC_FUNC(func_name)				\
		BOOT_PARAVIRT_GET_BOOT_OPS_FUNC(cur_pv_apic_ops, func_name)
#define	BOOT_PARAVIRT_APIC_READ(reg)					\
		(BOOT_PARAVIRT_GET_APIC_FUNC(boot_apic_read)(reg))
#define	BOOT_PARAVIRT_APIC_WRITE(reg, reg_value)			\
		(BOOT_PARAVIRT_GET_APIC_FUNC(boot_apic_write)(reg, reg_value))

typedef struct pv_epic_ops {
	void (*epic_write_w)(unsigned int reg, unsigned int v);
	unsigned int (*epic_read_w)(unsigned int reg);
	void (*epic_write_d)(unsigned int reg, unsigned long v);
	unsigned long (*epic_read_d)(unsigned int reg);
	void (*boot_epic_write_w)(unsigned int reg, unsigned int v);
	unsigned int (*boot_epic_read_w)(unsigned int reg);
} pv_epic_ops_t;

extern pv_epic_ops_t pv_epic_ops;
extern pv_epic_ops_t *cur_pv_epic_ops;

#define	BOOT_PARAVIRT_GET_EPIC_FUNC(func_name)				\
		BOOT_PARAVIRT_GET_BOOT_OPS_FUNC(cur_pv_epic_ops, func_name)
#define	BOOT_PARAVIRT_EPIC_READ_W(reg)					\
		(BOOT_PARAVIRT_GET_EPIC_FUNC(boot_epic_read_w)(reg))
#define	BOOT_PARAVIRT_EPIC_WRITE_W(reg, reg_value)			\
		(BOOT_PARAVIRT_GET_EPIC_FUNC(boot_epic_write_w)(reg, reg_value))

typedef struct pv_mmu_ops {
	long (*recovery_faulted_tagged_store)(e2k_addr_t address, u64 wr_data,
					u32 data_tag, u64 st_rec_opc, int chan);
	long (*recovery_faulted_load)(e2k_addr_t address, u64 *ld_val,
				u8 *data_tag, u64 ld_rec_opc, int chan);
	long (*recovery_faulted_move)(e2k_addr_t addr_from, e2k_addr_t addr_to,
				int format, int vr, u64 ld_rec_opc, int chan);
	long (*recovery_faulted_load_to_greg)(e2k_addr_t address,
				u32 greg_num_d, int format, int vr,
				u64 ld_rec_opc, int chan, void *saved_greg);
	void (*move_tagged_word)(e2k_addr_t addr_from, e2k_addr_t addr_to);
	void (*move_tagged_dword)(e2k_addr_t addr_from, e2k_addr_t addr_to);
	void (*move_tagged_qword)(e2k_addr_t addr_from, e2k_addr_t addr_to);
	void (*write_mmu_reg)(mmu_addr_t mmu_addr, mmu_reg_t mmu_reg);
	mmu_reg_t (*read_mmu_reg)(mmu_addr_t mmu_addr);
	void (*write_dtlb_reg)(tlb_addr_t tlb_addr, mmu_reg_t mmu_reg);
	mmu_reg_t (*read_dtlb_reg)(tlb_addr_t tlb_addr);
	void (*flush_tlb_entry)(flush_op_t flush_op, flush_addr_t flush_addr);
	void (*flush_dcache_line)(e2k_addr_t virt_addr);
	void (*clear_dcache_l1_set)(e2k_addr_t virt_addr, unsigned long set);
	void (*flush_dcache_range)(void *addr, size_t len);
	void (*clear_dcache_l1_range)(void *virt_addr, size_t len);
	void (*flush_icache_line)(flush_op_t flush_op, flush_addr_t flush_addr);
	void (*write_dcache_l2_reg)(unsigned long reg_val,
					int reg_num, int bank_num);
	unsigned long (*read_dcache_l2_reg)(int reg_num, int bank_num);
	void (*flush_cache_all)(flush_op_t flush_op);
	void (*do_flush_tlb_all)(flush_op_t flush_op);
	void (*flush_icache_all)(flush_op_t flush_op);
	probe_entry_t (*entry_probe_mmu_op)(e2k_addr_t virt_addr);
	probe_entry_t (*address_probe_mmu_op)(e2k_addr_t virt_addr);
	clw_reg_t (*read_clw_reg)(clw_addr_t clw_addr);
	void (*write_clw_reg)(clw_addr_t clw_addr, clw_reg_t val);
	void (*save_DAM)(unsigned long long *dam);
	void (*write_mmu_debug_reg)(int reg_no, mmu_reg_t mmu_reg);
	mmu_reg_t (*read_mmu_debug_reg)(int reg_no);
	void (*boot_set_pte_at)(unsigned long addr,
				pte_t *ptep, pte_t pteval);
	void (*write_pte_at)(struct mm_struct *mm, unsigned long addr,
				pte_t *ptep, pte_t pteval,
				bool only_validate, bool to_move);
	void (*set_pte)(pte_t *ptep, pte_t pteval);
	void (*write_pmd_at)(struct mm_struct *mm, unsigned long addr,
				pmd_t *pmdp, pmd_t pmdval, bool only_validate);
	void (*write_pud_at)(struct mm_struct *mm, unsigned long addr,
				pud_t *pudp, pud_t pudval, bool only_validate);
	void (*write_pgd_at)(struct mm_struct *mm, unsigned long addr,
				pgd_t *pgdp, pgd_t pgdval, bool only_validate);
	pte_t (*ptep_get_and_clear)(struct mm_struct *mm, unsigned long addr,
				pte_t *ptep, bool to_move);
	pte_t (*ptep_get_and_clear_as_valid)(struct mm_struct *mm,
				unsigned long addr, pte_t *ptep);
	void (*ptep_wrprotect_atomic)(struct mm_struct *mm,
				e2k_addr_t addr, pte_t *ptep);
	pte_t (*get_pte_for_address)(struct vm_area_struct *vma,
				e2k_addr_t address);
	int (*remap_area_pages)(unsigned long address, unsigned long phys_addr,
				unsigned long size,
				enum pte_mem_type memory_type);
	int (*host_guest_vmap_area)(e2k_addr_t start, e2k_addr_t end);
	int (*unhost_guest_vmap_area)(e2k_addr_t start, e2k_addr_t end);

	/* memory management - mman.h */
	void (*free_mm)(struct mm_struct *);
	struct mm_struct *(*mm_init)(struct mm_struct *mm,
						struct task_struct *p,
						struct user_namespace *user_ns);
	void (*activate_mm)(struct mm_struct *active_mm, struct mm_struct *mm);
	int (*make_host_pages_valid)(struct vm_area_struct *vma,
			e2k_addr_t start_addr, e2k_addr_t end_addr,
			bool chprot, bool flush);
	int (*set_memory_attr_on_host)(e2k_addr_t start, e2k_addr_t end,
					int mode);
	int (*access_process_vm)(struct task_struct *task,
			unsigned long addr, void *buf, int len,
			unsigned int gup_flags);

	/* memory management - mm.h */
	void (*free_pgd_range)(struct mmu_gather *tlb, unsigned long addr,
		unsigned long end, unsigned long floor, unsigned long ceiling);

	/* kernel virtual memory allocation */
	struct vmap_area *(*alloc_vmap_area)(unsigned long size,
				unsigned long align,
				unsigned long vstart, unsigned long vend,
				int node, gfp_t gfp_mask);
	void (*__free_vmap_area)(struct vmap_area *va);
#ifdef	CONFIG_SMP
	struct vm_struct **(*pcpu_get_vm_areas)(const unsigned long *offsets,
				const size_t *sizes, int nr_vms,
				size_t align);
#endif	/* CONFIG_SMP */
	void (*free_unmap_vmap_area)(struct vmap_area *va);

	/* unmap __init areas */
	void (*unmap_initmem)(void *start, void *end);

} pv_mmu_ops_t;

extern pv_mmu_ops_t pv_mmu_ops;
extern pv_mmu_ops_t *cur_pv_mmu_ops;

#define	BOOT_PARAVIRT_GET_MMU_FUNC(func_name)				\
		BOOT_PARAVIRT_GET_BOOT_OPS_FUNC(cur_pv_mmu_ops, func_name)
#define	BOOT_PARAVIRT_READ_MMU_REG(mmu_addr)				\
		BOOT_PARAVIRT_GET_MMU_FUNC(read_mmu_reg)(mmu_addr)
#define	BOOT_PARAVIRT_WRITE_MMU_REG(mmu_addr, mmu_reg)			\
		BOOT_PARAVIRT_GET_MMU_FUNC(write_mmu_reg)(mmu_addr, mmu_reg)

typedef struct pv_irq_ops {
} pv_irq_ops_t;

extern pv_irq_ops_t pv_irq_ops;

typedef struct pv_time_ops {
	void		(*time_init)(void);
	void		(*clock_init)(void);
	int		(*read_current_timer)(unsigned long *timer_val);
	unsigned long	(*get_cpu_running_cycles)(void);
	unsigned long long (*do_sched_clock)(void);
	unsigned long	(*steal_clock)(int cpu);
} pv_time_ops_t;

extern pv_time_ops_t pv_time_ops;

typedef struct pv_io_ops {
	void	(*boot_writeb)(u8 b, void __iomem *addr);
	void	(*boot_writew)(u16 w, void __iomem *addr);
	void	(*boot_writel)(u32 l, void __iomem *addr);
	void	(*boot_writell)(u64 q, void __iomem *addr);
	u8	(*boot_readb)(void __iomem *addr);
	u16	(*boot_readw)(void __iomem *addr);
	u32	(*boot_readl)(void __iomem *addr);
	u64	(*boot_readll)(void __iomem *addr);
	void	(*writeb)(u8 b, void __iomem *addr);
	void	(*writew)(u16 w, void __iomem *addr);
	void	(*writel)(u32 l, void __iomem *addr);
	void	(*writell)(u64 q, void __iomem *addr);
	u8	(*readb)(void __iomem *addr);
	u16	(*readw)(void __iomem *addr);
	u32	(*readl)(void __iomem *addr);
	u64	(*readll)(void __iomem *addr);
	u8	(*inb)(unsigned short port);
	void	(*outb)(unsigned char byte, unsigned short port);
	void	(*outw)(u16 halfword, unsigned short port);
	u16	(*inw)(unsigned short port);
	void	(*outl)(u32 word, unsigned short port);
	u32	(*inl)(unsigned short port);
	void	(*outsb)(unsigned short port, const void *src, unsigned long count);
	void	(*outsw)(unsigned short port, const void *src, unsigned long count);
	void	(*outsl)(unsigned short port, const void *src, unsigned long count);
	void	(*insb)(unsigned short port, void *dst, unsigned long count);
	void	(*insw)(unsigned short port, void *dst, unsigned long count);
	void	(*insl)(unsigned short port, void *dst, unsigned long count);
	void	(*conf_inb)(unsigned int domain, unsigned int bus,
				unsigned long port, u8 *byte);
	void	(*conf_inw)(unsigned int domain, unsigned int bus,
				unsigned long port, u16 *hword);
	void	(*conf_inl)(unsigned int domain, unsigned int bus,
				unsigned long port, u32 *word);
	void	(*conf_outb)(unsigned int domain, unsigned int bus,
				unsigned long port, u8 byte);
	void	(*conf_outw)(unsigned int domain, unsigned int bus,
				unsigned long port, u16 hword);
	void	(*conf_outl)(unsigned int domain, unsigned int bus,
				unsigned long port, u32 word);

	void	(*scr_writew)(u16 val, volatile u16 *addr);
	u16	(*scr_readw)(volatile const u16 *addr);
	void	(*vga_writeb)(u8 val, volatile u8 *addr);
	u8	(*vga_readb)(volatile const u8 *addr);

	int	(*pci_init)(void);
} pv_io_ops_t;

extern pv_io_ops_t pv_io_ops;
extern pv_io_ops_t *cur_pv_io_ops;

#define	BOOT_PARAVIRT_GET_IO_OPS_FUNC(func_name)			\
		BOOT_PARAVIRT_GET_BOOT_OPS_FUNC(cur_pv_io_ops, func_name)
#define	BOOT_PARAVIRT_IO_READ(io_func, io_addr)				\
		(BOOT_PARAVIRT_GET_IO_OPS_FUNC(io_func)(io_addr))
#define	BOOT_PARAVIRT_IO_WRITE(io_func, io_value, io_addr)		\
		(BOOT_PARAVIRT_GET_IO_OPS_FUNC(io_func)(io_value, io_addr))

#endif /* ! __ASSEMBLY__ */
#endif	/* CONFIG_PARAVIRT */

#endif /* __ASM_E2K_PARAVIRT_PV_OPS_H */
