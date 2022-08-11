/*  Paravirtualization interfaces
    Copyright (C) 2006 Rusty Russell IBM Corporation

    This program is free software; you can redistribute it and/or modify
    it under the terms of the GNU General Public License as published by
    the Free Software Foundation; either version 2 of the License, or
    (at your option) any later version.

    This program is distributed in the hope that it will be useful,
    but WITHOUT ANY WARRANTY; without even the implied warranty of
    MERCHANTABILITY or FITNESS FOR A PARTICULAR PURPOSE.  See the
    GNU General Public License for more details.

    You should have received a copy of the GNU General Public License
    along with this program; if not, write to the Free Software
    Foundation, Inc., 51 Franklin St, Fifth Floor, Boston, MA  02110-1301  USA

    2007 - x86_64 support added by Glauber de Oliveira Costa, Red Hat Inc
*/

#include <linux/errno.h>
#include <linux/export.h>

#include <asm/e2k_api.h>
#include <asm/p2v/boot_init.h>
#include <asm/cpu_regs.h>
#include <asm/pgtable.h>
#include <asm/system.h>
#include <asm/io.h>
#include <asm/regs_state.h>
#include <asm/e2k_sic.h>
#include <asm/p2v/boot_param.h>
#include <asm/time.h>
#include <asm/process.h>
#include <asm/cpu.h>
#include <asm/trap_table.h>
#include <asm/fast_syscalls.h>
#include <asm/mmu_context.h>
#include <asm/mman.h>
#include <asm/mmu_fault.h>
#include <asm/clkr.h>
#include <asm/vga.h>

#include <asm/paravirt/pv_ops.h>
#include <asm/kvm/guest/signal.h>

pv_info_t pv_info = {
	.name = "e2k bare hardware",
	.paravirt_enabled = 0,
	.page_offset = NATIVE_PAGE_OFFSET,
	.vmalloc_start = NATIVE_VMALLOC_START,
	.vmalloc_end = NATIVE_VMALLOC_END,
	.vmemmap_start = NATIVE_VMEMMAP_START,
	.vmemmap_end = NATIVE_VMEMMAP_END,
};
EXPORT_SYMBOL_GPL(pv_info);

#define	BOOT_PARAVIRT_GET_BOOT_MACHINE_FUNC(func_name)			\
({									\
	machdep_t machdep = boot_machine;				\
	typeof(machdep.func_name) func;					\
	func = machdep.func_name;					\
	boot_native_vp_to_pp(func);					\
})
#define	BOOT_PARAVIRT_CALL_MACHINE_FUNC(func_name)			\
		(BOOT_PARAVIRT_GET_BOOT_MACHINE_FUNC(func_name)())

static void *
BOOT_NATIVE_KERNEL_VA_TO_PA(void *virt_pnt, unsigned long kernel_base)
{
	return boot_native_kernel_va_to_pa(virt_pnt, kernel_base);
}

static void *
BOOT_NATIVE_FUNC_TO_PA(void *virt_pnt)
{
	return boot_native_func_to_pa(virt_pnt);
}

static e2k_addr_t
BOOT_NATIVE_VPA_TO_PA(e2k_addr_t vpa)
{
	return boot_native_vpa_to_pa(vpa);
}
static e2k_addr_t
BOOT_NATIVE_PA_TO_VPA(e2k_addr_t pa)
{
	return boot_native_pa_to_vpa(pa);
}

static e2k_addr_t
NATIVE_VPA_TO_PA(e2k_addr_t vpa)
{
	return native_vpa_to_pa(vpa);
}
static e2k_addr_t
NATIVE_PA_TO_VPA(e2k_addr_t pa)
{
	return native_pa_to_vpa(pa);
}

#define PV_V2P_OPS {							\
	.boot_kernel_va_to_pa = BOOT_NATIVE_KERNEL_VA_TO_PA,		\
	.boot_func_to_pa = BOOT_NATIVE_FUNC_TO_PA,			\
	.boot_vpa_to_pa = BOOT_NATIVE_VPA_TO_PA,			\
	.boot_pa_to_vpa = BOOT_NATIVE_PA_TO_VPA,			\
	.vpa_to_pa = NATIVE_VPA_TO_PA,					\
	.pa_to_vpa = NATIVE_PA_TO_VPA,					\
}
pv_v2p_ops_t pv_v2p_ops = PV_V2P_OPS;
/* boot-time copy of pv_v2p_ops: functions have physical addresses */
static pv_v2p_ops_t boot_pv_v2p_ops = PV_V2P_OPS;
pv_v2p_ops_t *cur_pv_v2p_ops = &boot_pv_v2p_ops;

static void native_boot_debug_cons_outb(u8 byte, u16 port)
{
	boot_native_outb(byte, port);
}

static u8 native_boot_debug_cons_inb(u16 port)
{
	return boot_native_inb(port);
}

static u32 native_boot_debug_cons_inl(u16 port)
{
	return boot_native_inl(port);
}

static void NATIVE_DEBUG_CONS_OUTB(u8 byte, u16 port)
{
	native_debug_cons_outb(byte, port);
}
static u8 NATIVE_DEBUG_CONS_INB(u16 port)
{
	return native_debug_cons_inb(port);
}
static u32 NATIVE_DEBUG_CONS_INL(u16 port)
{
	return native_debug_cons_inl(port);
}

static void  boot_do_native_cpu_relax(void)
{
	boot_native_cpu_relax();
}

#define	PV_BOOT_COMMON_OPS						\
	.boot_setup_machine_id = boot_native_setup_machine_id,		\
	.boot_loader_probe_memory = boot_native_loader_probe_memory,	\
	.boot_get_bootblock_size = boot_native_get_bootblock_size,	\
	.boot_reserve_all_bootmem = boot_native_reserve_all_bootmem,	\
	.boot_map_all_bootmem = boot_native_map_all_bootmem,		\
	.boot_map_needful_to_equal_virt_area =				\
		boot_native_map_needful_to_equal_virt_area,		\
	.boot_kernel_switch_to_virt = boot_native_switch_to_virt,	\
	.boot_clear_bss = boot_native_clear_bss,			\
	.boot_check_bootblock = boot_native_check_bootblock,		\
	.init_terminate_boot_init = init_native_terminate_boot_init,	\
	.boot_parse_param = boot_native_parse_param,			\
	.boot_debug_cons_outb = native_boot_debug_cons_outb,		\
	.boot_debug_cons_inb = native_boot_debug_cons_inb,		\
	.boot_debug_cons_inl = native_boot_debug_cons_inl,		\
	.debug_cons_outb = NATIVE_DEBUG_CONS_OUTB,			\
	.debug_cons_inb = NATIVE_DEBUG_CONS_INB,			\
	.debug_cons_inl = NATIVE_DEBUG_CONS_INL,			\
	.do_boot_panic = do_boot_printk,				\
	.boot_cpu_relax = boot_do_native_cpu_relax,			\

#ifdef	CONFIG_SMP
#define	PV_BOOT_SMP_OPS							\
	.boot_smp_cpu_config = boot_native_smp_cpu_config,		\
	.boot_smp_node_config = boot_native_smp_node_config,		\

#else	/* ! CONFIG_SMP */
#define	PV_BOOT_SMP_OPS
#endif	/* CONFIG_SMP */
#define	PV_BOOT_OPS {							\
		PV_BOOT_COMMON_OPS					\
		PV_BOOT_SMP_OPS						\
}

pv_boot_ops_t pv_boot_ops = PV_BOOT_OPS;
pv_boot_ops_t __initdata boot_pv_boot_ops = PV_BOOT_OPS;
pv_boot_ops_t *cur_pv_boot_ops = &boot_pv_boot_ops;

void __init default_banner(void)
{
	printk(KERN_INFO "Booting paravirtualized kernel on %s\n",
	       pv_info.name);
}

pv_init_ops_t pv_init_ops = {
	.banner = default_banner,
	.set_mach_type_id = native_set_mach_type_id,
	.print_machine_type_info = native_print_machine_type_info,
};

static unsigned long native_read_OSCUD_lo_reg_value(void)
{
	return NATIVE_READ_OSCUD_LO_REG_VALUE();
}

static unsigned long native_read_OSCUD_hi_reg_value(void)
{
	return NATIVE_READ_OSCUD_HI_REG_VALUE();
}

static void native_write_OSCUD_lo_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_OSCUD_LO_REG_VALUE(reg_value);
}

static void native_write_OSCUD_hi_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_OSCUD_HI_REG_VALUE(reg_value);
}

static unsigned long native_read_OSGD_lo_reg_value(void)
{
	return NATIVE_READ_OSGD_LO_REG_VALUE();
}

static unsigned long native_read_OSGD_hi_reg_value(void)
{
	return NATIVE_READ_OSGD_HI_REG_VALUE();
}

static void native_write_OSGD_lo_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_OSGD_LO_REG_VALUE(reg_value);
}

static void native_write_OSGD_hi_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_OSGD_HI_REG_VALUE(reg_value);
}

static unsigned long native_read_CUD_lo_reg_value(void)
{
	return NATIVE_READ_CUD_LO_REG_VALUE();
}

static unsigned long native_read_CUD_hi_reg_value(void)
{
	return NATIVE_READ_CUD_HI_REG_VALUE();
}

static void native_write_CUD_lo_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_CUD_LO_REG_VALUE(reg_value);
}

static void native_write_CUD_hi_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_CUD_HI_REG_VALUE(reg_value);
}

static unsigned long native_read_GD_lo_reg_value(void)
{
	return NATIVE_READ_GD_LO_REG_VALUE();
}

static unsigned long native_read_GD_hi_reg_value(void)
{
	return NATIVE_READ_GD_HI_REG_VALUE();
}

static void native_write_GD_lo_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_GD_LO_REG_VALUE(reg_value);
}

static void native_write_GD_hi_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_GD_HI_REG_VALUE(reg_value);
}

static unsigned long native_read_CTPR_reg_value(int reg_no)
{
	switch (reg_no) {
	case 1: return NATIVE_NV_READ_CTPR_REG_VALUE(1);
	case 2: return NATIVE_NV_READ_CTPR_REG_VALUE(2);
	case 3: return NATIVE_NV_READ_CTPR_REG_VALUE(3);
	default:
		panic("native_read_CTPR_reg_value() invalid CTPR # %d\n",
			reg_no);
	}
	return -1;
}

static void native_write_CTPR_reg_value(int reg_no, unsigned long reg_value)
{
	switch (reg_no) {
	case 1:
		NATIVE_WRITE_CTPR_REG_VALUE(1, reg_value);
		break;
	case 2:
		NATIVE_WRITE_CTPR_REG_VALUE(2, reg_value);
		break;
	case 3:
		NATIVE_WRITE_CTPR_REG_VALUE(3, reg_value);
		break;
	default:
		panic("native_write_CTPR_reg_value() invalid CTPR # %d\n",
			reg_no);
	}
}

static unsigned long native_read_SBR_reg_value(void)
{
	return NATIVE_NV_READ_SBR_REG_VALUE();
}

static void native_write_SBR_reg_value(unsigned long reg_value)
{
	NATIVE_NV_WRITE_SBR_REG_VALUE(reg_value);
}

#ifdef	NEED_PARAVIRT_LOOP_REGISTERS
static unsigned long native_read_LSR_reg_value(void)
{
	return NATIVE_READ_LSR_REG_VALUE();
}

static void native_write_LSR_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_LSR_REG_VALUE(reg_value);
}

static unsigned long native_read_ILCR_reg_value(void)
{
	return NATIVE_READ_ILCR_REG_VALUE();
}

static void native_write_ILCR_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_ILCR_REG_VALUE(reg_value);
}
#endif	/* NEED_PARAVIRT_LOOP_REGISTERS */

static unsigned long native_read_OSR0_reg_value(void)
{
	return NATIVE_NV_READ_OSR0_REG_VALUE();
}

static void native_write_OSR0_reg_value(unsigned long reg_value)
{
	NATIVE_NV_WRITE_OSR0_REG_VALUE(reg_value);
}

static unsigned int native_read_OSEM_reg_value(void)
{
	return NATIVE_READ_OSEM_REG_VALUE();
}

static void native_write_OSEM_reg_value(unsigned int reg_value)
{
	NATIVE_WRITE_OSEM_REG_VALUE(reg_value);
}

static unsigned int native_read_BGR_reg_value(void)
{
	return NATIVE_READ_BGR_REG_VALUE();
}

static notrace void native_write_BGR_reg_value(unsigned int bgr_value)
{
	NATIVE_WRITE_BGR_REG_VALUE(bgr_value);
}

static unsigned long native_read_CLKR_reg_value(void)
{
	return NATIVE_READ_CLKR_REG_VALUE();
}

static void native_write_CLKR_reg_value(void)
{
	NATIVE_WRITE_CLKR_REG_VALUE();
}

static unsigned long native_read_CU_HW0_reg_value(void)
{
	return NATIVE_READ_CU_HW0_REG_VALUE();
}
static unsigned long native_read_CU_HW1_reg_value(void)
{
	return machine.get_cu_hw1();
}
static void native_write_CU_HW0_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_CU_HW0_REG_VALUE(reg_value);
	E2K_WAIT_ALL;
}
static void native_write_CU_HW1_reg_value(unsigned long reg_value)
{
	machine.set_cu_hw1(reg_value);
}

static unsigned long native_read_RPR_lo_reg_value(void)
{
	return NATIVE_READ_RPR_LO_REG_VALUE();
}

static unsigned long native_read_RPR_hi_reg_value(void)
{
	return NATIVE_READ_RPR_HI_REG_VALUE();
}

static void native_write_RPR_lo_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_RPR_LO_REG_VALUE(reg_value);
}

static void native_write_RPR_hi_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_RPR_HI_REG_VALUE(reg_value);
}

static unsigned long native_read_SBBP_reg_value(void)
{
	return NATIVE_READ_SBBP_REG_VALUE();
}

static unsigned long native_read_IP_reg_value(void)
{
	return NATIVE_READ_IP_REG_VALUE();
}

static unsigned int native_read_DIBCR_reg_value(void)
{
	return NATIVE_READ_DIBCR_REG_VALUE();
}

static unsigned int native_read_DIBSR_reg_value(void)
{
	return NATIVE_READ_DIBSR_REG_VALUE();
}

static unsigned long native_read_DIMCR_reg_value(void)
{
	return NATIVE_READ_DIMCR_REG_VALUE();
}

static unsigned long native_read_DIBAR0_reg_value(void)
{
	return NATIVE_READ_DIBAR0_REG_VALUE();
}

static unsigned long native_read_DIBAR1_reg_value(void)
{
	return NATIVE_READ_DIBAR1_REG_VALUE();
}

static unsigned long native_read_DIBAR2_reg_value(void)
{
	return NATIVE_READ_DIBAR2_REG_VALUE();
}

static unsigned long native_read_DIBAR3_reg_value(void)
{
	return NATIVE_READ_DIBAR3_REG_VALUE();
}

static unsigned long native_read_DIMAR0_reg_value(void)
{
	return NATIVE_READ_DIMAR0_REG_VALUE();
}

static unsigned long native_read_DIMAR1_reg_value(void)
{
	return NATIVE_READ_DIMAR1_REG_VALUE();
}

static void native_write_DIBCR_reg_value(unsigned int reg_value)
{
	NATIVE_WRITE_DIBCR_REG_VALUE(reg_value);
}

static void native_write_DIBSR_reg_value(unsigned int reg_value)
{
	NATIVE_WRITE_DIBSR_REG_VALUE(reg_value);
}

static void native_write_DIMCR_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_DIMCR_REG_VALUE(reg_value);
}

static void native_write_DIBAR0_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_DIBAR0_REG_VALUE(reg_value);
}

static void native_write_DIBAR1_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_DIBAR1_REG_VALUE(reg_value);
}

static void native_write_DIBAR2_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_DIBAR2_REG_VALUE(reg_value);
}

static void native_write_DIBAR3_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_DIBAR3_REG_VALUE(reg_value);
}

static void native_write_DIMAR0_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_DIMAR0_REG_VALUE(reg_value);
}

static void native_write_DIMAR1_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_DIMAR1_REG_VALUE(reg_value);
}

static unsigned long native_read_CUTD_reg_value(void)
{
	return NATIVE_NV_READ_CUTD_REG_VALUE();
}

static void native_write_CUTD_reg_value(unsigned long reg_value)
{
	NATIVE_NV_NOIRQ_WRITE_CUTD_REG_VALUE(reg_value);
}

static unsigned int native_read_CUIR_reg_value(void)
{
	return NATIVE_READ_CUIR_REG_VALUE();
}

static unsigned int native_read_PFPFR_reg_value(void)
{
	return NATIVE_NV_READ_PFPFR_REG_VALUE();
}

static void native_write_PFPFR_reg_value(unsigned int reg_value)
{
	NATIVE_NV_WRITE_PFPFR_REG_VALUE(reg_value);
}

static unsigned int native_read_FPCR_reg_value(void)
{
	return NATIVE_NV_READ_FPCR_REG_VALUE();
}

static void native_write_FPCR_reg_value(unsigned int reg_value)
{
	NATIVE_NV_WRITE_FPCR_REG_VALUE(reg_value);
}

static unsigned int native_read_FPSR_reg_value(void)
{
	return NATIVE_NV_READ_FPSR_REG_VALUE();
}

static void native_write_FPSR_reg_value(unsigned int reg_value)
{
	NATIVE_NV_WRITE_FPSR_REG_VALUE(reg_value);
}

static unsigned long native_read_CS_lo_reg_value(void)
{
	return NATIVE_READ_CS_LO_REG_VALUE();
}

static unsigned long native_read_CS_hi_reg_value(void)
{
	return NATIVE_READ_CS_HI_REG_VALUE();
}

static unsigned long native_read_DS_lo_reg_value(void)
{
	return NATIVE_READ_DS_LO_REG_VALUE();
}

static unsigned long native_read_DS_hi_reg_value(void)
{
	return NATIVE_READ_DS_HI_REG_VALUE();
}

static unsigned long native_read_ES_lo_reg_value(void)
{
	return NATIVE_READ_ES_LO_REG_VALUE();
}

static unsigned long native_read_ES_hi_reg_value(void)
{
	return NATIVE_READ_ES_HI_REG_VALUE();
}

static unsigned long native_read_FS_lo_reg_value(void)
{
	return NATIVE_READ_FS_LO_REG_VALUE();
}

static unsigned long native_read_FS_hi_reg_value(void)
{
	return NATIVE_READ_FS_HI_REG_VALUE();
}

static unsigned long native_read_GS_lo_reg_value(void)
{
	return NATIVE_READ_GS_LO_REG_VALUE();
}

static unsigned long native_read_GS_hi_reg_value(void)
{
	return NATIVE_READ_GS_HI_REG_VALUE();
}

static unsigned long native_read_SS_lo_reg_value(void)
{
	return NATIVE_READ_SS_LO_REG_VALUE();
}

static unsigned long native_read_SS_hi_reg_value(void)
{
	return NATIVE_READ_SS_HI_REG_VALUE();
}

static void native_write_CS_lo_reg_value(unsigned long reg_value)
{
	NATIVE_CL_WRITE_CS_LO_REG_VALUE(reg_value);
}

static void native_write_CS_hi_reg_value(unsigned long reg_value)
{
	NATIVE_CL_WRITE_CS_HI_REG_VALUE(reg_value);
}

static void native_write_DS_lo_reg_value(unsigned long reg_value)
{
	NATIVE_CL_WRITE_DS_LO_REG_VALUE(reg_value);
}

static void native_write_DS_hi_reg_value(unsigned long reg_value)
{
	NATIVE_CL_WRITE_DS_HI_REG_VALUE(reg_value);
}

static void native_write_ES_lo_reg_value(unsigned long reg_value)
{
	NATIVE_CL_WRITE_ES_LO_REG_VALUE(reg_value);
}

static void native_write_ES_hi_reg_value(unsigned long reg_value)
{
	NATIVE_CL_WRITE_ES_HI_REG_VALUE(reg_value);
}

static void native_write_FS_lo_reg_value(unsigned long reg_value)
{
	NATIVE_CL_WRITE_FS_LO_REG_VALUE(reg_value);
}

static void native_write_FS_hi_reg_value(unsigned long reg_value)
{
	NATIVE_CL_WRITE_FS_HI_REG_VALUE(reg_value);
}

static void native_write_GS_lo_reg_value(unsigned long reg_value)
{
	NATIVE_CL_WRITE_GS_LO_REG_VALUE(reg_value);
}

static void native_write_GS_hi_reg_value(unsigned long reg_value)
{
	NATIVE_CL_WRITE_GS_HI_REG_VALUE(reg_value);
}

static void native_write_SS_lo_reg_value(unsigned long reg_value)
{
	NATIVE_CL_WRITE_SS_LO_REG_VALUE(reg_value);
}

static void native_write_SS_hi_reg_value(unsigned long reg_value)
{
	NATIVE_CL_WRITE_SS_HI_REG_VALUE(reg_value);
}

static unsigned long native_read_IDR_reg_value(void)
{
	return NATIVE_READ_IDR_REG_VALUE();
}

static unsigned int do_native_read_CORE_MODE_reg_value(void)
{
	return native_read_CORE_MODE_reg_value();
}
static void do_native_write_CORE_MODE_reg_value(unsigned int modes)
{
	native_write_CORE_MODE_reg_value(modes);
}
static unsigned int do_boot_native_read_CORE_MODE_reg_value(void)
{
	return boot_native_read_CORE_MODE_reg_value();
}
static void do_boot_native_write_CORE_MODE_reg_value(unsigned int modes)
{
	boot_native_write_CORE_MODE_reg_value(modes);
}

static inline unsigned int do_read_aafstr_reg_value(void)
{
	return native_read_aafstr_reg_value();
}
static inline void do_write_aafstr_reg_value(unsigned int reg_value)
{
	native_write_aafstr_reg_value(reg_value);
}

static void native_copy_stacks_to_memory(void)
{
	NATIVE_FLUSHCPU;
}
static void
native_correct_trap_psp_pcsp(struct pt_regs *regs, thread_info_t *thread_info)
{
	NATIVE_CORRECT_TRAP_PSP_PCSP(regs, thread_info);
}
static void
native_correct_scall_psp_pcsp(struct pt_regs *regs, thread_info_t *thread_info)
{
	NATIVE_CORRECT_SCALL_PSP_PCSP(regs, thread_info);
}
static void
do_correct_trap_return_ip(struct pt_regs *regs, unsigned long return_ip)
{
	native_correct_trap_return_ip(regs, return_ip);
}
static int do_switch_to_new_user(e2k_stacks_t *stacks, hw_stack_t *hw_stacks,
			e2k_addr_t cut_base, e2k_size_t cut_size,
			e2k_addr_t entry_point, int cui,
			unsigned long flags, bool kernel)
{
	return 0;	/* to continue switching on host */
}
static void
do_free_old_kernel_hardware_stacks(void)
{
	native_free_old_kernel_hardware_stacks();
}
static bool
do_is_proc_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return native_is_proc_stack_bounds(ti, regs);
}
static bool
do_is_chain_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return native_is_chain_stack_bounds(ti, regs);
}
static void
host_instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype,
			const int async_instr)
{
	kvm_host_instr_page_fault(regs, ftype, async_instr);
}
static unsigned long
do_mmio_page_fault(struct pt_regs *regs, struct trap_cellar *tcellar)
{
	return native_mmio_page_fault(regs, (trap_cellar_t *)tcellar);
}
static void
do_init_guest_system_handlers_table(void)
{
	native_init_guest_system_handlers_table();
}

static unsigned long
do_fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return native_fast_tagged_memory_copy(dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
}
static void
do_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	native_fast_tagged_memory_set(addr, val, tag, len, strd_opcode);
}

static unsigned long
do_extract_tags_32(u16 *dst, const void *src)
{
	return native_extract_tags_32(dst, src);
}

static void
do_save_local_glob_regs(local_gregs_t *l_gregs, bool is_signal)
{
	native_save_local_glob_regs(l_gregs, bool is_signal);
}
static void
do_restore_local_glob_regs(local_gregs_t *l_gregs, bool is_signal)
{
	native_restore_local_glob_regs(l_gregs, is_signal);
}

static void
do_get_all_user_glob_regs(global_regs_t *gregs)
{
	native_get_all_user_glob_regs(gregs);
}

static __interrupt void
native_restore_kernel_gregs_in_syscall(struct thread_info *ti)
{
	NATIVE_RESTORE_KERNEL_GREGS_IN_SYSCALL(ti);
}
static void do_cpu_relax(void)
{
	native_cpu_relax();
}
static void do_cpu_relax_no_resched(void)
{
	native_cpu_relax_no_resched();
}
static void do_lock_relax(void *lock)
{
	native_cpu_relax();
}

#ifdef	CONFIG_SMP
static void
do_arch_csd_lock_async(call_single_data_t *data)
{
	native_arch_csd_lock_async(data);
}
#endif	/* CONFIG_SMP */

#define	do_arch_spin_lock_slow		do_lock_relax
#define	do_arch_spin_locked_slow	do_lock_relax
#define	do_arch_spin_unlock_slow	do_lock_relax

#define	PV_CPU_COMMON_OPS						\
	.read_OSCUD_lo_reg_value = native_read_OSCUD_lo_reg_value,	\
	.read_OSCUD_hi_reg_value = native_read_OSCUD_hi_reg_value,	\
	.write_OSCUD_lo_reg_value = native_write_OSCUD_lo_reg_value,	\
	.write_OSCUD_hi_reg_value = native_write_OSCUD_hi_reg_value,	\
	.read_OSGD_lo_reg_value = native_read_OSGD_lo_reg_value,	\
	.read_OSGD_hi_reg_value = native_read_OSGD_hi_reg_value,	\
	.write_OSGD_lo_reg_value = native_write_OSGD_lo_reg_value,	\
	.write_OSGD_hi_reg_value = native_write_OSGD_hi_reg_value,	\
	.read_CUD_lo_reg_value = native_read_CUD_lo_reg_value,		\
	.read_CUD_hi_reg_value = native_read_CUD_hi_reg_value,		\
	.write_CUD_lo_reg_value = native_write_CUD_lo_reg_value,	\
	.write_CUD_hi_reg_value = native_write_CUD_hi_reg_value,	\
	.read_GD_lo_reg_value = native_read_GD_lo_reg_value,		\
	.read_GD_hi_reg_value = native_read_GD_hi_reg_value,		\
	.write_GD_lo_reg_value = native_write_GD_lo_reg_value,		\
	.write_GD_hi_reg_value = native_write_GD_hi_reg_value,		\
	.read_PSP_lo_reg_value = INLINE_FUNC_CALL,			\
	.read_PSP_hi_reg_value = INLINE_FUNC_CALL,			\
	.write_PSP_lo_reg_value = INLINE_FUNC_CALL,			\
	.write_PSP_hi_reg_value = INLINE_FUNC_CALL,			\
	.read_PSHTP_reg_value = INLINE_FUNC_CALL,			\
	.write_PSHTP_reg_value = INLINE_FUNC_CALL,			\
	.read_PCSP_lo_reg_value = INLINE_FUNC_CALL,			\
	.read_PCSP_hi_reg_value = INLINE_FUNC_CALL,			\
	.write_PCSP_lo_reg_value = INLINE_FUNC_CALL,			\
	.write_PCSP_hi_reg_value = INLINE_FUNC_CALL,			\
	.read_PCSHTP_reg_value = INLINE_FUNC_CALL,			\
	.write_PCSHTP_reg_value = INLINE_FUNC_CALL,			\
	.read_CR0_lo_reg_value = INLINE_FUNC_CALL,			\
	.read_CR0_hi_reg_value = INLINE_FUNC_CALL,			\
	.read_CR1_lo_reg_value = INLINE_FUNC_CALL,			\
	.read_CR1_hi_reg_value = INLINE_FUNC_CALL,			\
	.write_CR0_lo_reg_value = INLINE_FUNC_CALL,			\
	.write_CR0_hi_reg_value = INLINE_FUNC_CALL,			\
	.write_CR1_lo_reg_value = INLINE_FUNC_CALL,			\
	.write_CR1_hi_reg_value = INLINE_FUNC_CALL,			\
	.read_CTPR_reg_value = native_read_CTPR_reg_value,		\
	.write_CTPR_reg_value = native_write_CTPR_reg_value,		\
	.read_USD_lo_reg_value = INLINE_FUNC_CALL,			\
	.read_USD_hi_reg_value = INLINE_FUNC_CALL,			\
	.write_USD_lo_reg_value = INLINE_FUNC_CALL,			\
	.write_USD_hi_reg_value = INLINE_FUNC_CALL,			\
	.read_SBR_reg_value = native_read_SBR_reg_value,		\
	.write_SBR_reg_value = native_write_SBR_reg_value,		\
	.read_WD_reg_value = INLINE_FUNC_CALL,				\
	.write_WD_reg_value = INLINE_FUNC_CALL,				\
	.read_OSR0_reg_value = native_read_OSR0_reg_value,		\
	.write_OSR0_reg_value = native_write_OSR0_reg_value,		\
	.read_OSEM_reg_value = native_read_OSEM_reg_value,		\
	.write_OSEM_reg_value = native_write_OSEM_reg_value,		\
	.read_BGR_reg_value = native_read_BGR_reg_value,		\
	.write_BGR_reg_value = native_write_BGR_reg_value,		\
	.read_CLKR_reg_value = native_read_CLKR_reg_value,		\
	.write_CLKR_reg_value = native_write_CLKR_reg_value,		\
	.read_SCLKR_reg_value = native_read_SCLKR_reg_value,		\
	.write_SCLKR_reg_value = native_write_SCLKR_reg_value,		\
	.read_SCLKM1_reg_value = native_read_SCLKM1_reg_value,		\
	.write_SCLKM1_reg_value = native_write_SCLKM1_reg_value,	\
	.read_SCLKM2_reg_value = native_read_SCLKM2_reg_value,		\
	.write_SCLKM2_reg_value = native_write_SCLKM2_reg_value,	\
	.read_CU_HW0_reg_value = native_read_CU_HW0_reg_value,		\
	.read_CU_HW1_reg_value = native_read_CU_HW1_reg_value,		\
	.write_CU_HW0_reg_value = native_write_CU_HW0_reg_value,	\
	.write_CU_HW1_reg_value = native_write_CU_HW1_reg_value,	\
	.read_RPR_lo_reg_value = native_read_RPR_lo_reg_value,		\
	.read_RPR_hi_reg_value = native_read_RPR_hi_reg_value,		\
	.write_RPR_lo_reg_value = native_write_RPR_lo_reg_value,	\
	.write_RPR_hi_reg_value = native_write_RPR_hi_reg_value,	\
	.read_SBBP_reg_value = native_read_SBBP_reg_value,		\
	.read_IP_reg_value = native_read_IP_reg_value,			\
	.read_DIBCR_reg_value = native_read_DIBCR_reg_value,		\
	.read_DIBSR_reg_value = native_read_DIBSR_reg_value,		\
	.read_DIMCR_reg_value = native_read_DIMCR_reg_value,		\
	.read_DIBAR0_reg_value = native_read_DIBAR0_reg_value,		\
	.read_DIBAR1_reg_value = native_read_DIBAR1_reg_value,		\
	.read_DIBAR2_reg_value = native_read_DIBAR2_reg_value,		\
	.read_DIBAR3_reg_value = native_read_DIBAR3_reg_value,		\
	.read_DIMAR0_reg_value = native_read_DIMAR0_reg_value,		\
	.read_DIMAR1_reg_value = native_read_DIMAR1_reg_value,		\
	.write_DIBCR_reg_value = native_write_DIBCR_reg_value,		\
	.write_DIBSR_reg_value = native_write_DIBSR_reg_value,		\
	.write_DIMCR_reg_value = native_write_DIMCR_reg_value,		\
	.write_DIBAR0_reg_value = native_write_DIBAR0_reg_value,	\
	.write_DIBAR1_reg_value = native_write_DIBAR1_reg_value,	\
	.write_DIBAR2_reg_value = native_write_DIBAR2_reg_value,	\
	.write_DIBAR3_reg_value = native_write_DIBAR3_reg_value,	\
	.write_DIMAR0_reg_value = native_write_DIMAR0_reg_value,	\
	.write_DIMAR1_reg_value = native_write_DIMAR1_reg_value,	\
	.read_CUTD_reg_value = native_read_CUTD_reg_value,		\
	.read_CUIR_reg_value = native_read_CUIR_reg_value,		\
	.write_CUTD_reg_value = native_write_CUTD_reg_value,		\
	.read_UPSR_reg_value = INLINE_FUNC_CALL,			\
	.write_UPSR_reg_value = INLINE_FUNC_CALL,			\
	.read_PSR_reg_value = INLINE_FUNC_CALL,				\
	.write_PSR_reg_value = INLINE_FUNC_CALL,			\
	.write_UPSR_irq_barrier = INLINE_FUNC_CALL,			\
	.write_PSR_irq_barrier = INLINE_FUNC_CALL,			\
	.read_PFPFR_reg_value = native_read_PFPFR_reg_value,		\
	.read_FPCR_reg_value = native_read_FPCR_reg_value,		\
	.read_FPSR_reg_value = native_read_FPSR_reg_value,		\
	.write_PFPFR_reg_value = native_write_PFPFR_reg_value,		\
	.write_FPCR_reg_value = native_write_FPCR_reg_value,		\
	.write_FPSR_reg_value = native_write_FPSR_reg_value,		\
	.read_CS_lo_reg_value = native_read_CS_lo_reg_value,		\
	.read_CS_hi_reg_value = native_read_CS_hi_reg_value,		\
	.read_DS_lo_reg_value = native_read_DS_lo_reg_value,		\
	.read_DS_hi_reg_value = native_read_DS_hi_reg_value,		\
	.read_ES_lo_reg_value = native_read_ES_lo_reg_value,		\
	.read_ES_hi_reg_value = native_read_ES_hi_reg_value,		\
	.read_FS_lo_reg_value = native_read_FS_lo_reg_value,		\
	.read_FS_hi_reg_value = native_read_FS_hi_reg_value,		\
	.read_GS_lo_reg_value = native_read_GS_lo_reg_value,		\
	.read_GS_hi_reg_value = native_read_GS_hi_reg_value,		\
	.read_SS_lo_reg_value = native_read_SS_lo_reg_value,		\
	.read_SS_hi_reg_value = native_read_SS_hi_reg_value,		\
	.write_CS_lo_reg_value = native_write_CS_lo_reg_value,		\
	.write_CS_hi_reg_value = native_write_CS_hi_reg_value,		\
	.write_DS_lo_reg_value = native_write_DS_lo_reg_value,		\
	.write_DS_hi_reg_value = native_write_DS_hi_reg_value,		\
	.write_ES_lo_reg_value = native_write_ES_lo_reg_value,		\
	.write_ES_hi_reg_value = native_write_ES_hi_reg_value,		\
	.write_FS_lo_reg_value = native_write_FS_lo_reg_value,		\
	.write_FS_hi_reg_value = native_write_FS_hi_reg_value,		\
	.write_GS_lo_reg_value = native_write_GS_lo_reg_value,		\
	.write_GS_hi_reg_value = native_write_GS_hi_reg_value,		\
	.write_SS_lo_reg_value = native_write_SS_lo_reg_value,		\
	.write_SS_hi_reg_value = native_write_SS_hi_reg_value,		\
	.read_IDR_reg_value = native_read_IDR_reg_value,		\
	.boot_read_IDR_reg_value = boot_native_read_IDR_reg_value,	\
	.read_CORE_MODE_reg_value = do_native_read_CORE_MODE_reg_value,	\
	.boot_read_CORE_MODE_reg_value =				\
		do_boot_native_read_CORE_MODE_reg_value,		\
	.write_CORE_MODE_reg_value = do_native_write_CORE_MODE_reg_value, \
	.boot_write_CORE_MODE_reg_value =				\
		do_boot_native_write_CORE_MODE_reg_value,		\
	.put_updated_cpu_regs_flags = NULL,				\
	.read_aasr_reg_value = (void *)-1UL,				\
	.write_aasr_reg_value = INLINE_FUNC_CALL,			\
	.read_aafstr_reg_value = do_read_aafstr_reg_value,		\
	.write_aafstr_reg_value = do_write_aafstr_reg_value,		\
	.flush_stacks = INLINE_FUNC_CALL,				\
	.flush_regs_stack = INLINE_FUNC_CALL,				\
	.flush_chain_stack = INLINE_FUNC_CALL,				\
	.copy_stacks_to_memory = native_copy_stacks_to_memory,		\
	.get_active_cr0_lo_value = INLINE_FUNC_CALL,			\
	.get_active_cr0_hi_value = INLINE_FUNC_CALL,			\
	.get_active_cr1_lo_value = INLINE_FUNC_CALL,			\
	.get_active_cr1_hi_value = INLINE_FUNC_CALL,			\
	.put_active_cr0_lo_value = INLINE_FUNC_CALL,			\
	.put_active_cr0_hi_value = INLINE_FUNC_CALL,			\
	.put_active_cr1_lo_value = INLINE_FUNC_CALL,			\
	.put_active_cr1_hi_value = INLINE_FUNC_CALL,			\
	.correct_trap_psp_pcsp = native_correct_trap_psp_pcsp,		\
	.correct_scall_psp_pcsp = native_correct_scall_psp_pcsp,	\
	.correct_trap_return_ip = do_correct_trap_return_ip,		\
	.nested_kernel_return_address = __e2k_read_kernel_return_address, \
	.virt_cpu_thread_init = NULL,					\
	.prepare_start_thread_frames =					\
		native_do_prepare_start_thread_frames,			\
	.copy_kernel_stacks = native_copy_kernel_stacks,		\
	.copy_user_stacks = native_copy_user_stacks,			\
	.define_kernel_hw_stacks_sizes =				\
		native_do_define_kernel_hw_stacks_sizes,		\
	.define_user_hw_stacks_sizes = native_define_user_hw_stacks_sizes, \
	.switch_to_expanded_proc_stack = NULL,				\
	.switch_to_expanded_chain_stack = NULL,				\
	.stack_bounds_trap_enable = NULL,				\
	.is_proc_stack_bounds = do_is_proc_stack_bounds,		\
	.is_chain_stack_bounds = do_is_chain_stack_bounds,		\
	.release_hw_stacks = native_release_hw_stacks,			\
	.release_kernel_stacks = native_release_kernel_stacks,		\
	.register_kernel_hw_stack = NULL,				\
	.register_kernel_data_stack = NULL,				\
	.unregister_kernel_hw_stack = NULL,				\
	.unregister_kernel_data_stack = NULL,				\
	.kmem_area_host_chunk = NULL,					\
	.kmem_area_unhost_chunk = NULL,					\
	.switch_to_new_user = do_switch_to_new_user,			\
	.do_map_user_hard_stack_to_kernel = NULL,			\
	.do_switch_to_kernel_hardware_stacks = NULL,			\
	.free_old_kernel_hardware_stacks =				\
		do_free_old_kernel_hardware_stacks,			\
	.instr_page_fault = host_instr_page_fault,			\
	.mmio_page_fault = do_mmio_page_fault,				\
	.do_hw_stack_bounds = native_do_hw_stack_bounds,		\
	.handle_interrupt = native_do_interrupt,			\
	.init_guest_system_handlers_table =				\
		do_init_guest_system_handlers_table,			\
	.fix_process_pt_regs = NULL,					\
	.run_user_handler = NULL,					\
	.trap_table_entry1 = native_ttable_entry1,			\
	.trap_table_entry3 = native_ttable_entry3,			\
	.trap_table_entry4 = native_ttable_entry4,			\
	.do_fast_clock_gettime = native_do_fast_clock_gettime,		\
	.fast_sys_clock_gettime = native_fast_sys_clock_gettime,	\
	.do_fast_gettimeofday = native_do_fast_gettimeofday,		\
	.fast_sys_siggetmask = native_fast_sys_siggetmask,		\
	.fast_tagged_memory_copy = do_fast_tagged_memory_copy,		\
	.fast_tagged_memory_set = do_fast_tagged_memory_set,		\
	.extract_tags_32 = do_extract_tags_32,				\
	.save_local_glob_regs = do_save_local_glob_regs,		\
	.restore_local_glob_regs = do_restore_local_glob_regs,		\
	.restore_kernel_gregs_in_syscall =				\
		native_restore_kernel_gregs_in_syscall,			\
	.get_all_user_glob_regs = do_get_all_user_glob_regs,		\
	.arch_setup_machine = native_setup_machine,			\
	.cpu_default_idle = native_default_idle,			\
	.cpu_relax = do_cpu_relax,					\
	.cpu_relax_no_resched = do_cpu_relax_no_resched,		\
	.host_printk = printk,						\
	.arch_spin_lock_slow = do_arch_spin_lock_slow,			\
	.arch_spin_relock_slow = do_arch_spin_relock_slow,		\
	.arch_spin_locked_slow = do_arch_spin_locked_slow,		\
	.arch_spin_unlock_slow = do_arch_spin_unlock_slow,		\
	.ord_wait_read_lock_slow = NULL,				\
	.ord_wait_write_lock_slow = NULL,				\
	.ord_arch_read_locked_slow = NULL,				\
	.ord_arch_write_locked_slow = NULL,				\
	.ord_arch_read_unlock_slow = NULL,				\
	.ord_arch_write_unlock_slow = NULL,				\

#ifdef	CONFIG_SMP
#define	PV_CPU_SMP_OPS							\
	.wait_for_cpu_booting = native_wait_for_cpu_booting,		\
	.wait_for_cpu_wake_up = native_wait_for_cpu_wake_up,		\
	.activate_cpu = native_activate_cpu,				\
	.activate_all_cpus = native_activate_all_cpus,			\
	.csd_lock_wait = native_csd_lock_wait,				\
	.csd_lock = native_csd_lock,					\
	.arch_csd_lock_async = do_arch_csd_lock_async,			\
	.csd_unlock = native_csd_unlock,				\
	.setup_local_pic_virq = NULL,					\
	.startup_local_pic_virq = NULL,				\
	.smp_flush_tlb_all = native_smp_flush_tlb_all,			\
	.smp_flush_tlb_mm = native_smp_flush_tlb_mm,			\
	.smp_flush_tlb_page = native_smp_flush_tlb_page,		\
	.smp_flush_tlb_range = native_smp_flush_tlb_range,		\
	.smp_flush_pmd_tlb_range = native_smp_flush_pmd_tlb_range,	\
	.smp_flush_tlb_range_and_pgtables =				\
		native_smp_flush_tlb_range_and_pgtables,		\
	.smp_flush_icache_range = native_smp_flush_icache_range,	\
	.smp_flush_icache_range_array =					\
		(void (*)(void *))native_smp_flush_icache_range_array,	\
	.smp_flush_icache_page = native_smp_flush_icache_page,		\
	.smp_flush_icache_all = native_smp_flush_icache_all,		\
	.smp_flush_icache_kernel_line =					\
		native_smp_flush_icache_kernel_line,			\

#else	/* ! CONFIG_SMP */
#define	PV_CPU_SMP_OPS
#endif	/* CONFIG_SMP */

#ifdef	NEED_PARAVIRT_LOOP_REGISTERS
#define	PV_CPU_LOOP_OPS							\
	.read_LSR_reg_value = native_read_LSR_reg_value,		\
	.write_LSR_reg_value = native_write_LSR_reg_value,		\
	.read_ILCR_reg_value = native_read_ILCR_reg_value,		\
	.write_ILCR_reg_value = native_write_ILCR_reg_value,		\

#else	/* ! NEED_PARAVIRT_LOOP_REGISTERS */
#define	PV_CPU_LOOP_OPS
#endif	/* NEED_PARAVIRT_LOOP_REGISTERS */
#define	PV_CPU_OPS {							\
		PV_CPU_COMMON_OPS					\
		PV_CPU_LOOP_OPS						\
		PV_CPU_SMP_OPS						\
}

pv_cpu_ops_t pv_cpu_ops = PV_CPU_OPS;
EXPORT_SYMBOL(pv_cpu_ops);
pv_cpu_ops_t boot_pv_cpu_ops = PV_CPU_OPS;
pv_cpu_ops_t *cur_pv_cpu_ops = &boot_pv_cpu_ops;

static unsigned int do_apic_read(unsigned int reg)
{
	return native_apic_read(reg);
}

static void do_apic_write(unsigned int reg, unsigned int v)
{
	native_apic_write(reg, v);
}

#define	PV_APIC_OPS {							\
	.apic_write = do_apic_write,					\
	.apic_read = do_apic_read,					\
	.boot_apic_write = do_apic_write,				\
	.boot_apic_read = do_apic_read,					\
}

pv_apic_ops_t pv_apic_ops = PV_APIC_OPS;
EXPORT_SYMBOL_GPL(pv_apic_ops);
pv_apic_ops_t boot_pv_apic_ops = PV_APIC_OPS;
pv_apic_ops_t *cur_pv_apic_ops = &boot_pv_apic_ops;

static unsigned int do_epic_read_w(unsigned int reg)
{
	return native_epic_read_w(reg);
}

static void do_epic_write_w(unsigned int reg, unsigned int v)
{
	native_epic_write_w(reg, v);
}

static unsigned long do_epic_read_d(unsigned int reg)
{
	return native_epic_read_d(reg);
}

static void do_epic_write_d(unsigned int reg, unsigned long v)
{
	native_epic_write_d(reg, v);
}

#define	PV_EPIC_OPS {							\
	.epic_write_w = do_epic_write_w,				\
	.epic_read_w = do_epic_read_w,					\
	.epic_write_d = do_epic_write_d,				\
	.epic_read_d = do_epic_read_d,					\
	.boot_epic_write_w = do_epic_write_w,				\
	.boot_epic_read_w = do_epic_read_w,				\
}

pv_epic_ops_t pv_epic_ops = PV_EPIC_OPS;
EXPORT_SYMBOL_GPL(pv_epic_ops);
pv_epic_ops_t boot_pv_epic_ops = PV_EPIC_OPS;
pv_epic_ops_t *cur_pv_epic_ops = &boot_pv_epic_ops;

static long
RECOVERY_FAULTED_TAGGED_STORE(e2k_addr_t address, u64 wr_data,
				u32 data_tag, u64 st_rec_opc, int chan)
{
	return native_recovery_faulted_tagged_store(address, wr_data, data_tag,
							st_rec_opc, chan);
}
static long
RECOVERY_FAULTED_LOAD(e2k_addr_t address, u64 *ld_val, u8 *data_tag,
				u64 ld_rec_opc, int chan)
{
	return native_recovery_faulted_load(address, ld_val, data_tag,
							ld_rec_opc, chan);
}
static long
RECOVERY_FAULTED_MOVE(e2k_addr_t addr_from, e2k_addr_t addr_to,
				int format, int vr, u64 ld_rec_opc, int chan)
{
	return native_recovery_faulted_move(addr_from, addr_to,
						format, vr, ld_rec_opc, chan);
}
static long
RECOVERY_FAULTED_LOAD_TO_GREG(e2k_addr_t address,
				u32 greg_num_d, int format, int vr,
				u64 ld_rec_opc, int chan, void *saved_greg)
{
	return native_recovery_faulted_load_to_greg(address, greg_num_d,
				format, vr, ld_rec_opc, chan, saved_greg);
}
static void
MOVE_TAGGED_WORD(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	native_move_tagged_word(addr_from, addr_to);
}
static void
MOVE_TAGGED_DWORD(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	native_move_tagged_dword(addr_from, addr_to);
}
static void
MOVE_TAGGED_QWORD(e2k_addr_t addr_from, e2k_addr_t addr_to)
{
	native_move_tagged_qword(addr_from, addr_to);
}

static void DO_WRITE_MMU_REG(mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	NATIVE_WRITE_MMU_REG(mmu_addr, mmu_reg);
}

static mmu_reg_t DO_READ_MMU_REG(mmu_addr_t mmu_addr)
{
	return (mmu_reg_t)NATIVE_READ_MMU_REG(mmu_addr);
}

/*
 * Write/read Data TLB register
 */

static void DO_WRITE_DTLB_REG(tlb_addr_t tlb_addr, mmu_reg_t mmu_reg)
{
	NATIVE_WRITE_DTLB_REG(tlb_addr, mmu_reg);
}

static mmu_reg_t DO_READ_DTLB_REG(tlb_addr_t tlb_addr)
{
	return NATIVE_READ_DTLB_REG(tlb_addr);
}

/*
 * Flush TLB page/entry
 */

static void
DO_FLUSH_TLB_ENTRY(flush_op_t flush_op, flush_addr_t flush_addr)
{
	NATIVE_FLUSH_TLB_ENTRY(flush_op, flush_addr);
}

/*
 * Flush DCACHE line
 */

static void
PV_DO_FLUSH_DCACHE_LINE(e2k_addr_t virt_addr)
{
	NATIVE_FLUSH_DCACHE_LINE(virt_addr);
}

/*
 * Clear DCACHE L1 set
 */
static void
DO_CLEAR_DCACHE_L1_SET(e2k_addr_t virt_addr, unsigned long set)
{
	NATIVE_CLEAR_DCACHE_L1_SET(virt_addr, set);
}
static void
do_flush_DCACHE_range(void *addr, size_t len)
{
	native_flush_DCACHE_range(addr, len);
}
static void
do_clear_DCACHE_L1_range(void *virt_addr, size_t len)
{
	native_clear_DCACHE_L1_range(virt_addr, len);
}

/*
 * Write/read DCACHE L2 registers
 */
static void
DO_WRITE_DCACHE_L2_REG(unsigned long reg_val, int reg_num, int bank_num)
{
	native_write_DCACHE_L2_reg(reg_val, reg_num, bank_num);
}
static unsigned long
DO_READ_DCACHE_L2_REG(int reg_num, int bank_num)
{
	return native_read_DCACHE_L2_reg(reg_num, bank_num);
}

/*
 * Flush ICACHE line
 */

static void
DO_FLUSH_ICACHE_LINE(flush_op_t flush_op, flush_addr_t flush_addr)
{
	NATIVE_FLUSH_ICACHE_LINE(flush_op, flush_addr);
}

/*
 * Flush and invalidate or write back CACHE(s) (invalidate all caches
 * of the processor)
 */

static void
DO_FLUSH_CACHE_L12(flush_op_t flush_op)
{
	NATIVE_FLUSH_CACHE_L12(flush_op);
}

/*
 * Flush TLB (invalidate all TLBs of the processor)
 */

static void
DO_FLUSH_TLB_ALL(flush_op_t flush_op)
{
	NATIVE_FLUSH_TLB_ALL(flush_op);
}

/*
 * Flush ICACHE (invalidate instruction caches of the processor)
 */

static void
DO_FLUSH_ICACHE_ALL(flush_op_t flush_op)
{
	NATIVE_FLUSH_ICACHE_ALL(flush_op);
}

/*
 * Get Entry probe for virtual address
 */

static probe_entry_t
DO_ENTRY_PROBE_MMU_OP(e2k_addr_t virt_addr)
{
	return NATIVE_ENTRY_PROBE_MMU_OP(virt_addr);
}

/*
 * Get physical address for virtual address
 */

static probe_entry_t
DO_ADDRESS_PROBE_MMU_OP(e2k_addr_t virt_addr)
{
	return NATIVE_ADDRESS_PROBE_MMU_OP(virt_addr);
}

/*
 * Read CLW register
 */

static clw_reg_t
DO_READ_CLW_REG(clw_addr_t clw_addr)
{
	return NATIVE_READ_CLW_REG(clw_addr);
}

/*
 * Write CLW register
 */

static void
DO_WRITE_CLW_REG(clw_addr_t clw_addr, clw_reg_t val)
{
	NATIVE_WRITE_CLW_REG(clw_addr, val);
}

/* save DAM state */
static void
DO_SAVE_DAM(unsigned long long dam[DAM_ENTRIES_NUM])
{
	NATIVE_SAVE_DAM(dam);
}

/*
 * MMU DEBUG registers access
 */
static mmu_reg_t DO_READ_MMU_DEBUG_REG(int reg_no)
{
	return (mmu_reg_t)NATIVE_GET_MMU_DEBUG_REG(reg_no);
}

static void DO_WRITE_MMU_DEBUG_REG(int reg_no, mmu_reg_t mmu_reg)
{
	NATIVE_SET_MMU_DEBUG_REG(reg_no, mmu_reg);
}

static void do_boot_set_pte_at(unsigned long addr, pte_t *ptep, pte_t pteval)
{
	native_set_pte(ptep, pteval, false);
}
static void
do_write_pte_at(struct mm_struct *mm, unsigned long addr,
			pte_t *ptep, pte_t pteval,
			bool only_validate, bool to_move)
{
	native_write_pte_at(mm, addr, ptep, pteval, only_validate);
}
static void native_do_set_pte(pte_t *ptep, pte_t pteval)
{
	native_set_pte(ptep, pteval, false);
}

static void
do_write_pmd_at(struct mm_struct *mm, unsigned long addr,
			pmd_t *pmdp, pmd_t pmdval,
			bool only_validate)
{
	native_write_pmd_at(mm, addr, pmdp, pmdval, only_validate);
}

static void
do_write_pud_at(struct mm_struct *mm, unsigned long addr,
			pud_t *pudp, pud_t pudval,
			bool only_validate)
{
	native_write_pud_at(mm, addr, pudp, pudval, only_validate);
}

static void
do_write_pgd_at(struct mm_struct *mm, unsigned long addr,
			pgd_t *pgdp, pgd_t pgdval,
			bool only_validate)
{
	native_write_pgd_at(mm, addr, pgdp, pgdval, only_validate);
}

static pte_t do_pv_ptep_get_and_clear(struct mm_struct *mm, unsigned long addr,
					pte_t *ptep, bool to_move)
{
	return native_ptep_get_and_clear(mm, addr, ptep);
}
static void do_ptep_wrprotect_atomic(struct mm_struct *mm,
					e2k_addr_t addr, pte_t *ptep)
{
#ifdef	CONFIG_SMP
	native_ptep_wrprotect_atomic(mm, addr, ptep);
#endif	/* CONFIG_SMP */
}
static pte_t do_get_pte_for_address(struct vm_area_struct *vma,
					e2k_addr_t address)
{
	return native_do_get_pte_for_address(vma, address);
}
static void do_free_mm(struct mm_struct *mm)
{
	native_free_mm(mm);
}
static void do_activate_mm(struct mm_struct *active_mm, struct mm_struct *mm)
{
	native_activate_mm(active_mm, mm);
}
static int do_make_host_pages_valid(struct vm_area_struct *vma,
			e2k_addr_t start_addr, e2k_addr_t end_addr,
			bool chprot, bool flush)
{
	return native_make_host_pages_valid(vma, start_addr, end_addr,
						chprot, flush);
}
static int do_set_memory_attr_on_host(e2k_addr_t start, e2k_addr_t end,
					int mode)
{
	return native_set_memory_attr_on_host(start, end, (enum sma_mode)mode);
}

#define	PV_GEN_MMU_OPS							\
	.recovery_faulted_tagged_store = RECOVERY_FAULTED_TAGGED_STORE,	\
	.recovery_faulted_load = RECOVERY_FAULTED_LOAD,			\
	.recovery_faulted_move = RECOVERY_FAULTED_MOVE,			\
	.recovery_faulted_load_to_greg = RECOVERY_FAULTED_LOAD_TO_GREG,	\
	.move_tagged_word = MOVE_TAGGED_WORD,				\
	.move_tagged_dword = MOVE_TAGGED_DWORD,				\
	.move_tagged_qword = MOVE_TAGGED_QWORD,				\
	.write_mmu_reg = DO_WRITE_MMU_REG,				\
	.read_mmu_reg = DO_READ_MMU_REG,				\
	.write_dtlb_reg = DO_WRITE_DTLB_REG,				\
	.read_dtlb_reg = DO_READ_DTLB_REG,				\
	.flush_tlb_entry = DO_FLUSH_TLB_ENTRY,				\
	.flush_dcache_line = PV_DO_FLUSH_DCACHE_LINE,			\
	.clear_dcache_l1_set = DO_CLEAR_DCACHE_L1_SET,			\
	.flush_dcache_range = do_flush_DCACHE_range,			\
	.clear_dcache_l1_range = do_clear_DCACHE_L1_range,		\
	.write_dcache_l2_reg = DO_WRITE_DCACHE_L2_REG,			\
	.read_dcache_l2_reg = DO_READ_DCACHE_L2_REG,			\
	.flush_icache_line = DO_FLUSH_ICACHE_LINE,			\
	.flush_cache_all = DO_FLUSH_CACHE_L12,				\
	.do_flush_tlb_all = DO_FLUSH_TLB_ALL,				\
	.flush_icache_all = DO_FLUSH_ICACHE_ALL,			\
	.entry_probe_mmu_op = DO_ENTRY_PROBE_MMU_OP,			\
	.address_probe_mmu_op = DO_ADDRESS_PROBE_MMU_OP,		\
	.read_clw_reg = DO_READ_CLW_REG,				\
	.write_clw_reg = DO_WRITE_CLW_REG,				\
	.save_DAM = DO_SAVE_DAM,					\
	.write_mmu_debug_reg = DO_WRITE_MMU_DEBUG_REG,			\
	.read_mmu_debug_reg = DO_READ_MMU_DEBUG_REG,			\
	.boot_set_pte_at = do_boot_set_pte_at,				\
	.write_pte_at = do_write_pte_at,				\
	.set_pte = native_do_set_pte,					\
	.write_pmd_at = do_write_pmd_at,				\
	.write_pud_at = do_write_pud_at,				\
	.write_pgd_at = do_write_pgd_at,				\
	.ptep_get_and_clear = do_pv_ptep_get_and_clear,			\
	.ptep_wrprotect_atomic = do_ptep_wrprotect_atomic,		\
	.get_pte_for_address = do_get_pte_for_address,			\
	.remap_area_pages = native_remap_area_pages,			\
	.host_guest_vmap_area = NULL,					\
	.unhost_guest_vmap_area = NULL,					\
									\
	/* memory management - mman.h */				\
	.free_mm = do_free_mm,						\
	.mm_init = native_mm_init,					\
	.activate_mm = do_activate_mm,					\
	.make_host_pages_valid = do_make_host_pages_valid,		\
	.set_memory_attr_on_host = do_set_memory_attr_on_host,		\
	.access_process_vm = kvm_access_process_vm,			\
									\
	/* memory management - mm.h */					\
	.free_pgd_range = native_free_pgd_range,			\
									\
	/* kernel virtual memory allocation - vmalloc.h */		\
	.alloc_vmap_area = native_alloc_vmap_area,			\
	.__free_vmap_area = native__free_vmap_area,			\
	.free_unmap_vmap_area = native_free_unmap_vmap_area,		\
	/* unmap __init areas */					\
	.unmap_initmem = NULL,						\

#ifdef	CONFIG_SMP
#define	PV_SMP_MMU_OPS							\
	.pcpu_get_vm_areas = native_pcpu_get_vm_areas,			\

#else	/* ! CONFIG_SMP */
#define	PV_SMP_MMU_OPS
#endif	/* CONFIG_SMP */

#define	PV_MMU_OPS {	\
	PV_GEN_MMU_OPS	\
	PV_SMP_MMU_OPS	\
}

pv_mmu_ops_t pv_mmu_ops = PV_MMU_OPS;
EXPORT_SYMBOL(pv_mmu_ops);
pv_mmu_ops_t boot_pv_mmu_ops = PV_MMU_OPS;
pv_mmu_ops_t *cur_pv_mmu_ops = &boot_pv_mmu_ops;

/*
 * get/set current time
 */
static unsigned long do_get_cpu_running_cycles(void)
{
	return native_get_cpu_running_cycles();
}

static unsigned long long do_pv_sched_clock(void)
{
	/* FIXME: not implemented
	return native_sched_clock();
	*/
	return 0;
}

pv_time_ops_t pv_time_ops = {
	.time_init		= native_time_init,
	.clock_init		= native_clock_init,
	.read_current_timer	= native_read_current_timer,
	.get_cpu_running_cycles	= do_get_cpu_running_cycles,
	.do_sched_clock		= do_pv_sched_clock,
	.steal_clock		= native_steal_clock,
};
EXPORT_SYMBOL_GPL(pv_time_ops);

pv_irq_ops_t pv_irq_ops = {
};
EXPORT_SYMBOL(pv_irq_ops);

static notrace void NATIVE_WRITEB(u8 b, void __iomem *addr)
{
	native_writeb(b, addr);
}

static notrace void NATIVE_WRITEW(u16 w, void __iomem *addr)
{
	native_writew(w, addr);
}

static notrace void NATIVE_WRITEL(u32 l, void __iomem *addr)
{
	native_writel(l, addr);
}

static notrace void NATIVE_WRITELL(u64 q, void __iomem *addr)
{
	native_writeq(q, addr);
}

static notrace u8 NATIVE_READB(void __iomem *addr)
{
	return native_readb(addr);
}

static notrace u16 NATIVE_READW(void __iomem *addr)
{
	return native_readw(addr);
}

static notrace u32 NATIVE_READL(void __iomem *addr)
{
	return native_readl(addr);
}

static notrace u64 NATIVE_READLL(void __iomem *addr)
{
	return native_readq(addr);
}

static notrace void BOOT_NATIVE_WRITEB(u8 b, void __iomem *addr)
{
	boot_native_writeb(b, addr);
}

static notrace void BOOT_NATIVE_WRITEW(u16 w, void __iomem *addr)
{
	boot_native_writew(w, addr);
}

static notrace void BOOT_NATIVE_WRITEL(u32 l, void __iomem *addr)
{
	boot_native_writel(l, addr);
}

static notrace void BOOT_NATIVE_WRITELL(u64 q, void __iomem *addr)
{
	boot_native_writell(q, addr);
}

static notrace u8 BOOT_NATIVE_READB(void __iomem *addr)
{
	return boot_native_readb(addr);
}

static notrace u16 BOOT_NATIVE_READW(void __iomem *addr)
{
	return boot_native_readw(addr);
}

static notrace u32 BOOT_NATIVE_READL(void __iomem *addr)
{
	return boot_native_readl(addr);
}

static notrace u64 BOOT_NATIVE_READLL(void __iomem *addr)
{
	return boot_native_readll(addr);
}

static void NATIVE_OUTSB(unsigned short port, const void *src, unsigned long count)
{
	native_outsb(port, src, count);
}

static void NATIVE_OUTSW(unsigned short port, const void *src, unsigned long count)
{
	native_outsw(port, src, count);
}

static void NATIVE_OUTSL(unsigned short port, const void *src, unsigned long count)
{
	native_outsl(port, src, count);
}

static void NATIVE_INSB(unsigned short port, void *dst, unsigned long count)
{
	native_insb(port, dst, count);
}

static void NATIVE_INSW(unsigned short port, void *dst, unsigned long count)
{
	native_insw(port, dst, count);
}

static void NATIVE_INSL(unsigned short port, void *dst, unsigned long count)
{
	native_insl(port, dst, count);
}

static void do_scr_writew(u16 val, volatile u16 *addr)
{
	native_scr_writew(val, addr);
}
static u16 do_scr_readw(volatile const u16 *addr)
{
	return native_scr_readw(addr);
}
static void do_vga_writeb(u8 val, volatile u8 *addr)
{
	native_vga_writeb(val, addr);
}
static u8 do_vga_readb(volatile const u8 *addr)
{
	return native_vga_readb(addr);
}

#define PV_IO_OPS {							\
	.boot_writeb	= BOOT_NATIVE_WRITEB,				\
	.boot_writew	= BOOT_NATIVE_WRITEW,				\
	.boot_writel	= BOOT_NATIVE_WRITEL,				\
	.boot_writell	= BOOT_NATIVE_WRITELL,				\
	.boot_readb	= BOOT_NATIVE_READB,				\
	.boot_readw	= BOOT_NATIVE_READW,				\
	.boot_readl	= BOOT_NATIVE_READL,				\
	.boot_readll	= BOOT_NATIVE_READLL,				\
									\
	.writeb	= NATIVE_WRITEB,					\
	.writew	= NATIVE_WRITEW,					\
	.writel	= NATIVE_WRITEL,					\
	.writell = NATIVE_WRITELL,					\
	.readb	= NATIVE_READB,						\
	.readw	= NATIVE_READW,						\
	.readl	= NATIVE_READL,						\
	.readll	= NATIVE_READLL,					\
									\
	.inb	= native_inb,						\
	.outb	= native_outb,						\
	.outw	= native_outw,						\
	.inw	= native_inw,						\
	.outl	= native_outl,						\
	.inl	= native_inl,						\
									\
	.outsb	= NATIVE_OUTSB,						\
	.outsw	= NATIVE_OUTSW,						\
	.outsl	= NATIVE_OUTSL,						\
	.insb	= NATIVE_INSB,						\
	.insw	= NATIVE_INSW,						\
	.insl	= NATIVE_INSL,						\
									\
	.conf_inb	= native_conf_inb,				\
	.conf_inw	= native_conf_inw,				\
	.conf_inl	= native_conf_inl,				\
	.conf_outb	= native_conf_outb,				\
	.conf_outw	= native_conf_outw,				\
	.conf_outl	= native_conf_outl,				\
									\
	.scr_writew	= do_scr_writew,				\
	.scr_readw	= do_scr_readw,					\
	.vga_writeb	= do_vga_writeb,				\
	.vga_readb	= do_vga_readb,					\
									\
	.pci_init	= native_arch_pci_init,				\
}
pv_io_ops_t pv_io_ops = PV_IO_OPS;
EXPORT_SYMBOL(pv_io_ops);
/* boot-time copy of pv_io_ops: functions have physical addresses */
static pv_io_ops_t boot_pv_io_ops = PV_IO_OPS;
pv_io_ops_t *cur_pv_io_ops = &boot_pv_io_ops;

static void pv_ops_to_boot_pv_ops(void *boot_pv_ops[], int entries_num)
{
	void **pv_ops = boot_native_vp_to_pp(boot_pv_ops);
	void *op;
	int entry;

	for (entry = 0; entry < entries_num; entry++) {
		op = pv_ops[entry];
		if (op == NULL)
			continue;
		op = boot_native_vp_to_pp(op);
		pv_ops[entry] = op;
	}
}
static inline void pv_v2p_ops_to_boot_ops(void)
{
	pv_ops_to_boot_pv_ops((void **)&boot_pv_v2p_ops,
				sizeof(boot_pv_v2p_ops) / sizeof(void *));
	/* switch PV_V2P_OPS pointer to physical functions entries */
	boot_native_get_vo_value(cur_pv_v2p_ops) = &boot_pv_v2p_ops;
}
static inline void pv_boot_ops_to_boot_ops(void)
{
	pv_ops_to_boot_pv_ops((void **)&boot_pv_boot_ops,
				sizeof(boot_pv_boot_ops) / sizeof(void *));
	/* switch PV_V2P_OPS pointer to physical functions entries */
	boot_native_get_vo_value(cur_pv_boot_ops) = &boot_pv_boot_ops;
}
static inline void pv_cpu_ops_to_boot_ops(void)
{
	pv_ops_to_boot_pv_ops((void **)&boot_pv_cpu_ops,
				sizeof(boot_pv_cpu_ops) / sizeof(void *));
	/* switch PV_V2P_OPS pointer to physical functions entries */
	boot_native_get_vo_value(cur_pv_cpu_ops) = &boot_pv_cpu_ops;
}
static inline void pv_apic_ops_to_boot_ops(void)
{
	pv_ops_to_boot_pv_ops((void **)&boot_pv_apic_ops,
				sizeof(boot_pv_apic_ops) / sizeof(void *));
	/* switch PV_V2P_OPS pointer to physical functions entries */
	boot_native_get_vo_value(cur_pv_apic_ops) = &boot_pv_apic_ops;
}
static inline void pv_epic_ops_to_boot_ops(void)
{
	pv_ops_to_boot_pv_ops((void **)&boot_pv_epic_ops,
				sizeof(boot_pv_epic_ops) / sizeof(void *));
	/* switch PV_V2P_OPS pointer to physical functions entries */
	boot_native_get_vo_value(cur_pv_epic_ops) = &boot_pv_epic_ops;
}
static inline void pv_mmu_ops_to_boot_ops(void)
{
	pv_ops_to_boot_pv_ops((void **)&boot_pv_mmu_ops,
				sizeof(boot_pv_mmu_ops) / sizeof(void *));
	/* switch PV_V2P_OPS pointer to physical functions entries */
	boot_native_get_vo_value(cur_pv_mmu_ops) = &boot_pv_mmu_ops;
}
static inline void pv_io_ops_to_boot_ops(void)
{
	pv_ops_to_boot_pv_ops((void **)&boot_pv_io_ops,
				sizeof(boot_pv_io_ops) / sizeof(void *));
	/* switch PV_IO_OPS pointer to physical functions entries */
	boot_native_get_vo_value(cur_pv_io_ops) = &boot_pv_io_ops;
}

static inline void boot_pv_v2p_ops_to_ops(void)
{
	/* switch PV_V2P_OPS pointer to virtual functions entries */
	boot_native_get_vo_value(cur_pv_v2p_ops) = &pv_v2p_ops;
}
static inline void boot_pv_boot_ops_to_ops(void)
{
	/* switch PV_V2P_OPS pointer to virtual functions entries */
	boot_native_get_vo_value(cur_pv_boot_ops) = &pv_boot_ops;
}
static inline void boot_pv_cpu_ops_to_ops(void)
{
	/* switch PV_V2P_OPS pointer to virtual functions entries */
	boot_native_get_vo_value(cur_pv_cpu_ops) = &pv_cpu_ops;
}
static inline void boot_pv_apic_ops_to_ops(void)
{
	/* switch PV_V2P_OPS pointer to virtual functions entries */
	boot_native_get_vo_value(cur_pv_apic_ops) = &pv_apic_ops;
}
static inline void boot_pv_epic_ops_to_ops(void)
{
	/* switch PV_V2P_OPS pointer to virtual functions entries */
	boot_native_get_vo_value(cur_pv_epic_ops) = &pv_epic_ops;
}
static inline void boot_pv_mmu_ops_to_ops(void)
{
	/* switch PV_V2P_OPS pointer to virtual functions entries */
	boot_native_get_vo_value(cur_pv_mmu_ops) = &pv_mmu_ops;
}
static inline void boot_pv_io_ops_to_ops(void)
{
	/* switch PV_IO_OPS pointer to virtual functions entries */
	boot_native_get_vo_value(cur_pv_io_ops) = &pv_io_ops;
}
void native_pv_ops_to_boot_ops(void)
{
	pv_v2p_ops_to_boot_ops();
	pv_boot_ops_to_boot_ops();
	pv_cpu_ops_to_boot_ops();
	pv_apic_ops_to_boot_ops();
	pv_epic_ops_to_boot_ops();
	pv_mmu_ops_to_boot_ops();
	pv_io_ops_to_boot_ops();
}
void native_boot_pv_ops_to_ops(void)
{
	boot_pv_v2p_ops_to_ops();
	boot_pv_boot_ops_to_ops();
	boot_pv_cpu_ops_to_ops();
	boot_pv_apic_ops_to_ops();
	boot_pv_epic_ops_to_ops();
	boot_pv_mmu_ops_to_ops();
	boot_pv_io_ops_to_ops();
}
