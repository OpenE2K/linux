/*
 * Core of KVM guest paravirt_ops implementation.
 *
 * This file contains the kvm_paravirt_ops structure itself, and the
 * implementations for:
 * - privileged instructions
 * - booting and setup
 */

#include <linux/kernel.h>

#include <asm/pgtable.h>
#include <asm/e2k_sic.h>
#include <asm/process.h>
#include <asm/kvm/sge.h>
#include <asm/tlbflush.h>
#include <asm/traps.h> /* user_trap_init() */
#include <asm/trap_table.h>
#include <asm/switch_to.h>

#include <asm/paravirt/pv_ops.h>
#include <asm/kvm/hypercall.h>
#include <asm/kvm/cpu_regs_access.h>
#include <asm/kvm/aau_regs_access.h>
#include <asm/kvm/mmu_regs_access.h>
#include <asm/kvm/guest/io.h>
#include <asm/kvm/guest/v2p.h>
#include <asm/kvm/guest/boot.h>
#include <asm/kvm/guest/setup.h>
#include <asm/kvm/guest/cpu.h>
#include <asm/kvm/guest/traps.h>
#include <asm/kvm/guest/process.h>
#include <asm/kvm/guest/processor.h>
#include <asm/kvm/guest/hw_stacks.h>
#include <asm/kvm/guest/regs_state.h>
#include <asm/kvm/guest/system.h>
#include <asm/kvm/guest/ptrace.h>
#include <asm/kvm/guest/sge.h>
#include <asm/kvm/guest/signal.h>
#include <asm/kvm/guest/area_alloc.h>
#include <asm/kvm/guest/mman.h>
#include <asm/kvm/guest/mmu.h>
#include <asm/kvm/guest/mmu_context.h>
#include <asm/kvm/guest/pgtable.h>
#include <asm/kvm/guest/time.h>
#include <asm/kvm/guest/timex.h>
#include <asm/kvm/guest/clkr.h>
#include <asm/kvm/guest/spinlock.h>
#include <asm/kvm/guest/string.h>
#include <asm/kvm/guest/host_printk.h>
#include <asm/kvm/guest/fast_syscalls.h>
#include <asm/kvm/guest/smp.h>
#include <asm/kvm/guest/cacheflush.h>

#include "paravirt.h"
#include "time.h"
#include "process.h"
#include "pic.h"

static const pv_info_t kvm_info __initdata = {
	.name = "KVM",
	.paravirt_enabled = 1,
	.page_offset = GUEST_PAGE_OFFSET,
	.vmalloc_start = GUEST_VMALLOC_START,
	.vmalloc_end = GUEST_VMALLOC_END,
	.vmemmap_start = GUEST_VMEMMAP_START,
	.vmemmap_end = GUEST_VMEMMAP_END,
};

static void *
BOOT_KVM_KERNEL_VA_TO_PA(void *virt_pnt, unsigned long kernel_base)
{
	return boot_kvm_kernel_va_to_pa(virt_pnt, kernel_base);
}

static void *
BOOT_KVM_FUNC_TO_PA(void *virt_pnt)
{
	return boot_kvm_func_to_pa(virt_pnt);
}

static e2k_addr_t
BOOT_KVM_VPA_TO_PA(e2k_addr_t vpa)
{
	return boot_kvm_vpa_to_pa(vpa);
}
static e2k_addr_t
BOOT_KVM_PA_TO_VPA(e2k_addr_t pa)
{
	return boot_kvm_pa_to_vpa(pa);
}

static e2k_addr_t
KVM_VPA_TO_PA(e2k_addr_t vpa)
{
	return kvm_vpa_to_pa(vpa);
}
static e2k_addr_t
KVM_PA_TO_VPA(e2k_addr_t pa)
{
	return kvm_pa_to_vpa(pa);
}

pv_v2p_ops_t kvm_v2p_ops = {
	.boot_kernel_va_to_pa = BOOT_KVM_KERNEL_VA_TO_PA,
	.boot_func_to_pa = BOOT_KVM_FUNC_TO_PA,
	.boot_vpa_to_pa = BOOT_KVM_VPA_TO_PA,
	.boot_pa_to_vpa = BOOT_KVM_PA_TO_VPA,
	.vpa_to_pa = KVM_VPA_TO_PA,
	.pa_to_vpa = KVM_PA_TO_VPA,
};

static void __init kvm_banner(void)
{
	printk(KERN_INFO "Booting paravirtualized guest kernel on %s\n",
	       pv_info.name);
}

pv_init_ops_t kvm_init_ops = {
	.banner = kvm_banner,
	.set_mach_type_id = kvm_set_mach_type_id,
	.print_machine_type_info = kvm_print_machine_type_info,
};

static void kvm_debug_outb(u8 byte, u16 port)
{
	KVM_DEBUG_OUTB(byte, port);
}
static u8 kvm_debug_inb(u16 port)
{
	return KVM_DEBUG_INB(port);
}
static u32 kvm_debug_inl(u16 port)
{
	return KVM_DEBUG_INL(port);
}

static const struct pv_boot_ops kvm_boot_ops __initdata = {
	.boot_setup_machine_id = boot_kvm_setup_machine_id,
	.boot_loader_probe_memory = boot_kvm_probe_memory,
	.boot_get_bootblock_size = boot_kvm_get_bootblock_size,
	.boot_cpu_relax = boot_kvm_cpu_relax,
#ifdef	CONFIG_SMP
	.boot_smp_cpu_config = boot_kvm_smp_cpu_config,
	.boot_smp_node_config = boot_kvm_smp_node_config,
#endif	/* CONFIG_SMP */
	.boot_reserve_all_bootmem = boot_kvm_reserve_all_bootmem,
	.boot_map_all_bootmem = boot_kvm_map_all_bootmem,
	.boot_map_needful_to_equal_virt_area =
		boot_kvm_map_needful_to_equal_virt_area,
	.boot_kernel_switch_to_virt = boot_kvm_switch_to_virt,
	.boot_clear_bss = boot_kvm_clear_bss,
	.boot_check_bootblock = boot_kvm_check_bootblock,
	.init_terminate_boot_init = init_kvm_terminate_boot_init,
	.boot_parse_param = boot_kvm_parse_param,
	.boot_debug_cons_outb = kvm_debug_outb,
	.boot_debug_cons_inb = kvm_debug_inb,
	.boot_debug_cons_inl = kvm_debug_inl,
	.debug_cons_outb = kvm_debug_outb,
	.debug_cons_inb = kvm_debug_inb,
	.debug_cons_inl = kvm_debug_inl,
	.do_boot_panic = boot_kvm_panic,
};

static unsigned long kvm_read_OSCUD_lo_reg_value(void)
{
	return KVM_READ_OSCUD_LO_REG_VALUE();
}

static unsigned long kvm_read_OSCUD_hi_reg_value(void)
{
	return KVM_READ_OSCUD_HI_REG_VALUE();
}

static void kvm_write_OSCUD_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_OSCUD_LO_REG_VALUE(reg_value);
}

static void kvm_write_OSCUD_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_OSCUD_HI_REG_VALUE(reg_value);
}

static unsigned long kvm_read_OSGD_lo_reg_value(void)
{
	return KVM_READ_OSGD_LO_REG_VALUE();
}

static unsigned long kvm_read_OSGD_hi_reg_value(void)
{
	return KVM_READ_OSGD_HI_REG_VALUE();
}

static void kvm_write_OSGD_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_OSGD_LO_REG_VALUE(reg_value);
}

static void kvm_write_OSGD_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_OSGD_HI_REG_VALUE(reg_value);
}

static unsigned long kvm_read_CUD_lo_reg_value(void)
{
	return KVM_READ_CUD_LO_REG_VALUE();
}

static unsigned long kvm_read_CUD_hi_reg_value(void)
{
	return KVM_READ_CUD_HI_REG_VALUE();
}

static void kvm_write_CUD_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_CUD_LO_REG_VALUE(reg_value);
}

static void kvm_write_CUD_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_CUD_HI_REG_VALUE(reg_value);
}

static unsigned long kvm_read_GD_lo_reg_value(void)
{
	return KVM_READ_GD_LO_REG_VALUE();
}

static unsigned long kvm_read_GD_hi_reg_value(void)
{
	return KVM_READ_GD_HI_REG_VALUE();
}

static void kvm_write_GD_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_GD_LO_REG_VALUE(reg_value);
}

static void kvm_write_GD_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_GD_HI_REG_VALUE(reg_value);
}

static unsigned long kvm_read_PSP_lo_reg_value(void)
{
	return KVM_READ_PSP_LO_REG_VALUE();
}
static unsigned long kvm_read_PSP_hi_reg_value(void)
{
	return KVM_READ_PSP_HI_REG_VALUE();
}
static void kvm_write_PSP_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_PSP_LO_REG_VALUE(reg_value);
}
static void kvm_write_PSP_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_PSP_HI_REG_VALUE(reg_value);
}
static unsigned long kvm_read_PSHTP_reg_value(void)
{
	return KVM_READ_PSHTP_REG_VALUE();
}
static void kvm_write_PSHTP_reg_value(unsigned long reg_value)
{
	KVM_WRITE_PSHTP_REG_VALUE(reg_value);
}

static unsigned long kvm_read_PCSP_lo_reg_value(void)
{
	return KVM_READ_PCSP_LO_REG_VALUE();
}
static unsigned long kvm_read_PCSP_hi_reg_value(void)
{
	return KVM_READ_PCSP_HI_REG_VALUE();
}
static void kvm_write_PCSP_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_PCSP_LO_REG_VALUE(reg_value);
}
static void kvm_write_PCSP_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_PCSP_HI_REG_VALUE(reg_value);
}
static int kvm_read_PCSHTP_reg_svalue(void)
{
	return KVM_READ_PCSHTP_REG_SVALUE();
}
static void kvm_write_PCSHTP_reg_svalue(int reg_value)
{
	KVM_WRITE_PCSHTP_REG_SVALUE(reg_value);
}

static unsigned long kvm_read_CR0_lo_reg_value(void)
{
	return KVM_READ_CR0_LO_REG_VALUE();
}
static unsigned long kvm_read_CR0_hi_reg_value(void)
{
	return KVM_READ_CR0_HI_REG_VALUE();
}
static unsigned long kvm_read_CR1_lo_reg_value(void)
{
	return KVM_READ_CR1_LO_REG_VALUE();
}
static unsigned long kvm_read_CR1_hi_reg_value(void)
{
	return KVM_READ_CR1_HI_REG_VALUE();
}
static void kvm_write_CR0_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_CR0_LO_REG_VALUE(reg_value);
}
static void kvm_write_CR0_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_CR0_HI_REG_VALUE(reg_value);
}
static void kvm_write_CR1_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_CR1_LO_REG_VALUE(reg_value);
}
static void kvm_write_CR1_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_CR1_HI_REG_VALUE(reg_value);
}
static unsigned long kvm_read_USD_lo_reg_value(void)
{
	return KVM_READ_USD_LO_REG_VALUE();
}
static unsigned long kvm_read_USD_hi_reg_value(void)
{
	return KVM_READ_USD_HI_REG_VALUE();
}
static void kvm_write_USD_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_USD_LO_REG_VALUE(reg_value);
}
static void kvm_write_USD_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_USD_HI_REG_VALUE(reg_value);
}

static unsigned long kvm_read_WD_reg_value(void)
{
	return KVM_READ_WD_REG_VALUE();
}
static void kvm_write_WD_reg_value(unsigned long reg_value)
{
	KVM_WRITE_WD_REG_VALUE(reg_value);
}

static unsigned int kvm_read_UPSR_reg_value(void)
{
	return KVM_READ_UPSR_REG_VALUE();
}
static void kvm_write_UPSR_reg_value(unsigned int reg_value)
{
	KVM_WRITE_UPSR_REG_VALUE(reg_value);
}

static unsigned int kvm_read_PSR_reg_value(void)
{
	return KVM_READ_PSR_REG_VALUE();
}
static void kvm_write_PSR_reg_value(unsigned int reg_value)
{
	KVM_WRITE_PSR_REG_VALUE(reg_value);
}

static unsigned long kvm_read_CTPR_reg_value(int reg_no)
{
	switch (reg_no) {
	case 1: return KVM_READ_CTPR_REG_VALUE(1);
	case 2: return KVM_READ_CTPR_REG_VALUE(2);
	case 3: return KVM_READ_CTPR_REG_VALUE(3);
	default:
		panic("kvm_read_CTPR_reg_value() invalid CTPR # %d\n",
			reg_no);
	}
	return -1;
}

static void kvm_write_CTPR_reg_value(int reg_no, unsigned long reg_value)
{
	switch (reg_no) {
	case 1:
		KVM_WRITE_CTPR_REG_VALUE(1, reg_value);
		break;
	case 2:
		KVM_WRITE_CTPR_REG_VALUE(2, reg_value);
		break;
	case 3:
		KVM_WRITE_CTPR_REG_VALUE(3, reg_value);
		break;
	default:
		panic("kvm_write_CTPR_reg_value() invalid CTPR # %d\n",
			reg_no);
	}
}

static unsigned long kvm_read_SBR_reg_value(void)
{
	return KVM_READ_SBR_REG_VALUE();
}

static void kvm_write_SBR_reg_value(unsigned long reg_value)
{
	KVM_WRITE_SBR_REG_VALUE(reg_value);
}

#ifdef	NEED_PARAVIRT_LOOP_REGISTERS
static unsigned long kvm_read_LSR_reg_value(void)
{
	return KVM_READ_LSR_REG_VALUE();
}

static void kvm_write_LSR_reg_value(unsigned long reg_value)
{
	KVM_WRITE_LSR_REG_VALUE(reg_value);
}

static unsigned long kvm_read_ILCR_reg_value(void)
{
	return KVM_READ_ILCR_REG_VALUE();
}

static void kvm_write_ILCR_reg_value(unsigned long reg_value)
{
	KVM_WRITE_ILCR_REG_VALUE(reg_value);
}
#endif	/* NEED_PARAVIRT_LOOP_REGISTERS */

static unsigned long kvm_read_OSR0_reg_value(void)
{
	return KVM_READ_OSR0_REG_VALUE();
}

static void kvm_write_OSR0_reg_value(unsigned long reg_value)
{
	KVM_WRITE_OSR0_REG_VALUE(reg_value);
}

static unsigned int kvm_read_OSEM_reg_value(void)
{
	return KVM_READ_OSEM_REG_VALUE();
}

static void kvm_write_OSEM_reg_value(unsigned int reg_value)
{
	KVM_WRITE_OSEM_REG_VALUE(reg_value);
}

static unsigned int kvm_read_BGR_reg_value(void)
{
	return KVM_READ_BGR_REG_VALUE();
}

static void kvm_write_BGR_reg_value(unsigned int reg_value)
{
	KVM_WRITE_BGR_REG_VALUE(reg_value);
}

static unsigned long kvm_read_CLKR_reg_value(void)
{
	return KVM_READ_CLKR_REG_VALUE();
}
static unsigned long kvm_read_CU_HW0_reg_value(void)
{
	return KVM_READ_CU_HW0_REG_VALUE();
}
static unsigned long kvm_read_CU_HW1_reg_value(void)
{
	return KVM_READ_CU_HW1_REG_VALUE();
}
static void kvm_write_CU_HW0_reg_value(unsigned long reg_value)
{
	KVM_WRITE_CU_HW0_REG_VALUE(reg_value);
}
static void kvm_write_CU_HW1_reg_value(unsigned long reg_value)
{
	KVM_WRITE_CU_HW1_REG_VALUE(reg_value);
}

static unsigned long kvm_read_RPR_lo_reg_value(void)
{
	return KVM_READ_RPR_LO_REG_VALUE();
}

static unsigned long kvm_read_RPR_hi_reg_value(void)
{
	return KVM_READ_RPR_HI_REG_VALUE();
}

static void kvm_write_RPR_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_RPR_LO_REG_VALUE(reg_value);
}

static void kvm_write_RPR_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_RPR_HI_REG_VALUE(reg_value);
}

static unsigned long kvm_read_SBBP_reg_value(void)
{
	return KVM_READ_SBBP_REG_VALUE();
}

static unsigned long kvm_read_IP_reg_value(void)
{
	return KVM_READ_IP_REG_VALUE();
}

static unsigned int kvm_read_DIBCR_reg_value(void)
{
	return KVM_READ_DIBCR_REG_VALUE();
}

static unsigned int kvm_read_DIBSR_reg_value(void)
{
	return KVM_READ_DIBSR_REG_VALUE();
}

static unsigned long kvm_read_DIMCR_reg_value(void)
{
	return KVM_READ_DIMCR_REG_VALUE();
}

static unsigned long kvm_read_DIBAR0_reg_value(void)
{
	return KVM_READ_DIBAR0_REG_VALUE();
}

static unsigned long kvm_read_DIBAR1_reg_value(void)
{
	return KVM_READ_DIBAR1_REG_VALUE();
}

static unsigned long kvm_read_DIBAR2_reg_value(void)
{
	return KVM_READ_DIBAR2_REG_VALUE();
}

static unsigned long kvm_read_DIBAR3_reg_value(void)
{
	return KVM_READ_DIBAR3_REG_VALUE();
}

static unsigned long kvm_read_DIMAR0_reg_value(void)
{
	return KVM_READ_DIMAR0_REG_VALUE();
}

static unsigned long kvm_read_DIMAR1_reg_value(void)
{
	return KVM_READ_DIMAR1_REG_VALUE();
}

static void kvm_write_DIBCR_reg_value(unsigned int reg_value)
{
	KVM_WRITE_DIBCR_REG_VALUE(reg_value);
}

static void kvm_write_DIBSR_reg_value(unsigned int reg_value)
{
	KVM_WRITE_DIBSR_REG_VALUE(reg_value);
}

static void kvm_write_DIMCR_reg_value(unsigned long reg_value)
{
	KVM_WRITE_DIMCR_REG_VALUE(reg_value);
}

static void kvm_write_DIBAR0_reg_value(unsigned long reg_value)
{
	KVM_WRITE_DIBAR0_REG_VALUE(reg_value);
}

static void kvm_write_DIBAR1_reg_value(unsigned long reg_value)
{
	KVM_WRITE_DIBAR1_REG_VALUE(reg_value);
}

static void kvm_write_DIBAR2_reg_value(unsigned long reg_value)
{
	KVM_WRITE_DIBAR2_REG_VALUE(reg_value);
}

static void kvm_write_DIBAR3_reg_value(unsigned long reg_value)
{
	KVM_WRITE_DIBAR3_REG_VALUE(reg_value);
}

static void kvm_write_DIMAR0_reg_value(unsigned long reg_value)
{
	KVM_WRITE_DIMAR0_REG_VALUE(reg_value);
}

static void kvm_write_DIMAR1_reg_value(unsigned long reg_value)
{
	KVM_WRITE_DIMAR1_REG_VALUE(reg_value);
}

static unsigned long kvm_read_CUTD_reg_value(void)
{
	return KVM_READ_CUTD_REG_VALUE();
}

static void kvm_write_CUTD_reg_value(unsigned long reg_value)
{
	KVM_WRITE_CUTD_REG_VALUE(reg_value);
}

static unsigned int kvm_read_CUIR_reg_value(void)
{
	return KVM_READ_CUIR_REG_VALUE();
}

static unsigned int kvm_read_PFPFR_reg_value(void)
{
	return KVM_READ_PFPFR_REG_VALUE();
}

static void kvm_write_PFPFR_reg_value(unsigned int reg_value)
{
	KVM_WRITE_PFPFR_REG_VALUE(reg_value);
}

static unsigned int kvm_read_FPCR_reg_value(void)
{
	return KVM_READ_FPCR_REG_VALUE();
}

static void kvm_write_FPCR_reg_value(unsigned int reg_value)
{
	KVM_WRITE_FPCR_REG_VALUE(reg_value);
}

static unsigned int kvm_read_FPSR_reg_value(void)
{
	return KVM_READ_FPSR_REG_VALUE();
}

static void kvm_write_FPSR_reg_value(unsigned int reg_value)
{
	KVM_WRITE_FPSR_REG_VALUE(reg_value);
}

static unsigned long kvm_read_CS_lo_reg_value(void)
{
	return KVM_READ_CS_LO_REG_VALUE();
}

static unsigned long kvm_read_CS_hi_reg_value(void)
{
	return KVM_READ_CS_HI_REG_VALUE();
}

static unsigned long kvm_read_DS_lo_reg_value(void)
{
	return KVM_READ_DS_LO_REG_VALUE();
}

static unsigned long kvm_read_DS_hi_reg_value(void)
{
	return KVM_READ_DS_HI_REG_VALUE();
}

static unsigned long kvm_read_ES_lo_reg_value(void)
{
	return KVM_READ_ES_LO_REG_VALUE();
}

static unsigned long kvm_read_ES_hi_reg_value(void)
{
	return KVM_READ_ES_HI_REG_VALUE();
}

static unsigned long kvm_read_FS_lo_reg_value(void)
{
	return KVM_READ_FS_LO_REG_VALUE();
}

static unsigned long kvm_read_FS_hi_reg_value(void)
{
	return KVM_READ_FS_HI_REG_VALUE();
}

static unsigned long kvm_read_GS_lo_reg_value(void)
{
	return KVM_READ_GS_LO_REG_VALUE();
}

static unsigned long kvm_read_GS_hi_reg_value(void)
{
	return KVM_READ_GS_HI_REG_VALUE();
}

static unsigned long kvm_read_SS_lo_reg_value(void)
{
	return KVM_READ_SS_LO_REG_VALUE();
}

static unsigned long kvm_read_SS_hi_reg_value(void)
{
	return KVM_READ_SS_HI_REG_VALUE();
}

static void kvm_write_CS_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_CS_LO_REG_VALUE(reg_value);
}

static void kvm_write_CS_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_CS_HI_REG_VALUE(reg_value);
}

static void kvm_write_DS_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_DS_LO_REG_VALUE(reg_value);
}

static void kvm_write_DS_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_DS_HI_REG_VALUE(reg_value);
}

static void kvm_write_ES_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_ES_LO_REG_VALUE(reg_value);
}

static void kvm_write_ES_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_ES_HI_REG_VALUE(reg_value);
}

static void kvm_write_FS_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_FS_LO_REG_VALUE(reg_value);
}

static void kvm_write_FS_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_FS_HI_REG_VALUE(reg_value);
}

static void kvm_write_GS_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_GS_LO_REG_VALUE(reg_value);
}

static void kvm_write_GS_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_GS_HI_REG_VALUE(reg_value);
}

static void kvm_write_SS_lo_reg_value(unsigned long reg_value)
{
	KVM_WRITE_SS_LO_REG_VALUE(reg_value);
}

static void kvm_write_SS_hi_reg_value(unsigned long reg_value)
{
	KVM_WRITE_SS_HI_REG_VALUE(reg_value);
}

static unsigned long kvm_read_IDR_reg_value(void)
{
	return KVM_READ_IDR_REG_VALUE();
}

static unsigned int kvm_read_CORE_MODE_reg_value(void)
{
	return KVM_READ_CORE_MODE_REG_VALUE();
}
static void kvm_write_CORE_MODE_reg_value(unsigned int modes)
{
	return KVM_WRITE_CORE_MODE_REG_VALUE(modes);
}

static void kvm_put_updated_cpu_regs_flags(unsigned long flags)
{
	KVM_PUT_UPDATED_CPU_REGS_FLAGS(flags);
}

static unsigned int pv_kvm_read_aasr_reg_value(void)
{
	return kvm_read_aasr_reg_value();
}
static void pv_kvm_write_aasr_reg_value(unsigned int reg_value)
{
	kvm_write_aasr_reg_value(reg_value);
}
static unsigned int pv_kvm_read_aafstr_reg_value(void)
{
	return kvm_read_aafstr_reg_value();
}
static void pv_kvm_write_aafstr_reg_value(unsigned int reg_value)
{
	kvm_write_aafstr_reg_value(reg_value);
}

static void kvm_flush_stacks(void)
{
	KVM_FLUSHCPU;
}
static void kvm_flush_regs_stack(void)
{
	KVM_FLUSHR;
}
static void kvm_flush_chain_stack(void)
{
	KVM_FLUSHC;
}
static void
do_free_old_kernel_hardware_stacks(void)
{
	kvm_free_old_kernel_hardware_stacks();
}
static void
kvm_switch_to_expanded_proc_stack(long delta_size, long delta_offset,
					bool decr_k_ps)
{
	kvm_do_switch_to_expanded_proc_stack(delta_size, delta_offset,
						decr_k_ps);
}
static void
kvm_switch_to_expanded_chain_stack(long delta_size, long delta_offset,
					bool decr_k_pcs)
{
	kvm_do_switch_to_expanded_chain_stack(delta_size, delta_offset,
						decr_k_pcs);
}
static void
do_stack_bounds_trap_enable(void)
{
	kvm_stack_bounds_trap_enable();
}
static bool
do_is_proc_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return kvm_is_proc_stack_bounds(ti, regs);
}
static bool
do_is_chain_stack_bounds(struct thread_info *ti, struct pt_regs *regs)
{
	return kvm_is_chain_stack_bounds(ti, regs);
}
static void
guest_instr_page_fault(struct pt_regs *regs, tc_fault_type_t ftype,
			const int async_instr)
{
	kvm_instr_page_fault(regs, ftype, async_instr);
}
static unsigned long
do_mmio_page_fault(struct pt_regs *regs, struct trap_cellar *tcellar)
{
	return kvm_mmio_page_fault(regs, (trap_cellar_t *)tcellar);
}

static void kvm_copy_stacks_to_memory(void)
{
	KVM_COPY_STACKS_TO_MEMORY();
}

static __interrupt void
kvm_restore_kernel_gregs_in_syscall(struct thread_info *ti)
{
	KVM_RESTORE_KERNEL_GREGS_IN_SYSCALL(ti);
}

static unsigned long
guest_fast_tagged_memory_copy(void *dst, const void *src, size_t len,
		unsigned long strd_opcode, unsigned long ldrd_opcode,
		int prefetch)
{
	return kvm_fast_tagged_memory_copy(dst, src, len,
				strd_opcode, ldrd_opcode, prefetch);
}
static unsigned long
guest_fast_tagged_memory_set(void *addr, u64 val, u64 tag,
		size_t len, u64 strd_opcode)
{
	return kvm_fast_tagged_memory_set(addr, val, tag, len, strd_opcode);
}

static unsigned long
guest_extract_tags_32(u16 *dst, const void *src)
{
	return kvm_extract_tags_32(dst, src);
}
#ifdef	CONFIG_SMP

static void
do_smp_flush_tlb_all(void)
{
	kvm_smp_flush_tlb_all();
}
static void
do_smp_flush_tlb_mm(struct mm_struct *mm)
{
	kvm_smp_flush_tlb_mm(mm);
}
static void
do_smp_flush_tlb_page(struct vm_area_struct *vma, e2k_addr_t addr)
{
	kvm_smp_flush_tlb_page(vma, addr);
}
static void
do_smp_flush_tlb_range(struct mm_struct *mm, e2k_addr_t start, e2k_addr_t end)
{
	kvm_smp_flush_tlb_range(mm, start, end);
}
static void
do_smp_flush_pmd_tlb_range(struct mm_struct *mm, e2k_addr_t start,
		e2k_addr_t end)
{
	kvm_smp_flush_pmd_tlb_range(mm, start, end);
}
static void
do_smp_flush_tlb_range_and_pgtables(struct mm_struct *mm,
				e2k_addr_t start, e2k_addr_t end)
{
	kvm_smp_flush_tlb_range_and_pgtables(mm, start, end);
}
static void
do_smp_flush_icache_range(e2k_addr_t start, e2k_addr_t end)
{
	kvm_smp_flush_icache_range(start, end);
}
static void
do_smp_flush_icache_range_array(void *icache_range_arr)
{
	kvm_smp_flush_icache_range_array(icache_range_arr);
}
static void
do_smp_flush_icache_page(struct vm_area_struct *vma, struct page *page)
{
	kvm_smp_flush_icache_page(vma, page);
}
static void
do_smp_flush_icache_all(void)
{
	kvm_smp_flush_icache_all();
}
static void
do_smp_flush_icache_kernel_line(e2k_addr_t addr)
{
	kvm_smp_flush_icache_kernel_line(addr);
}
#endif	/* CONFIG_SMP */

static const pv_cpu_ops_t kvm_cpu_ops __initdata = {
	.read_OSCUD_lo_reg_value = kvm_read_OSCUD_lo_reg_value,
	.read_OSCUD_hi_reg_value = kvm_read_OSCUD_hi_reg_value,
	.write_OSCUD_lo_reg_value = kvm_write_OSCUD_lo_reg_value,
	.write_OSCUD_hi_reg_value = kvm_write_OSCUD_hi_reg_value,
	.read_OSGD_lo_reg_value = kvm_read_OSGD_lo_reg_value,
	.read_OSGD_hi_reg_value = kvm_read_OSGD_hi_reg_value,
	.write_OSGD_lo_reg_value = kvm_write_OSGD_lo_reg_value,
	.write_OSGD_hi_reg_value = kvm_write_OSGD_hi_reg_value,
	.read_CUD_lo_reg_value = kvm_read_CUD_lo_reg_value,
	.read_CUD_hi_reg_value = kvm_read_CUD_hi_reg_value,
	.write_CUD_lo_reg_value = kvm_write_CUD_lo_reg_value,
	.write_CUD_hi_reg_value = kvm_write_CUD_hi_reg_value,
	.read_GD_lo_reg_value = kvm_read_GD_lo_reg_value,
	.read_GD_hi_reg_value = kvm_read_GD_hi_reg_value,
	.write_GD_lo_reg_value = kvm_write_GD_lo_reg_value,
	.write_GD_hi_reg_value = kvm_write_GD_hi_reg_value,
	.read_PSP_lo_reg_value = kvm_read_PSP_lo_reg_value,
	.read_PSP_hi_reg_value = kvm_read_PSP_hi_reg_value,
	.write_PSP_lo_reg_value = kvm_write_PSP_lo_reg_value,
	.write_PSP_hi_reg_value = kvm_write_PSP_hi_reg_value,
	.read_PSHTP_reg_value = kvm_read_PSHTP_reg_value,
	.write_PSHTP_reg_value = kvm_write_PSHTP_reg_value,
	.read_PCSP_lo_reg_value = kvm_read_PCSP_lo_reg_value,
	.read_PCSP_hi_reg_value = kvm_read_PCSP_hi_reg_value,
	.write_PCSP_lo_reg_value = kvm_write_PCSP_lo_reg_value,
	.write_PCSP_hi_reg_value = kvm_write_PCSP_hi_reg_value,
	.read_PCSHTP_reg_value = kvm_read_PCSHTP_reg_svalue,
	.write_PCSHTP_reg_value = kvm_write_PCSHTP_reg_svalue,
	.read_CR0_lo_reg_value = kvm_read_CR0_lo_reg_value,
	.read_CR0_hi_reg_value = kvm_read_CR0_hi_reg_value,
	.read_CR1_lo_reg_value = kvm_read_CR1_lo_reg_value,
	.read_CR1_hi_reg_value = kvm_read_CR1_hi_reg_value,
	.write_CR0_lo_reg_value = kvm_write_CR0_lo_reg_value,
	.write_CR0_hi_reg_value = kvm_write_CR0_hi_reg_value,
	.write_CR1_lo_reg_value = kvm_write_CR1_lo_reg_value,
	.write_CR1_hi_reg_value = kvm_write_CR1_hi_reg_value,
	.read_CTPR_reg_value = kvm_read_CTPR_reg_value,
	.write_CTPR_reg_value = kvm_write_CTPR_reg_value,
	.read_USD_lo_reg_value = kvm_read_USD_lo_reg_value,
	.read_USD_hi_reg_value = kvm_read_USD_hi_reg_value,
	.write_USD_lo_reg_value = kvm_write_USD_lo_reg_value,
	.write_USD_hi_reg_value = kvm_write_USD_hi_reg_value,
	.read_SBR_reg_value = kvm_read_SBR_reg_value,
	.write_SBR_reg_value = kvm_write_SBR_reg_value,
	.read_WD_reg_value = kvm_read_WD_reg_value,
	.write_WD_reg_value = kvm_write_WD_reg_value,
#ifdef	NEED_PARAVIRT_LOOP_REGISTERS
	.read_LSR_reg_value = kvm_read_LSR_reg_value,
	.write_LSR_reg_value = kvm_write_LSR_reg_value,
	.read_ILCR_reg_value = kvm_read_ILCR_reg_value,
	.write_ILCR_reg_value = kvm_write_ILCR_reg_value,
#endif	/* NEED_PARAVIRT_LOOP_REGISTERS */
	.read_OSR0_reg_value = kvm_read_OSR0_reg_value,
	.write_OSR0_reg_value = kvm_write_OSR0_reg_value,
	.read_OSEM_reg_value = kvm_read_OSEM_reg_value,
	.write_OSEM_reg_value = kvm_write_OSEM_reg_value,
	.read_BGR_reg_value = kvm_read_BGR_reg_value,
	.write_BGR_reg_value = kvm_write_BGR_reg_value,
	.read_CLKR_reg_value = kvm_read_CLKR_reg_value,
	.read_CU_HW0_reg_value = kvm_read_CU_HW0_reg_value,
	.read_CU_HW1_reg_value = kvm_read_CU_HW1_reg_value,
	.write_CU_HW0_reg_value = kvm_write_CU_HW0_reg_value,
	.write_CU_HW1_reg_value = kvm_write_CU_HW1_reg_value,
	.read_RPR_lo_reg_value = kvm_read_RPR_lo_reg_value,
	.read_RPR_hi_reg_value = kvm_read_RPR_hi_reg_value,
	.write_RPR_lo_reg_value = kvm_write_RPR_lo_reg_value,
	.write_RPR_hi_reg_value = kvm_write_RPR_hi_reg_value,
	.read_SBBP_reg_value = kvm_read_SBBP_reg_value,
	.read_IP_reg_value = kvm_read_IP_reg_value,
	.read_DIBCR_reg_value = kvm_read_DIBCR_reg_value,
	.read_DIBSR_reg_value = kvm_read_DIBSR_reg_value,
	.read_DIMCR_reg_value = kvm_read_DIMCR_reg_value,
	.read_DIBAR0_reg_value = kvm_read_DIBAR0_reg_value,
	.read_DIBAR1_reg_value = kvm_read_DIBAR1_reg_value,
	.read_DIBAR2_reg_value = kvm_read_DIBAR2_reg_value,
	.read_DIBAR3_reg_value = kvm_read_DIBAR3_reg_value,
	.read_DIMAR0_reg_value = kvm_read_DIMAR0_reg_value,
	.read_DIMAR1_reg_value = kvm_read_DIMAR1_reg_value,
	.write_DIBCR_reg_value = kvm_write_DIBCR_reg_value,
	.write_DIBSR_reg_value = kvm_write_DIBSR_reg_value,
	.write_DIMCR_reg_value = kvm_write_DIMCR_reg_value,
	.write_DIBAR0_reg_value = kvm_write_DIBAR0_reg_value,
	.write_DIBAR1_reg_value = kvm_write_DIBAR1_reg_value,
	.write_DIBAR2_reg_value = kvm_write_DIBAR2_reg_value,
	.write_DIBAR3_reg_value = kvm_write_DIBAR3_reg_value,
	.write_DIMAR0_reg_value = kvm_write_DIMAR0_reg_value,
	.write_DIMAR1_reg_value = kvm_write_DIMAR1_reg_value,
	.read_CUTD_reg_value = kvm_read_CUTD_reg_value,
	.read_CUIR_reg_value = kvm_read_CUIR_reg_value,
	.write_CUTD_reg_value = kvm_write_CUTD_reg_value,
	.read_UPSR_reg_value = kvm_read_UPSR_reg_value,
	.write_UPSR_reg_value = kvm_write_UPSR_reg_value,
	.write_UPSR_irq_barrier = kvm_write_UPSR_reg_value,
	.read_PSR_reg_value = kvm_read_PSR_reg_value,
	.write_PSR_reg_value = kvm_write_PSR_reg_value,
	.write_PSR_irq_barrier = kvm_write_PSR_reg_value,
	.read_PFPFR_reg_value = kvm_read_PFPFR_reg_value,
	.read_FPCR_reg_value = kvm_read_FPCR_reg_value,
	.read_FPSR_reg_value = kvm_read_FPSR_reg_value,
	.write_PFPFR_reg_value = kvm_write_PFPFR_reg_value,
	.write_FPCR_reg_value = kvm_write_FPCR_reg_value,
	.write_FPSR_reg_value = kvm_write_FPSR_reg_value,
	.read_CS_lo_reg_value = kvm_read_CS_lo_reg_value,
	.read_CS_hi_reg_value = kvm_read_CS_hi_reg_value,
	.read_DS_lo_reg_value = kvm_read_DS_lo_reg_value,
	.read_DS_hi_reg_value = kvm_read_DS_hi_reg_value,
	.read_ES_lo_reg_value = kvm_read_ES_lo_reg_value,
	.read_ES_hi_reg_value = kvm_read_ES_hi_reg_value,
	.read_FS_lo_reg_value = kvm_read_FS_lo_reg_value,
	.read_FS_hi_reg_value = kvm_read_FS_hi_reg_value,
	.read_GS_lo_reg_value = kvm_read_GS_lo_reg_value,
	.read_GS_hi_reg_value = kvm_read_GS_hi_reg_value,
	.read_SS_lo_reg_value = kvm_read_SS_lo_reg_value,
	.read_SS_hi_reg_value = kvm_read_SS_hi_reg_value,
	.write_CS_lo_reg_value = kvm_write_CS_lo_reg_value,
	.write_CS_hi_reg_value = kvm_write_CS_hi_reg_value,
	.write_DS_lo_reg_value = kvm_write_DS_lo_reg_value,
	.write_DS_hi_reg_value = kvm_write_DS_hi_reg_value,
	.write_ES_lo_reg_value = kvm_write_ES_lo_reg_value,
	.write_ES_hi_reg_value = kvm_write_ES_hi_reg_value,
	.write_FS_lo_reg_value = kvm_write_FS_lo_reg_value,
	.write_FS_hi_reg_value = kvm_write_FS_hi_reg_value,
	.write_GS_lo_reg_value = kvm_write_GS_lo_reg_value,
	.write_GS_hi_reg_value = kvm_write_GS_hi_reg_value,
	.write_SS_lo_reg_value = kvm_write_SS_lo_reg_value,
	.write_SS_hi_reg_value = kvm_write_SS_hi_reg_value,
	.read_IDR_reg_value = kvm_read_IDR_reg_value,
	.boot_read_IDR_reg_value = kvm_read_IDR_reg_value,
	.read_CORE_MODE_reg_value = kvm_read_CORE_MODE_reg_value,
	.boot_read_CORE_MODE_reg_value = kvm_read_CORE_MODE_reg_value,
	.write_CORE_MODE_reg_value = kvm_write_CORE_MODE_reg_value,
	.boot_write_CORE_MODE_reg_value = kvm_write_CORE_MODE_reg_value,
	.put_updated_cpu_regs_flags = kvm_put_updated_cpu_regs_flags,
	.read_aasr_reg_value = pv_kvm_read_aasr_reg_value,
	.write_aasr_reg_value = pv_kvm_write_aasr_reg_value,
	.read_aafstr_reg_value = pv_kvm_read_aafstr_reg_value,
	.write_aafstr_reg_value = pv_kvm_write_aafstr_reg_value,
	.flush_stacks = kvm_flush_stacks,
	.flush_regs_stack = kvm_flush_regs_stack,
	.flush_chain_stack = kvm_flush_chain_stack,
	.copy_stacks_to_memory = kvm_copy_stacks_to_memory,
	.get_active_cr0_lo_value = kvm_get_active_cr0_lo_value,
	.get_active_cr0_hi_value = kvm_get_active_cr0_hi_value,
	.get_active_cr1_lo_value = kvm_get_active_cr1_lo_value,
	.get_active_cr1_hi_value = kvm_get_active_cr1_hi_value,
	.put_active_cr0_lo_value = kvm_put_active_cr0_lo_value,
	.put_active_cr0_hi_value = kvm_put_active_cr0_hi_value,
	.put_active_cr1_lo_value = kvm_put_active_cr1_lo_value,
	.put_active_cr1_hi_value = kvm_put_active_cr1_hi_value,
	.correct_trap_psp_pcsp = kvm_correct_trap_psp_pcsp,
	.correct_scall_psp_pcsp = kvm_correct_scall_psp_pcsp,
	.correct_trap_return_ip = kvm_correct_trap_return_ip,
	.nested_kernel_return_address = kvm_nested_kernel_return_address,
	.prepare_start_thread_frames = kvm_prepare_start_thread_frames,
	.copy_kernel_stacks = kvm_copy_kernel_stacks,
	.virt_cpu_thread_init = kvm_vcpu_boot_thread_init,
	.copy_user_stacks = kvm_copy_user_stacks,
	.define_kernel_hw_stacks_sizes = kvm_define_kernel_hw_stacks_sizes,
	.define_user_hw_stacks_sizes = kvm_define_user_hw_stacks_sizes,
	.switch_to_expanded_proc_stack = kvm_switch_to_expanded_proc_stack,
	.switch_to_expanded_chain_stack = kvm_switch_to_expanded_chain_stack,
	.stack_bounds_trap_enable = do_stack_bounds_trap_enable,
	.is_proc_stack_bounds = do_is_proc_stack_bounds,
	.is_chain_stack_bounds = do_is_chain_stack_bounds,
	.release_hw_stacks = kvm_release_hw_stacks,
	.release_kernel_stacks = kvm_release_kernel_stacks,
	.register_kernel_hw_stack = kvm_register_kernel_hw_stack,
	.register_kernel_data_stack = kvm_register_kernel_data_stack,
	.unregister_kernel_hw_stack = kvm_unregister_kernel_hw_stack,
	.unregister_kernel_data_stack = kvm_unregister_kernel_data_stack,
	.kmem_area_host_chunk = kvm_kmem_area_host_chunk,
	.kmem_area_unhost_chunk = kvm_kmem_area_unhost_chunk,
	.switch_to_new_user = kvm_switch_to_new_user,
	.do_map_user_hard_stack_to_kernel = NULL,
	.do_switch_to_kernel_hardware_stacks = NULL,
	.free_old_kernel_hardware_stacks = do_free_old_kernel_hardware_stacks,
	.instr_page_fault = guest_instr_page_fault,
	.mmio_page_fault = do_mmio_page_fault,
	.do_hw_stack_bounds = kvm_do_hw_stack_bounds,
	.handle_interrupt = guest_do_interrupt,
	.init_guest_system_handlers_table = kvm_init_system_handlers_table,
	.fix_process_pt_regs = kvm_fix_process_pt_regs,
	.run_user_handler = kvm_run_user_handler,
	.trap_table_entry1 = (long (*)(int, ...))kvm_guest_ttable_entry1,
	.trap_table_entry3 = (long (*)(int, ...))kvm_guest_ttable_entry3,
	.trap_table_entry4 = (long (*)(int, ...))kvm_guest_ttable_entry4,
	.do_fast_clock_gettime = kvm_do_fast_clock_gettime,
	.fast_sys_clock_gettime = kvm_fast_sys_clock_gettime,
	.do_fast_gettimeofday = kvm_do_fast_gettimeofday,
	.fast_sys_siggetmask = kvm_fast_sys_siggetmask,
	.fast_tagged_memory_copy = guest_fast_tagged_memory_copy,
	.fast_tagged_memory_set = guest_fast_tagged_memory_set,
	.extract_tags_32 = guest_extract_tags_32,
	.save_local_glob_regs = kvm_save_local_glob_regs,
	.restore_local_glob_regs = kvm_restore_local_glob_regs,
	.restore_kernel_gregs_in_syscall = kvm_restore_kernel_gregs_in_syscall,
	.get_all_user_glob_regs = kvm_get_all_user_glob_regs,
	.arch_setup_machine = e2k_virt_setup_machine,
	.cpu_default_idle = kvm_default_idle,
	.cpu_relax = kvm_cpu_relax,
	.cpu_relax_no_resched = kvm_cpu_relax_no_resched,
#ifdef	CONFIG_SMP
	.wait_for_cpu_booting = kvm_wait_for_cpu_booting,
	.wait_for_cpu_wake_up = kvm_wait_for_cpu_wake_up,
	.activate_cpu = kvm_activate_cpu,
	.activate_all_cpus = kvm_activate_all_cpus,
	.csd_lock_wait = kvm_csd_lock_wait,
	.csd_lock = kvm_csd_lock,
	.arch_csd_lock_async = kvm_arch_csd_lock_async,
	.csd_unlock = kvm_csd_unlock,
	.setup_local_pic_virq = kvm_setup_pic_virq,
	.startup_local_pic_virq = kvm_startup_pic_virq,
	.smp_flush_tlb_all = do_smp_flush_tlb_all,
	.smp_flush_tlb_mm = do_smp_flush_tlb_mm,
	.smp_flush_tlb_page = do_smp_flush_tlb_page,
	.smp_flush_tlb_range = do_smp_flush_tlb_range,
	.smp_flush_pmd_tlb_range = do_smp_flush_pmd_tlb_range,
	.smp_flush_tlb_range_and_pgtables =
		do_smp_flush_tlb_range_and_pgtables,
	.smp_flush_icache_range = do_smp_flush_icache_range,
	.smp_flush_icache_range_array =
		do_smp_flush_icache_range_array,
	.smp_flush_icache_page = do_smp_flush_icache_page,
	.smp_flush_icache_all = do_smp_flush_icache_all,
	.smp_flush_icache_kernel_line =
		do_smp_flush_icache_kernel_line,
#endif	/* CONFIG_SMP */
	.host_printk = kvm_host_printk,
	.arch_spin_lock_slow = kvm_arch_spin_lock_slow,
	.arch_spin_locked_slow = kvm_arch_spin_locked_slow,
	.arch_spin_unlock_slow = kvm_arch_spin_unlock_slow,
	.ord_wait_read_lock_slow = kvm_wait_read_lock_slow,
	.ord_wait_write_lock_slow = kvm_wait_write_lock_slow,
	.ord_arch_read_locked_slow = kvm_arch_read_locked_slow,
	.ord_arch_write_locked_slow = kvm_arch_write_locked_slow,
	.ord_arch_read_unlock_slow = kvm_arch_read_unlock_slow,
	.ord_arch_write_unlock_slow = kvm_arch_write_unlock_slow,
};

static void kvm_WRITE_MMU_REG(mmu_addr_t mmu_addr, mmu_reg_t mmu_reg)
{
	KVM_WRITE_MMU_REG(mmu_addr, mmu_reg);
}

static mmu_reg_t kvm_READ_MMU_REG(mmu_addr_t mmu_addr)
{
	return (mmu_reg_t)KVM_READ_MMU_REG(mmu_addr);
}

/*
 * Write/read Data TLB register
 */

static void kvm_WRITE_DTLB_REG(tlb_addr_t tlb_addr, mmu_reg_t mmu_reg)
{
	KVM_WRITE_DTLB_REG(tlb_addr, mmu_reg);
}

static mmu_reg_t kvm_READ_DTLB_REG(tlb_addr_t tlb_addr)
{
	return KVM_READ_DTLB_REG(tlb_addr);
}

/*
 * Flush TLB page/entry
 */

static void
kvm_FLUSH_TLB_ENTRY(flush_op_t flush_op, flush_addr_t flush_addr)
{
	KVM_FLUSH_TLB_ENTRY(flush_op, flush_addr);
}

/*
 * Flush DCACHE line
 */

static void
kvm_FLUSH_DCACHE_LINE(e2k_addr_t virt_addr)
{
	kvm_flush_dcache_line(virt_addr);
}

/*
 * Clear DCACHE L1 set
 */
static void
kvm_CLEAR_DCACHE_L1_SET(e2k_addr_t virt_addr, unsigned long set)
{
	kvm_clear_dcache_l1_set(virt_addr, set);
}
static void
kvm_flush_DCACHE_range(void *addr, size_t len)
{
	kvm_flush_dcache_range(addr, len);
}
static void
kvm_clear_DCACHE_L1_range(void *virt_addr, size_t len)
{
	kvm_clear_dcache_l1_range(virt_addr, len);
}

/*
 * Flush ICACHE line
 */

static void
kvm_FLUSH_ICACHE_LINE(flush_op_t flush_op, flush_addr_t flush_addr)
{
	KVM_FLUSH_ICACHE_LINE(flush_op, flush_addr);
}

/*
 * Flush and invalidate or write back CACHE(s) (invalidate all caches
 * of the processor)
 */

static void
kvm_FLUSH_CACHE_L12(flush_op_t flush_op)
{
	KVM_FLUSH_CACHE_L12(flush_op);
}

/*
 * Flush TLB (invalidate all TLBs of the processor)
 */

static void
kvm_FLUSH_TLB_ALL(flush_op_t flush_op)
{
	KVM_FLUSH_TLB_ALL(flush_op);
}

/*
 * Flush ICACHE (invalidate instruction caches of the processor)
 */

static void
kvm_FLUSH_ICACHE_ALL(flush_op_t flush_op)
{
	KVM_FLUSH_ICACHE_ALL(flush_op);
}

/*
 * Get Entry probe for virtual address
 */

static probe_entry_t
kvm_ENTRY_PROBE_MMU_OP(e2k_addr_t virt_addr)
{
	return KVM_ENTRY_PROBE_MMU_OP(virt_addr);
}

/*
 * Get physical address for virtual address
 */

static probe_entry_t
kvm_ADDRESS_PROBE_MMU_OP(e2k_addr_t virt_addr)
{
	return KVM_ADDRESS_PROBE_MMU_OP(virt_addr);
}

/*
 * Read CLW register
 */

static clw_reg_t
kvm_READ_CLW_REG(clw_addr_t clw_addr)
{
	return KVM_READ_CLW_REG(clw_addr);
}

/*
 * Write CLW register
 */

static void
kvm_WRITE_CLW_REG(clw_addr_t clw_addr, clw_reg_t val)
{
	KVM_WRITE_CLW_REG(clw_addr, val);
}

/* save DAM state */
static void
do_save_DAM(unsigned long long dam[DAM_ENTRIES_NUM])
{
	kvm_save_DAM(dam);
}

/*
 * KVM MMU DEBUG registers access
 */
static inline mmu_reg_t
PV_DO_READ_MMU_DEBUG_REG_VALUE(int reg_no)
{
	return KVM_READ_MMU_DEBUG_REG_VALUE(reg_no);
}
static inline void
PV_DO_WRITE_MMU_DEBUG_REG_VALUE(int reg_no, mmu_reg_t value)
{
	KVM_WRITE_MMU_DEBUG_REG_VALUE(reg_no, value);
}

static void
do_write_pte_at(struct mm_struct *mm, unsigned long addr,
			pte_t *ptep, pte_t pteval,
			bool only_validate, bool to_move)
{
	kvm_write_pte_at(mm, addr, ptep, pteval, only_validate, to_move);
}

static void kvm_raw_set_pte(pte_t *ptep, pte_t pteval)
{
	kvm_set_pte_kernel(ptep, pteval);
}

static pte_t do_pv_ptep_get_and_clear(struct mm_struct *mm, unsigned long addr,
					pte_t *ptep, bool to_move)
{
	return kvm_do_ptep_get_and_clear(mm, addr, ptep, false, to_move);
}

static void
do_write_pmd_at(struct mm_struct *mm, unsigned long addr,
			pmd_t *pmdp, pmd_t pmdval,
			bool only_validate)
{
	kvm_write_pmd_at(mm, addr, pmdp, pmdval, only_validate);
}

static void
do_write_pud_at(struct mm_struct *mm, unsigned long addr,
			pud_t *pudp, pud_t pudval,
			bool only_validate)
{
	kvm_write_pud_at(mm, addr, pudp, pudval, only_validate);
}

static void
do_write_pgd_at(struct mm_struct *mm, unsigned long addr,
			pgd_t *pgdp, pgd_t pgdval,
			bool only_validate)
{
	kvm_write_pgd_at(mm, addr, pgdp, pgdval, only_validate);
}

pv_mmu_ops_t kvm_mmu_ops = {
	.recovery_faulted_tagged_store = kvm_recovery_faulted_tagged_store,
	.recovery_faulted_load = kvm_recovery_faulted_load,
	.recovery_faulted_move = kvm_recovery_faulted_move,
	.recovery_faulted_load_to_greg = kvm_recovery_faulted_load_to_greg,
	.move_tagged_word = kvm_move_tagged_word,
	.move_tagged_dword = kvm_move_tagged_dword,
	.move_tagged_qword = kvm_move_tagged_qword,
	.write_mmu_reg = kvm_WRITE_MMU_REG,
	.read_mmu_reg = kvm_READ_MMU_REG,
	.write_dtlb_reg = kvm_WRITE_DTLB_REG,
	.read_dtlb_reg = kvm_READ_DTLB_REG,
	.flush_tlb_entry = kvm_FLUSH_TLB_ENTRY,
	.flush_dcache_line = kvm_FLUSH_DCACHE_LINE,
	.clear_dcache_l1_set = kvm_CLEAR_DCACHE_L1_SET,
	.flush_dcache_range = kvm_flush_DCACHE_range,
	.clear_dcache_l1_range = kvm_clear_DCACHE_L1_range,
	.write_dcache_l2_reg = kvm_write_dcache_l2_reg,
	.read_dcache_l2_reg = kvm_read_dcache_l2_reg,
	.flush_icache_line = kvm_FLUSH_ICACHE_LINE,
	.flush_cache_all = kvm_FLUSH_CACHE_L12,
	.do_flush_tlb_all = kvm_FLUSH_TLB_ALL,
	.flush_icache_all = kvm_FLUSH_ICACHE_ALL,
	.entry_probe_mmu_op = kvm_ENTRY_PROBE_MMU_OP,
	.address_probe_mmu_op = kvm_ADDRESS_PROBE_MMU_OP,
	.read_clw_reg = kvm_READ_CLW_REG,
	.write_clw_reg = kvm_WRITE_CLW_REG,
	.save_DAM = do_save_DAM,
	.write_mmu_debug_reg = PV_DO_WRITE_MMU_DEBUG_REG_VALUE,
	.read_mmu_debug_reg = PV_DO_READ_MMU_DEBUG_REG_VALUE,
	.boot_set_pte_at = boot_kvm_set_pte,
	.write_pte_at = do_write_pte_at,
	.set_pte = kvm_raw_set_pte,
	.write_pmd_at = do_write_pmd_at,
	.write_pud_at = do_write_pud_at,
	.write_pgd_at = do_write_pgd_at,
	.ptep_get_and_clear = do_pv_ptep_get_and_clear,
	.ptep_wrprotect_atomic = kvm_ptep_wrprotect_atomic,
	.get_pte_for_address = kvm_get_pte_for_address,
	.remap_area_pages = kvm_remap_area_pages,
	.host_guest_vmap_area = kvm_host_guest_vmap_area,
	.unhost_guest_vmap_area = kvm_unhost_guest_vmap_area,

	/* memory management - mman.h */
	.free_mm = kvm_free_mm,
	.mm_init = kvm_mm_init,
	.activate_mm = kvm_activate_mm,
	.make_host_pages_valid = kvm_make_host_pages_valid,
	.set_memory_attr_on_host =
		(int (*)(e2k_addr_t, e2k_addr_t, int))
					kvm_set_memory_attr_on_host,
	.access_process_vm = native_access_process_vm,

	/* memory management - mm.h */
	.free_pgd_range = kvm_free_pgd_range,

	/* kernel virtual memory allocation */
	.alloc_vmap_area = kvm_alloc_vmap_area,
	.__free_vmap_area = kvm__free_vmap_area,
	.free_unmap_vmap_area = kvm_free_unmap_vmap_area,
#ifdef	CONFIG_SMP
	.pcpu_get_vm_areas = kvm_pcpu_get_vm_areas,
#endif	/* CONFIG_SMP */

	/* unmap __init areas */
	.unmap_initmem = kvm_unmap_initmem,
};

pv_time_ops_t kvm_time_ops = {
	.time_init		= kvm_time_init,
	.clock_init		= kvm_clock_init,
	.read_current_timer	= kvm_read_current_timer,
	.get_cpu_running_cycles	= kvm_get_cpu_running_cycles,
	.do_sched_clock		= kvm_sched_clock,
	.steal_clock		= kvm_steal_clock,
};

pv_io_ops_t kvm_io_ops = {
	.boot_writeb	= kvm_writeb,
	.boot_writew	= kvm_writew,
	.boot_writel	= kvm_writel,
	.boot_writell	= kvm_writell,
	.boot_readb	= kvm_readb,
	.boot_readw	= kvm_readw,
	.boot_readl	= kvm_readl,
	.boot_readll	= kvm_readll,

	.writeb	= kvm_writeb,
	.writew	= kvm_writew,
	.writel	= kvm_writel,
	.writell = kvm_writell,
	.readb	= kvm_readb,
	.readw	= kvm_readw,
	.readl	= kvm_readl,
	.readll	= kvm_readll,

	.inb	= kvm_inb,
	.outb	= kvm_outb,
	.outw	= kvm_outw,
	.inw	= kvm_inw,
	.outl	= kvm_outl,
	.inl	= kvm_inl,

	.outsb	= kvm_outsb,
	.outsw	= kvm_outsw,
	.outsl	= kvm_outsl,
	.insb	= kvm_insb,
	.insw	= kvm_insw,
	.insl	= kvm_insl,

	.conf_inb	= kvm_conf_inb,
	.conf_inw	= kvm_conf_inw,
	.conf_inl	= kvm_conf_inl,
	.conf_outb	= kvm_conf_outb,
	.conf_outw	= kvm_conf_outw,
	.conf_outl	= kvm_conf_outl,

	.scr_writew	= kvm_scr_writew,
	.scr_readw	= kvm_scr_readw,
	.vga_writeb	= kvm_vga_writeb,
	.vga_readb	= kvm_vga_readb,

	.pci_init	= kvm_arch_pci_init,
};
static void kvm_set_pv_ops(void)
{
	/* set PV_OPS pointers to virtual functions entries */
	cur_pv_v2p_ops = &pv_v2p_ops;
	cur_pv_boot_ops = &pv_boot_ops;
	cur_pv_cpu_ops = &pv_cpu_ops;
	cur_pv_mmu_ops = &pv_mmu_ops;
	cur_pv_io_ops = &pv_io_ops;
}

/* First C function to be called on KVM guest boot */
asmlinkage void __init kvm_init_paravirt_guest(void)
{
	/* Install kvm guest paravirt ops */
	pv_info = kvm_info;
	pv_v2p_ops = kvm_v2p_ops;
	pv_boot_ops = kvm_boot_ops;
	pv_init_ops = kvm_init_ops;
	pv_time_ops = kvm_time_ops;
	pv_cpu_ops = kvm_cpu_ops;
	pv_mmu_ops = kvm_mmu_ops;
	pv_io_ops = kvm_io_ops;
	kvm_set_pv_ops();
}
