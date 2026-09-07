/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2025 MCST
 */

#include <asm/kexec.h>
#include <linux/kexec.h>
#include <linux/kernel.h>
#include <asm/string.h>
#include <asm/cpu_regs.h>
#include <asm/p2v/boot_v2p.h>
#include <asm/tlbflush.h>
#include <asm/cacheflush.h>
#include <asm/sic_regs.h>
#include <asm/boot_recovery.h>
#include <asm/pic.h>
#include <asm/p2v/boot_init.h>
#include <linux/tick.h>
#include <asm-l/l_timer.h>
#include <linux/device.h>
#include <linux/reboot.h>
#include <asm-l/serial.h>
#include <linux/irq.h>
#include <asm/nmi.h>
#include <linux/cpu.h>
#include <linux/pci.h>
#include <asm/l-iommu.h>
#include <../../kernel/irq/internals.h>

#define __switch_to_phys__	__attribute__((__section__(".switch_to_phys")))

void machine_kexec_cleanup(struct kimage *kimage) { }

static bool crashkernel_intersects_busy(bootblock_struct_t *bb)
{
	for (size_t i = 0; i < bb->info.num_of_busy; i++) {
		u64 busy_start = bb->info.busy[i].address;
		u64 busy_end = bb->info.busy[i].address + bb->info.busy[i].size - 1;
		if (!(crashk_res.start > busy_end || crashk_res.end < busy_start))
			return true;
	}

	return false;
}

static int setup_bootblock(struct kimage *kimage, unsigned long flags)
{
	u64 kernel_base, kernel_size, ramdisk_base, ramdisk_size, cline_pnt;
	bootblock_struct_t __user *new_block = kimage->arch.bootblock_va;
	u16 boot_flag = KEXEC_CRASH_BB_FLAG;

	if (kimage->arch.kexec_lintel) {

		if (get_user(ramdisk_base, &new_block->info.ramdisk_base) ||
			get_user(ramdisk_size, &new_block->info.ramdisk_size))
			return -EFAULT;

		if (copy_to_user(new_block, bootblock_virt, sizeof(*bootblock_virt)))
			return -EFAULT;

		if (put_user(ramdisk_base, &new_block->info.ramdisk_base) ||
			put_user(ramdisk_size, &new_block->info.ramdisk_size))
			return -EFAULT;
		return 0;
	}

	char cline[KSTRMAX_SIZE] = {0};
	char ex_cline[KSTRMAX_SIZE_EX] = {0};

	if (get_user(kernel_base, &new_block->info.kernel_base) ||
	    get_user(kernel_size, &new_block->info.kernel_size) ||
	    get_user(ramdisk_base, &new_block->info.ramdisk_base) ||
	    get_user(ramdisk_size, &new_block->info.ramdisk_size) ||
	    get_user(cline_pnt, &new_block->info.kernel_args_string_pnt) ||
	    copy_from_user(cline, new_block->info.kernel_args_string, KSTRMAX_SIZE) ||
	    copy_from_user(ex_cline, new_block->info.kernel_args_string_ex, KSTRMAX_SIZE_EX)) {
		return -EFAULT;
	}

	if (copy_to_user(new_block, bootblock_virt, sizeof(*bootblock_virt)))
		return -EFAULT;

	if (put_user(kernel_base, &new_block->info.kernel_base) ||
	    put_user(kernel_size, &new_block->info.kernel_size) ||
	    put_user(ramdisk_base, &new_block->info.ramdisk_base) ||
	    put_user(ramdisk_size, &new_block->info.ramdisk_size) ||
	    put_user(cline_pnt, &new_block->info.kernel_args_string_pnt) ||
	    put_user(boot_flag, &new_block->boot_flags) ||
	    copy_to_user(new_block->info.kernel_args_string, cline, KSTRMAX_SIZE) ||
	    copy_to_user(new_block->info.kernel_args_string_ex, ex_cline, KSTRMAX_SIZE_EX)) {
		return -EFAULT;
	}

	if (!(flags & KEXEC_ON_CRASH)) {
		return 0;
	}

	if (WARN_ON(crashkernel_intersects_busy(bootblock_virt))) {
		return -EINVAL;
	}

	if (put_user(2, &new_block->info.num_of_busy) ||
	    put_user(0, &new_block->info.busy[0].address) ||
	    put_user(crashk_res.start, &new_block->info.busy[0].size) ||
	    put_user(crashk_res.end - 2 * PAGE_SIZE + 1, &new_block->info.busy[1].address) ||
	    put_user(MAX_PM_SIZE - crashk_res.end - 1, &new_block->info.busy[1].size)) {
		return -EFAULT;
	}

	return 0;
}

static void setup_image_arch(struct kimage *kimage, unsigned long flags)
{
	struct kexec_segment const *bootblock;

	if (flags & KEXEC_LINTEL_IMAGE) {
		bootblock = &kimage->segment[BOOTBLOCK_SEGMENT_ID];
		kimage->arch.kexec_lintel = 1;
		kimage->arch.bootblock_va = bootblock->buf;
		kimage->arch.bootblock_pa = (phys_addr_t)bootblock->mem;
	} else {
		bootblock = &kimage->segment[KERNEL_SEGMENT_ID];
		kimage->arch.kexec_lintel = 0;
		kimage->arch.bootblock_va = bootblock->buf + BOOTBLOCK_OFFSET;
		kimage->arch.bootblock_pa = (phys_addr_t)bootblock->mem + BOOTBLOCK_OFFSET;
	}
}

static void setup_stacks_arch(struct kimage *kimage, unsigned long flags)
{
	int rid = (flags & KEXEC_ON_CRASH) ? CRASH_STACKS_SEGMENT_RID : STACKS_SEGMENT_RID;

	kimage->arch.stacks_pa = kimage->segment[kimage->nr_segments + rid].mem;
	kimage->arch.stacks_size = kimage->segment[kimage->nr_segments + rid].memsz;
	kimage->arch.blocksz = kimage->arch.stacks_size / num_present_cpus();
}

int machine_kexec_prepare(struct kimage *kimage, unsigned long flags)
{
	size_t buf_len = __end_kexec_relocate_kernel - __start_kexec_relocate_kernel;
	void *reboot_code_buffer = (void *) page_to_virt(kimage->control_code_page);
	int ret;

	memcpy(reboot_code_buffer, __start_kexec_relocate_kernel, buf_len);

	setup_image_arch(kimage, flags);

	ret = setup_bootblock(kimage, flags);
	if (ret)
		return ret;

	setup_stacks_arch(kimage, flags);

	return 0;
}

static noinline void __switch_to_phys__
kexec_switch_pa_and_run(struct kimage *kimage)
{
	bootmem_areas_t	*bootmem = &kernel_bootmem;
	e2k_cud_t	cud;
	e2k_cutd_t	cutd;
	e2k_gd_t	gd;
	int		cpuid = hard_smp_processor_id();

	NATIVE_FLUSHCPU;

	unsigned long stack_base = kimage->arch.stacks_pa +
		cpuid * kimage->arch.blocksz;
	WARN_ON(THREAD_SIZE > 30 * PAGE_SIZE);
	NATIVE_SWITCH_TO_KERNEL_STACK(
		stack_base + KERNEL_P_STACK_OFFSET, KERNEL_P_STACK_SIZE,
		stack_base + KERNEL_PC_STACK_OFFSET, KERNEL_PC_STACK_SIZE,
		stack_base + KERNEL_C_STACK_OFFSET, KERNEL_C_STACK_SIZE);

	cud = native_read_CUD_reg();
	cud = new_cud(bootmem->text.phys, CUD_SIZE(cud), 1, cud_m64);
	native_write_CUD_reg(cud);

	cud = native_read_OSCUD_reg();
	cud = new_cud(bootmem->text.phys, CUD_SIZE(cud), 1, cud_m64);
	native_write_OSCUD_reg(cud);

	gd = new_gd(bootmem->data.phys, GD_BASE(native_read_GD_reg()));
	native_write_GD_reg(gd);

	gd = new_gd(bootmem->data.phys, GD_BASE(native_read_OSGD_reg()));
	native_write_OSGD_reg(gd);

	write_CURRENT_reg_value(cpuid);

	cutd.base = (e2k_addr_t) boot_kernel_CUT;
	native_write_CUTD_reg(cutd);

	E2K_CLEAR_CTPRS();
	__E2K_WAIT_ALL;

	NATIVE_WRITE_MMU_CR(MMU_CR_KERNEL_OFF);
	__E2K_WAIT_ALL;

	kimage = (struct kimage *)__pa(kimage);

	void (*relocate)(struct kimage *img) =
		(void *)page_to_phys(kimage->control_code_page);

	relocate(kimage);
}

static void machine_kexec_mask_interrupts(void)
{
	unsigned int i;
	struct irq_desc *desc;

	for_each_irq_desc(i, desc) {
		struct irq_chip *chip;
		int ret;

		chip = irq_desc_get_chip(desc);
		if (!chip)
			continue;

		/*
		 * First try to remove the active state. If this
		 * fails, try to EOI the interrupt.
		 */
		ret = irq_set_irqchip_state(i, IRQCHIP_STATE_ACTIVE, false);

		if (ret && irqd_irq_inprogress(&desc->irq_data) &&
		    chip->irq_eoi)
			chip->irq_eoi(&desc->irq_data);

		irq_shutdown(desc);
	}
}

bool kexec_wakeup_offline = 0;

#ifdef CONFIG_SMP
static void kexec_wakeup_offline_cpus(void)
{
	kexec_wakeup_offline = 1;

	/* Paired with smp_rmb() in wait_for_startup */
	smp_wmb();

	bitmap_fill(physid_bits(&callin_go), MAX_PHYSID_NUM);

	int cpu;
	if (machine.clk_on)
		for_each_present_cpu(cpu)
			if (cpu_is_offline(cpu))
				machine.clk_on(cpu);
}
#else
static void kexec_wakeup_offline_cpus(void) {}
#endif

static bool ready_to_jump = 0;
static DEFINE_PER_CPU(struct kimage *, kimagep);

void __cpu_wait_jump(void *info)
{
	all_irq_disable();

	smp_cond_load_acquire(&ready_to_jump, VAL);

	pic_disable();
	kexec_switch_pa_and_run(per_cpu(kimagep, smp_processor_id()));
}

static void kexec_cpus_wait_jump(void)
{
	nmi_call_function(__cpu_wait_jump, NULL, 0, 0);

	kexec_wakeup_offline_cpus();
}

void machine_kexec(struct kimage *kimage)
{
	int cpu;

	for_each_present_cpu(cpu) {
		per_cpu(kimagep, cpu) = kimage;
	}

	machine_kexec_mask_interrupts();
	pic_disable();

	smp_store_release(&ready_to_jump, true);

	kexec_switch_pa_and_run(kimage);
}

static void kexec_pci_reset_secondary_bus(struct pci_dev *dev)
{
	u16 ctrl;

	pci_read_config_word(dev, PCI_BRIDGE_CONTROL, &ctrl);
	ctrl |= PCI_BRIDGE_CTL_BUS_RESET;
	pci_write_config_word(dev, PCI_BRIDGE_CONTROL, ctrl);

	mdelay(2);

	ctrl &= ~PCI_BRIDGE_CTL_BUS_RESET;
	pci_write_config_word(dev, PCI_BRIDGE_CONTROL, ctrl);
}

static void kexec_walk_bus(struct pci_bus *bus)
{
	struct pci_bus *child;

	list_for_each_entry(child, &bus->children, node) {
		kexec_walk_bus(child);
	}

	if (bus->self)
		kexec_pci_reset_secondary_bus(bus->self);
}

static void kexec_reset_pci_devices(void)
{
	struct pci_bus *bus;

	list_for_each_entry(bus, &pci_root_buses, node) {
		kexec_walk_bus(bus);
	}
}

void machine_crash_shutdown(struct pt_regs *regs)
{
	all_irq_disable();
	kexec_cpus_wait_jump();

	kexec_reset_pci_devices();
}

void machine_shutdown(void)
{
	all_irq_disable();
	kexec_cpus_wait_jump();

	kexec_scc_init(bootblock_virt->info.serial_base);
}

static void kexec_writeb(u8 b, void __iomem *addr)
{
	NATIVE_WRITE_MAS_B((unsigned long) addr, b, MAS_IO_OPERATION);
}

static void kexec_scc_outb_command(u64 iomem_addr, u8 reg_num, u8 val)
{
	kexec_writeb(reg_num, (void __iomem __force *)iomem_addr);
	kexec_writeb(val, (void __iomem __force *)iomem_addr);
}

static void kexec_scc_init_port(u8 channel, u64 port)
{
	kexec_scc_outb_command(port, AM85C30_WR9, SCC_WR9_RESET_BASE >> channel);
	kexec_scc_outb_command(port, AM85C30_WR1, 0x0);
	kexec_scc_outb_command(port, AM85C30_WR4,
			       SCC_WR4_PARITY_NONE | SCC_WR4_STOP_BITS_1 |
			       SCC_WR4_CLOCK_MODE_X16);
	kexec_scc_outb_command(port, AM85C30_WR6, 0x15);
	kexec_scc_outb_command(port, AM85C30_WR7, SCC_WR7_XN_MODE_ENABLE);
	kexec_scc_outb_command(port, AM85C30_WR10, SCC_WR10_ENCODING_NRZ);
	kexec_scc_outb_command(port, AM85C30_WR11,
			       SCC_WR11_TXCLK_BRG | SCC_WR11_RXCLK_BRG);
	kexec_scc_outb_command(port, AM85C30_WR12, 0x0);
	kexec_scc_outb_command(port, AM85C30_WR13, 0x0);
	kexec_scc_outb_command(port, AM85C30_WR14,
			       SCC_WR14_BRG_ENABLE | SCC_WR14_BRG_SOURCE);
	kexec_scc_outb_command(port, AM85C30_WR3,
			       SCC_WR3_RX_DATA | SCC_WR3_RX_ENABLE);
	kexec_scc_outb_command(port, AM85C30_WR5,
			       SCC_WR5_TX_DATA | SCC_WR5_TX_ENABLE);
}

void kexec_scc_init(u64 base)
{
	kexec_scc_init_port(0, base);
	kexec_scc_init_port(1, base + 2);
}
