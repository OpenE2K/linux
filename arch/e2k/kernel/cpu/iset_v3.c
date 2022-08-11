#include <linux/cpu.h>
#include <asm/mmu_regs_access.h>
#include <asm/e2k_api.h>
#include <asm/cpu_regs.h>
#include <asm/machdep.h>
#include <asm/nmi.h>
#include <asm/pic.h>
#include <asm/sic_regs.h>

unsigned long rrd_v3(int reg)
{
	switch (reg) {
	case E2K_REG_CORE_MODE:
		return NATIVE_READ_CORE_MODE_REG_VALUE();
	}

	return 0;
}

void rwd_v3(int reg, unsigned long value)
{
	switch (reg) {
	case E2K_REG_CORE_MODE:
		NATIVE_WRITE_CORE_MODE_REG_VALUE(value);
		return;
	}
}

void flushts_v3(void)
{
	E2K_FLUSHTS;
}

#ifdef CONFIG_MLT_STORAGE
void invalidate_MLT_v3()
{
	NATIVE_SET_MMUREG(mlt_inv, 0);
}

static bool read_MLT_entry_v3(e2k_mlt_entry_t *mlt, int entry_num)
{
	AW(mlt->dw0) = NATIVE_READ_MLT_REG(REG_MLT_TYPE << REG_MLT_TYPE_SHIFT |
					   entry_num << REG_MLT_N_SHIFT);

	if (!AS_V2_STRUCT(mlt->dw0).val)
		return false;

	AW(mlt->dw1) = NATIVE_READ_MLT_REG(1 << REG_MLT_DW_SHIFT |
			REG_MLT_TYPE << REG_MLT_TYPE_SHIFT |
			entry_num << REG_MLT_N_SHIFT);
	AW(mlt->dw2) = NATIVE_READ_MLT_REG(2 << REG_MLT_DW_SHIFT |
			REG_MLT_TYPE << REG_MLT_TYPE_SHIFT |
			entry_num << REG_MLT_N_SHIFT);

	return true;
}

void get_and_invalidate_MLT_context_v3(e2k_mlt_t *mlt_state)
{
	int i;

	mlt_state->num = 0;

	for (i = 0; i < NATIVE_MLT_SIZE; i++) {
		e2k_mlt_entry_t *mlt = &mlt_state->mlt[mlt_state->num];

		if (read_MLT_entry_v3(mlt, i))
			mlt_state->num++;
	}

	NATIVE_SET_MMUREG(mlt_inv, 0);
}
#endif

/* SCLKR/SCLKM1/SCLKM2 implemented only on machine from e2s */

unsigned long native_read_SCLKR_reg_value(void)
{
	return NATIVE_READ_SCLKR_REG_VALUE();
}

unsigned long native_read_SCLKM1_reg_value(void)
{
	return NATIVE_READ_SCLKM1_REG_VALUE();
}

unsigned long native_read_SCLKM2_reg_value(void)
{
	return NATIVE_READ_SCLKM2_REG_VALUE();
}

void native_write_SCLKR_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_SCLKR_REG_VALUE(reg_value);
}

void native_write_SCLKM1_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_SCLKM1_REG_VALUE(reg_value);
}

void native_write_SCLKM2_reg_value(unsigned long reg_value)
{
	NATIVE_WRITE_SCLKM2_REG_VALUE(reg_value);
}

__section(".C3_wait_trap.text")
static noinline notrace void C3_wait_trap(bool nmi_only)
{
	e2k_st_core_t st_core;
	int cpuid = read_pic_id();
	int reg = SIC_st_core(cpuid % cpu_max_cores_num());
	int node = numa_node_id();
	phys_addr_t nbsr_phys = sic_get_node_nbsr_phys_base(node);

	/* Only NMIs that go through APIC are allowed: if we receive local
	 * NMI (or just a local exception) hardware will block.  So here we
	 * disable all other sources (and reenable them in handle_wtrap());
	 * it must be done under all closed interrupts so that handle_wtrap()
	 * does not try to read uninitalized values from [current->thread.C3].
	 *
	 * Newer processors have a much better "wait int" interface that
	 * doesn't have this problem (and some others) and should be used
	 * instead. */
	WARN_ON_ONCE(!raw_all_irqs_disabled());
	NATIVE_SET_MMUREG(mlt_inv, 0);
	current->thread.C3.ddbcr = READ_DDBCR_REG();
	current->thread.C3.dibcr = READ_DIBCR_REG();
	current->thread.C3.ddmcr = READ_DDMCR_REG();
	current->thread.C3.dimcr = READ_DIMCR_REG();

	WRITE_DDBCR_REG_VALUE(0);
	WRITE_DIBCR_REG_VALUE(0);
	WRITE_DDMCR_REG_VALUE(0);
	WRITE_DIMCR_REG_VALUE(0);

	AW(st_core) = sic_read_node_nbsr_reg(node, reg);
	st_core.val = 0;
	if (IS_MACHINE_E1CP)
		st_core.e1cp.pmc_rst = 1;

	/* Interrupts must be enabled in the ".wait_trap.text" section
	 * so that the wakeup IRQ is not missed by handle_wtrap(). */
	if (nmi_only)
		raw_local_irq_disable();
	else
		local_irq_enable();

	C3_WAIT_TRAP_V3(AW(st_core), nbsr_phys + reg);
	/* Will not get here */
}

void __cpuidle C3_enter_v3(void)
{
	WARN_ON_ONCE(!irqs_disabled());
	raw_all_irq_disable();
	C3_wait_trap(false);
	local_irq_disable();
}

#ifdef CONFIG_SMP
void clock_off_v3(void)
{
	unsigned long flags;

	/* Make sure we do not race with `callin_go` write */
	raw_all_irq_save(flags);
	if (!cpumask_test_cpu(read_pic_id(), &callin_go))
		C3_wait_trap(true);
	raw_all_irq_restore(flags);
}

static void clock_on_v3_ipi(void *unused)
{
	/* Handling is done in handle_wtrap() */
}

void clock_on_v3(int cpu)
{
	/* Wake CPU disabled by clk_off(CPU_HOTPLUG_CLOCK_OFF) */
	nmi_call_function_single_offline(cpu, clock_on_v3_ipi, NULL, true, 0);
}
#endif
