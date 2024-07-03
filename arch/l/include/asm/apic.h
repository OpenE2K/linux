/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

#ifndef _ASM_L_APIC_H
#define _ASM_L_APIC_H

#include <linux/cpumask.h>
#include <linux/errno.h>
#include <linux/atomic.h>
#include <linux/cpumask.h>

#include <asm/percpu.h>
#include <asm/processor.h>
#include <asm/apicdef.h>
#include <asm/hardirq.h>
#include <asm/mpspec.h>

#include <asm-l/pic_common.h>
#include <asm-l/idle.h>

#define READ_APIC_ID() GET_APIC_ID(arch_apic_read(APIC_ID))

extern int first_system_vector;

/*
 * Debugging macros
 */
#define APIC_QUIET   0
#define APIC_VERBOSE 1
#define APIC_DEBUG   2

/*
 * Define the default level of output to be very little
 * This can be turned up by using apic=verbose for more
 * information and apic=debug for _lots_ of information.
 * apic_verbosity is defined in apic.c
 */
#define apic_printk(v, s, a...) do {       \
		if ((v) <= apic_verbosity) \
			printk(s, ##a);    \
	} while (0)

#ifdef CONFIG_L_LOCAL_APIC

# define READ_APIC_ID()		GET_APIC_ID(arch_apic_read(APIC_ID))
# define BOOT_READ_APIC_ID()	GET_APIC_ID(boot_arch_apic_read(APIC_ID))

extern unsigned int apic_verbosity;

/*
 * Basic functions accessing APICs.
 */
#ifdef CONFIG_PARAVIRT
#include <asm/paravirt/pv_ops.h>
#endif

static inline void native_apic_mem_write(u32 reg, u32 v)
{
	arch_apic_write(reg, v);
}

static inline u32 native_apic_mem_read(u32 reg)
{
	return arch_apic_read(reg);
}

extern void native_apic_wait_icr_idle(void);
extern u32 native_safe_apic_wait_icr_idle(void);
extern void native_apic_icr_write(u32 low, u32 id);
extern u64 native_apic_icr_read(void);

extern int get_physical_broadcast(void);

extern int lapic_get_maxlvt(void);
extern void clear_local_APIC(void);
extern void disconnect_bsp_APIC(int virt_wire_setup);
extern void disable_local_APIC(void);

#ifdef CONFIG_E2K
extern void clear_local_APIC(void);
#endif /* CONFIG_E2K */

extern void lapic_shutdown(void);
extern int verify_local_APIC(void);
extern void init_bsp_APIC(void);
extern void setup_local_APIC(void);
extern void end_local_APIC_setup(void);
extern void bsp_end_local_APIC_setup(void);
extern void init_apic_mappings(void);
void register_lapic_address(unsigned long address);
extern void setup_boot_APIC_clock(void);
extern void setup_secondary_APIC_clock(void);

#else /* !CONFIG_L_LOCAL_APIC */
static inline void lapic_shutdown(void) { }
static inline void init_apic_mappings(void) { }
static inline void disable_local_APIC(void) { }

#ifdef CONFIG_E2K
static inline void clear_local_APIC(void) { }
#endif /* CONFIG_E2K */

# define setup_boot_APIC_clock()	do { } while (0)
# define setup_secondary_APIC_clock()	do { } while (0)
#endif /* !CONFIG_L_LOCAL_APIC */

/*
 * Generic APIC sub-arch data struct.
 */
struct apic {
	char *name;

	int (*probe)(void);
	int (*acpi_madt_oem_check)(char *oem_id, char *oem_table_id);
	int (*apic_id_registered)(void);

	u32 irq_delivery_mode;
	u32 irq_dest_mode;

	const struct cpumask *(*target_cpus)(void);

	int dest_logical;
	unsigned long (*check_apicid_used)(physid_mask_t *map, int apicid);

	void (*vector_allocation_domain)(int cpu, struct cpumask *retmask,
					 const struct cpumask *mask);
	void (*ioapic_phys_id_map)(physid_mask_t *phys_map, physid_mask_t *retmap);

	void (*apicid_to_cpu_present)(int phys_apicid, physid_mask_t *retmap);
	int (*check_phys_apicid_present)(int phys_apicid);

	unsigned int (*get_apic_id)(unsigned long x);
	unsigned long apic_id_mask;

	int (*cpu_mask_to_apicid_and)(const struct cpumask *cpumask,
				      const struct cpumask *andmask,
				      unsigned int *apicid);

	/* ipi */
	void (*send_IPI_mask)(const struct cpumask *mask, int vector);
	void (*send_IPI_mask_allbutself)(const struct cpumask *mask,
					 int vector);
	void (*send_IPI_allbutself)(int vector);
	void (*send_IPI_all)(int vector);
	void (*send_IPI_self)(int vector);

	/* apic ops */
	u32 (*read)(u32 reg);
	void (*write)(u32 reg, u32 v);
	/*
	 * ->eoi_write() has the same signature as ->write().
	 *
	 * Drivers can support both ->eoi_write() and ->write() by passing the same
	 * callback value. Kernel can override ->eoi_write() and fall back
	 * on write for EOI.
	 */
	void (*eoi_write)(u32 reg, u32 v);
	u64 (*icr_read)(void);
	void (*icr_write)(u32 low, u32 high);
	void (*wait_icr_idle)(void);
	u32 (*safe_wait_icr_idle)(void);
};

/*
 * Pointer to the local APIC driver in use on this system (there's
 * always just one such driver in use - the kernel decides via an
 * early probing process which one it picks - and then sticks to it):
 */
extern struct apic *apic;

/*
 * APIC drivers are probed based on how they are listed in the .apicdrivers
 * section. So the order is important and enforced by the ordering
 * of different apic driver files in the Makefile.
 *
 * For the files having two apic drivers, we use apic_drivers()
 * to enforce the order with in them.
 */
#define apic_driver(sym)					\
	static const struct apic *__apicdrivers_##sym __used		\
	__aligned(sizeof(struct apic *))			\
	__section(".apicdrivers") = { &sym }

#define apic_drivers(sym1, sym2)					\
	static struct apic *__apicdrivers_##sym1##sym2[2] __used	\
	__aligned(sizeof(struct apic *))				\
	__section(".apicdrivers") = { &sym1, &sym2 }

extern struct apic *__apicdrivers[], *__apicdrivers_end[];

#ifdef CONFIG_L_LOCAL_APIC

static inline u32 apic_read(u32 reg)
{
	return apic->read(reg);
}

static inline void apic_write(u32 reg, u32 val)
{
	apic->write(reg, val);
}

static inline void apic_eoi(void)
{
	apic->eoi_write(APIC_EOI, APIC_EOI_ACK);
}

static inline u64 apic_icr_read(void)
{
	return apic->icr_read();
}

static inline void apic_icr_write(u32 low, u32 high)
{
	apic->icr_write(low, high);
}

static inline void apic_wait_icr_idle(void)
{
	apic->wait_icr_idle();
}

static inline u32 safe_apic_wait_icr_idle(void)
{
	return apic->safe_wait_icr_idle();
}

#else /* CONFIG_L_LOCAL_APIC */

static inline u32 apic_read(u32 reg) { return 0; }
static inline void apic_write(u32 reg, u32 val) { }
static inline void apic_eoi(void) { }
static inline u64 apic_icr_read(void) { return 0; }
static inline void apic_icr_write(u32 low, u32 high) { }
static inline void apic_wait_icr_idle(void) { }
static inline u32 safe_apic_wait_icr_idle(void) { return 0; }

#endif /* CONFIG_L_LOCAL_APIC */

static inline void ack_APIC_irq(void)
{
	/*
	 * ack_APIC_irq() actually gets compiled as a single instruction
	 * ... yummie.
	 */
	apic_eoi();
}

static inline unsigned default_get_apic_id(unsigned long x)
{
	unsigned int ver = GET_APIC_VERSION(apic_read(APIC_LVR));

	if (APIC_XAPIC(ver))
		return (x >> 24) & 0xFF;
	else
		return (x >> 24) & 0x0F;
}

#ifdef CONFIG_L_LOCAL_APIC
extern int default_acpi_madt_oem_check(char *, char *);

extern void apic_send_IPI_self(int vector);

#endif

#ifdef CONFIG_L_LOCAL_APIC

static inline const struct cpumask *online_target_cpus(void)
{
	return cpu_online_mask;
}

DECLARE_EARLY_PER_CPU_READ_MOSTLY(u16, cpu_to_picid);
#ifdef CONFIG_SMP
#define cpu_physical_id(cpu)	per_cpu(cpu_to_picid, cpu)
#else
#define cpu_physical_id(cpu)	boot_cpu_physical_apicid
#endif


static inline unsigned int read_apic_id(void)
{
	unsigned int reg;

	reg = apic_read(APIC_ID);

	return apic->get_apic_id(reg);
}

extern void default_setup_apic_routing(void);

static inline int
flat_cpu_mask_to_apicid_and(const struct cpumask *cpumask,
			    const struct cpumask *andmask,
			    unsigned int *apicid)
{
	unsigned long cpu_mask = cpumask_bits(cpumask)[0] &
				 cpumask_bits(andmask)[0] &
				 cpumask_bits(cpu_online_mask)[0] &
				 APIC_ALL_CPUS;

	if (likely(cpu_mask)) {
		*apicid = (unsigned int)cpu_mask;
		return 0;
	} else {
		return -EINVAL;
	}
}

extern int
default_cpu_mask_to_apicid_and(const struct cpumask *cpumask,
			       const struct cpumask *andmask,
			       unsigned int *apicid);

static inline void
flat_vector_allocation_domain(int cpu, struct cpumask *retmask,
			      const struct cpumask *mask)
{
	/* Careful. Some cpus do not strictly honor the set of cpus
	 * specified in the interrupt destination when using lowest
	 * priority interrupt delivery mode.
	 *
	 * In particular there was a hyperthreading cpu observed to
	 * deliver interrupts to the wrong hyperthread when only one
	 * hyperthread was specified in the interrupt desitination.
	 */
	cpumask_clear(retmask);
	cpumask_bits(retmask)[0] = APIC_ALL_CPUS;
}

static inline void
default_vector_allocation_domain(int cpu, struct cpumask *retmask,
				 const struct cpumask *mask)
{
	cpumask_copy(retmask, cpumask_of(cpu));
}

static inline unsigned long default_check_apicid_used(physid_mask_t *map, int apicid)
{
	return physid_isset(apicid, *map);
}

static inline unsigned long default_check_apicid_present(int bit)
{
	return physid_isset(bit, phys_cpu_present_map);
}

static inline void default_ioapic_phys_id_map(physid_mask_t *phys_map, physid_mask_t *retmap)
{
	*retmap = *phys_map;
}

static inline int __default_cpu_present_to_apicid(int mps_cpu)
{
	if (mps_cpu < nr_cpu_ids && cpu_present(mps_cpu))
		return (int)per_cpu(cpu_to_picid, mps_cpu);
	else
		return BAD_APICID;
}

static inline int
__default_check_phys_apicid_present(int phys_apicid)
{
	return physid_isset(phys_apicid, phys_cpu_present_map);
}

static inline int default_cpu_present_to_apicid(int mps_cpu)
{
	return __default_cpu_present_to_apicid(mps_cpu);
}

static inline int
default_check_phys_apicid_present(int phys_apicid)
{
	return __default_check_phys_apicid_present(phys_apicid);
}

extern bool default_check_phys_apicid_online(void);

#endif /* CONFIG_L_LOCAL_APIC */

static inline void entering_irq(void)
{
	l_irq_enter();
	exit_idle();
}

static inline void entering_ack_irq(void)
{
	entering_irq();
	ack_APIC_irq();
}

static inline void exiting_irq(void)
{
	l_irq_exit();
}

static inline void exiting_ack_irq(void)
{
	l_irq_exit();
	/* Ack only at the end to avoid potential reentry */
	ack_APIC_irq();
}

struct irq_data;
extern void ack_apic_edge(struct irq_data *data);
#endif /* _ASM_L_APIC_H */
