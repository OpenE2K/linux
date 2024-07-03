/*
 * SPDX-License-Identifier: GPL-2.0
 * Copyright (c) 2023 MCST
 */

/*
 * IO-EPIC support
 */

#include <linux/interrupt.h>
#include <linux/init.h>
#include <linux/pci.h>
#include <linux/compiler.h>
#include <linux/delay.h>
#include <linux/export.h>
#include <linux/syscore_ops.h>
#include <linux/irq.h>
#include <linux/msi.h>
#include <linux/pci.h>
#include <linux/slab.h>

#include <asm/io_apic.h>
#include <asm/io.h>
#include <asm/smp.h>
#include <asm/setup.h>
#include <asm/hw_irq.h>
#include <asm/sic_regs.h>

#include <asm/epic.h>
#include <asm/apic.h>
#include <asm/io_epic.h>
#include <asm/io_epic_regs.h>
#include <asm/gpio.h>
#include <asm-l/pic.h>
#include <asm-l/iolinkmask.h>

#include <asm-l/msidef.h>

static DEFINE_RAW_SPINLOCK(ioepic_lock);
static DEFINE_RAW_SPINLOCK(vector_lock);

static struct ioepic {
	/* Number of IRQ routing registers */
	int nr_registers;
	/* IO-EPIC config */
	struct {
		unsigned char epicver;
		unsigned short epicid;
		unsigned short nodeid;
		unsigned short bus;
		unsigned long epicaddr;
	} mp_config;
	/* IO-EPIC gsi routing info */
	struct mp_ioepic_gsi gsi_config;
	/* Saved state during suspend/resume */
	struct IO_EPIC_route_entry *saved_registers;
	/* For APIC + EIOHub machines */
	struct pci_dev *ioepic;
} ioepics[MAX_IO_EPICS];

#define	IO_EPIC_NR_REGS	64

/* 0: edge, 1: level */
static int pin_to_trigger[IO_EPIC_NR_REGS] = {
	[0 ... IO_EPIC_NR_REGS - 1] = 1,
	[2]  = 0,	/* 2 - System Timer */
	[29] = 0,	/* 29 - WLCC */
};

int mpc_ioepic_id(int ioepic_idx)
{
	return ioepics[ioepic_idx].mp_config.epicid;
}

static int mpc_ioepic_version(int ioepic_idx)
{
	return ioepics[ioepic_idx].mp_config.epicver;
}

static bool ioepic_has_fast_eoi(int ioepic_idx)
{
	return mpc_ioepic_version(ioepic_idx) >= IOEPIC_VERSION_2;
}

int mpc_ioepic_nodeid(int ioepic_idx)
{
	return ioepics[ioepic_idx].mp_config.nodeid;
}

int mpc_ioepic_bus(int ioepic_idx)
{
	return ioepics[ioepic_idx].mp_config.bus;
}

unsigned long mpc_ioepic_addr(int ioepic_idx)
{
	return ioepics[ioepic_idx].mp_config.epicaddr;
}

unsigned int mp_ioepic_gsi_base(int ioepic_idx)
{
	return ioepics[ioepic_idx].gsi_config.gsi_base;
}

int nr_ioepics;

static inline unsigned long io_epic_base(int idx)
{
	return mpc_ioepic_addr(idx);
}

unsigned long io_epic_base_node(int node)
{
	int i;

	for (i = 0; i < nr_ioepics; i++) {
		if (mpc_ioepic_nodeid(i) == node)
			return mpc_ioepic_addr(i);
	}

	pr_err("%s(): could not find IOEPIC on node %d\n", __func__, node);

	return 0;
}

unsigned long io_epic_version_node(int node)
{
	int i;

	for (i = 0; i < nr_ioepics; i++) {
		if (mpc_ioepic_nodeid(i) == node)
			return mpc_ioepic_version(i);
	}

	pr_err("%s(): could not find IOEPIC on node %d\n", __func__, node);

	return 0;
}

void io_epic_write(unsigned int epic, unsigned int reg, unsigned int value)
{
	boot_writel(value, (void __iomem *) (io_epic_base(epic) + reg));
}

unsigned int io_epic_read(unsigned int epic, unsigned int reg)
{
	return boot_readl((void __iomem *) (io_epic_base(epic) + reg));
}

union io_epic_entry_union {
	struct { u32 w1, w2, w3, w4, w5; };
	struct IO_EPIC_route_entry entry;
};

/* Mask the pin before overwriting the entry */
static void __ioepic_write_entry(int epic, int pin,
					struct IO_EPIC_route_entry e)
{
	union io_epic_entry_union eu;
	union IO_EPIC_INT_CTRL reg;

	reg.raw = 0;
	reg.bits.mask = 1;
	io_epic_write(epic, IOEPIC_TABLE_INT_CTRL(pin), reg.raw);

	eu.entry = e;
	io_epic_write(epic, IOEPIC_TABLE_MSG_DATA(pin), eu.w2);
	io_epic_write(epic, IOEPIC_TABLE_ADDR_HIGH(pin), eu.w3);
	io_epic_write(epic, IOEPIC_TABLE_ADDR_LOW(pin), eu.w4);
	io_epic_write(epic, IOEPIC_INT_RID(pin), eu.w5);

	reg.raw = eu.w1;
	/* do not reset RWC1 bits */
	reg.bits.delivery_status = 0;
	reg.bits.software_int = 0;

	io_epic_write(epic, IOEPIC_TABLE_INT_CTRL(pin), reg.raw);
}

static struct IO_EPIC_route_entry __ioepic_read_entry(int epic, int pin)
{
	union io_epic_entry_union eu;

	eu.w1 = io_epic_read(epic, IOEPIC_TABLE_INT_CTRL(pin));
	eu.w2 = io_epic_read(epic, IOEPIC_TABLE_MSG_DATA(pin));
	eu.w3 = io_epic_read(epic, IOEPIC_TABLE_ADDR_HIGH(pin));
	eu.w4 = io_epic_read(epic, IOEPIC_TABLE_ADDR_LOW(pin));
	eu.w5 = io_epic_read(epic, IOEPIC_INT_RID(pin));

	return eu.entry;
}

void ioepic_write_entry(int epic, int pin, struct IO_EPIC_route_entry e)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&ioepic_lock, flags);
	__ioepic_write_entry(epic, pin, e);
	raw_spin_unlock_irqrestore(&ioepic_lock, flags);
}

struct IO_EPIC_route_entry ioepic_read_entry(int epic, int pin)
{
	unsigned long flags;
	struct IO_EPIC_route_entry e;

	raw_spin_lock_irqsave(&ioepic_lock, flags);
	e = __ioepic_read_entry(epic, pin);
	raw_spin_unlock_irqrestore(&ioepic_lock, flags);

	return e;
}

void ioepic_initialize_pin(struct epic_irq_cfg *cfg)
{
	struct IO_EPIC_route_entry entry;
	u32 lo, hi;

	if (ioepics[cfg->epic].ioepic) {
		struct iohub_sysdata *sd =
			ioepics[cfg->epic].ioepic->bus->sysdata;
		lo = sd->pci_msi_addr_lo;
		hi = sd->pci_msi_addr_hi;
	} else {
		get_io_epic_msi(ioepics[cfg->epic].mp_config.nodeid,
				&lo, &hi);
	}
	memset(&entry, 0, sizeof(entry));

	entry.msg_data.bits.vector = cfg->vector;
	entry.addr_high = hi;
	entry.addr_low.bits.MSI = lo >> E2K_SIC_ALIGN_RT_MSI;
	entry.addr_low.bits.dst = cpu_to_full_cepic_id(cfg->dest);

	entry.int_ctrl.bits.trigger = cfg->trigger;
	if (cfg->trigger)
		entry.int_ctrl.bits.mask = 1;

	entry.rid.raw = cfg->rid;

	ioepic_write_entry(cfg->epic, cfg->pin, entry);
}

/* Return 0, if the pin was not already masked, and 1, if it was */
static bool __mask_ioepic_pin(unsigned short epic, unsigned short pin)
{
	union IO_EPIC_INT_CTRL reg_ctrl;

	reg_ctrl.raw = io_epic_read(epic, IOEPIC_TABLE_INT_CTRL(pin));

	if (reg_ctrl.bits.mask)
		return 0;

	/* do not reset RWC1 bits */
	reg_ctrl.bits.delivery_status = 0;
	reg_ctrl.bits.software_int = 0;

	reg_ctrl.bits.mask = 1;
	io_epic_write(epic, IOEPIC_TABLE_INT_CTRL(pin), reg_ctrl.raw);

	/*
	 * Synchronize the IO-EPIC and the CPU by doing
	 * a dummy read from the IO-EPIC
	 */
	io_epic_read(epic, IOEPIC_ID);

	return 1;
}

static bool __mask_ioepic_irq(struct epic_irq_cfg *cfg)
{
	return __mask_ioepic_pin(cfg->epic, cfg->pin);
}

static void mask_ioepic_irq(struct irq_data *data)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&ioepic_lock, flags);
	__mask_ioepic_irq(data->chip_data);
	raw_spin_unlock_irqrestore(&ioepic_lock, flags);
}

static void __unmask_ioepic_pin(unsigned short epic, unsigned short pin)
{
	union IO_EPIC_INT_CTRL reg_ctrl;

	reg_ctrl.raw = io_epic_read(epic, IOEPIC_TABLE_INT_CTRL(pin));

	/* do not reset RWC1 bits */
	reg_ctrl.bits.delivery_status = 0;
	reg_ctrl.bits.software_int = 0;

	reg_ctrl.bits.mask = 0;
	io_epic_write(epic, IOEPIC_TABLE_INT_CTRL(pin), reg_ctrl.raw);
}

static void __unmask_ioepic_irq(struct epic_irq_cfg *cfg)
{
	__unmask_ioepic_pin(cfg->epic, cfg->pin);
}

static void unmask_ioepic_irq(struct irq_data *data)
{
	unsigned long flags;

	raw_spin_lock_irqsave(&ioepic_lock, flags);
	__unmask_ioepic_irq(data->chip_data);
	raw_spin_unlock_irqrestore(&ioepic_lock, flags);
}

/*
 * When listed as conforming in the MP table, ISA interupts are edge triggered,
 * and PCI interrupts are level triggered
 */
static int irq_trigger(int idx)
{
	int bus = mp_irqs[idx].srcbus;
	int trigger;

	/*
	 * Determine IRQ trigger mode (edge or level sensitive):
	 */
	switch ((mp_irqs[idx].irqflag>>2) & 3) {
	case 0: /* conforms, ie. bus-type dependent */
		if (test_bit(bus, mp_bus_not_pci))
			trigger = 0;
		else
			trigger = 1;
		break;
	case 1: /* edge */
	{
		trigger = 0;
		break;
	}
	case 2: /* reserved */
	{
		pr_warn("broken BIOS!!\n");
		trigger = 1;
		break;
	}
	case 3: /* level */
	{
		trigger = 1;
		break;
	}
	default: /* invalid */
	{
		pr_warn("broken BIOS!!\n");
		trigger = 0;
		break;
	}
	}
	return trigger;
}

/* Change destination core id in IO-EPIC routing table */
static void __target_IO_EPIC_irq(struct epic_irq_cfg *cfg, unsigned int dest)
{
	bool masked;
	unsigned int vector = cfg->vector;
	unsigned int epic = cfg->epic;
	unsigned int pin = cfg->pin;
	union IO_EPIC_MSG_DATA reg_data;
	union IO_EPIC_MSG_ADDR_LOW reg_addr;

	/* Mask the pin */
	masked = __mask_ioepic_pin(epic, pin);

	/* Set vector */
	reg_data.raw = io_epic_read(epic, IOEPIC_TABLE_MSG_DATA(pin));
	reg_data.bits.vector = vector;
	io_epic_write(epic, IOEPIC_TABLE_MSG_DATA(pin), reg_data.raw);

	/* Set destination core id */
	reg_addr.raw = io_epic_read(epic, IOEPIC_TABLE_ADDR_LOW(pin));
	reg_addr.bits.dst = cpu_to_full_cepic_id(dest);
	io_epic_write(epic, IOEPIC_TABLE_ADDR_LOW(pin), reg_addr.raw);

	/* Unmask the pin, if it was masked here */
	if (masked)
		__unmask_ioepic_pin(epic, pin);
}

static bool irqchip_is_ioepic(struct irq_chip *chip);

#ifdef CONFIG_SMP
static void irq_complete_move_vector(struct epic_irq_cfg *cfg, unsigned int vector)
{
	/*
	 * When the first interrupt reaches the new CPU destination, we can
	 * safely clean up the table on the old one
	 */
	if (vector == cfg->vector && smp_processor_id() == cfg->dest) {
		cfg->move_in_progress = 0;
		epic_send_IPI(cfg->old_dest, IRQ_MOVE_CLEANUP_VECTOR);
		epic_printk("Finished moving vector 0x%x to CPU %d\n",
				cfg->vector, cfg->dest);
	}
}

static void irq_complete_move(struct epic_irq_cfg *cfg)
{
	if (likely(!cfg->move_in_progress))
		return;

#if defined CONFIG_E2K
	irq_complete_move_vector(cfg, get_irq_regs()->interrupt_vector);
#elif defined CONFIG_E90S
	irq_complete_move_vector(cfg, e90s_irq_pending[smp_processor_id()].vector);
#else
#error fixme
#endif
}

void epic_irq_force_complete_move(struct irq_desc *desc)
{
	struct irq_data *data = irq_desc_get_irq_data(desc);
	struct epic_irq_cfg *cfg;
	unsigned int irq;

	if (!data)
		return;

	irq = data->irq;
	cfg = irq_data_get_irq_chip_data(data);
	if (unlikely(cfg && cfg->move_in_progress))
		irq_complete_move_vector(cfg, cfg->vector);
}

/* Handler of IRQ move cleanup */
asmlinkage void epic_smp_irq_move_cleanup_interrupt(struct pt_regs *regs)
{
	unsigned int vector, me;

	ack_epic_irq();
	l_irq_enter();

	me = smp_processor_id();
	for (vector = FIRST_EXTERNAL_VECTOR; vector < NR_VECTORS; vector++) {
		int irq;
		unsigned int irr;
		struct irq_desc *desc;
		struct irq_chip *chip;
		struct irq_cfg *apic_cfg;
		struct epic_irq_cfg *epic_cfg;

		irq = __this_cpu_read(vector_irq[vector]);

		if (irq <= VECTOR_UNDEFINED)
			continue;

		desc = irq_to_desc(irq);
		if (!desc)
			continue;

		chip = irq_get_chip(irq);
		if (irqchip_is_ioepic(chip)) {
			/* IO-EPIC IRQ */
			epic_cfg = irq_get_chip_data(irq);
			if (!epic_cfg)
				continue;

			raw_spin_lock(&desc->lock);

			/*
			 * Check if the irq migration is in progress. If so, we
			 * haven't received the cleanup request yet for this irq
			 */
			if (epic_cfg->move_in_progress)
				goto unlock;

			if (vector == epic_cfg->vector && me == epic_cfg->dest)
				goto unlock;
		} else {
			/* IO-APIC IRQ */
			apic_cfg = irq_get_chip_data(irq);
			if (!apic_cfg)
				continue;

			raw_spin_lock(&desc->lock);

			/*
			 * Check if the irq migration is in progress. If so, we
			 * haven't received the cleanup request yet for this irq
			 */
			if (apic_cfg->move_in_progress)
				goto unlock;

			if (vector == apic_cfg->vector &&
					cpumask_test_cpu(me, apic_cfg->domain))
				goto unlock;
		}

		irr = epic_read_w(CEPIC_PMIRR + vector / 32 * 0x4);
		/*
		 * Check if the vector that needs to be cleaned up is
		 * registered at the cpu's IRR. If so, then this is not
		 * the best time to clean it up. Lets clean it up in the
		 * next attempt by sending another IRQ_MOVE_CLEANUP_VECTOR
		 * to myself.
		 */
		if (irr  & (1 << (vector % 32))) {
			epic_send_IPI_self(IRQ_MOVE_CLEANUP_VECTOR);
			goto unlock;
		}
		__this_cpu_write(vector_irq[vector], -1);
		epic_printk("Cleanup finished freeing vector 0x%x\n", vector);
unlock:
		raw_spin_unlock(&desc->lock);
	}

	l_irq_exit();
}
#else
static inline void irq_complete_move(struct epic_irq_cfg *cfg) { }
#endif /* CONFIG_SMP */

static void ack_epic_edge(struct irq_data *data)
{
	irq_complete_move(data->chip_data);
	irq_move_irq(data);
	ack_epic_irq();
}

static void ioepic_level_eoi_slow(int epic, int pin)
{
	unsigned long flags;
	union IO_EPIC_INT_CTRL reg;

	raw_spin_lock_irqsave(&ioepic_lock, flags);

	reg.raw = io_epic_read(epic, IOEPIC_TABLE_INT_CTRL(pin));
	reg.bits.delivery_status = 1;
	io_epic_write(epic, IOEPIC_TABLE_INT_CTRL(pin), reg.raw);

	raw_spin_unlock_irqrestore(&ioepic_lock, flags);
}

/* Writing W1C bits of int_ctrl does not change the RW bits (IOEPIC version 2) */
static void ioepic_level_eoi_fast(int epic, int pin)
{
	union IO_EPIC_INT_CTRL reg;

	reg.raw = 0;
	reg.bits.delivery_status = 1;
	io_epic_write(epic, IOEPIC_TABLE_INT_CTRL(pin), reg.raw);
}

static void ioepic_level_eoi(int epic, int pin)
{
	if (ioepic_has_fast_eoi(epic))
		ioepic_level_eoi_fast(epic, pin);
	else
		ioepic_level_eoi_slow(epic, pin);
}

#ifdef CONFIG_GENERIC_PENDING_IRQ
static bool io_epic_level_ack_pending(struct epic_irq_cfg *cfg)
{
	unsigned long flags;
	union IO_EPIC_INT_CTRL reg;

	raw_spin_lock_irqsave(&ioepic_lock, flags);

	reg.raw = io_epic_read(cfg->epic,
		IOEPIC_TABLE_INT_CTRL(cfg->pin));
	/* Is the remote IRR bit set? */
	if (reg.bits.delivery_status) {
		raw_spin_unlock_irqrestore(&ioepic_lock, flags);
		return true;
	}

	raw_spin_unlock_irqrestore(&ioepic_lock, flags);

	return false;
}

static inline bool ioepic_irqd_mask(struct irq_data *data)
{
	/* If we are moving the irq we need to mask it */
	if (unlikely(irqd_is_setaffinity_pending(data))) {
		if (!irqd_irq_masked(data))
			mask_ioepic_irq(data);
		return true;
	}
	return false;
}

static inline void ioepic_irqd_unmask(struct irq_data *data,
				      struct epic_irq_cfg *cfg, bool masked)
{
	if (unlikely(masked)) {
		/* Only migrate the irq if the ack has been received.
		 *
		 * On rare occasions the broadcast level triggered ack gets
		 * delayed going to ioepics, and if we reprogram the
		 * vector while Remote IRR is still set the irq will never
		 * fire again.
		 *
		 * To prevent this scenario we read the Remote IRR bit
		 * of the ioepic.  This has two effects.
		 * - On any sane system the read of the ioepic will
		 *   flush writes (and acks) going to the ioepic from
		 *   this cpu.
		 * - We get to see if the ACK has actually been delivered.
		 */
		if (!io_epic_level_ack_pending(cfg))
			irq_move_masked_irq(data);

		/* If the IRQ is masked in the core, leave it: */
		if (!irqd_irq_masked(data))
			unmask_ioepic_irq(data);
	}
}
#else
static inline bool ioepic_irqd_mask(struct irq_data *data)
{
	return false;
}
static inline void ioepic_irqd_unmask(struct irq_data *data,
				      struct epic_irq_cfg *cfg, bool masked)
{
}
#endif

static void ack_epic_level(struct irq_data *data)
{
	struct epic_irq_cfg *cfg = irq_data_get_irq_chip_data(data);
	bool masked;

	irq_complete_move(cfg);
	masked = ioepic_irqd_mask(data);

	ack_epic_irq();
	ioepic_level_eoi(cfg->epic, cfg->pin);

	ioepic_irqd_unmask(data, cfg, masked);
}

/* Assign IRQ to one of the CPUs from mask */
static int __epic_assign_irq_vector(int irq, struct epic_irq_cfg *cfg,
					const struct cpumask *mask)
{
	/*
	 * Start distributing vectors sequentially from
	 * FIRST_EXTERNAL_VECTOR + 1
	 */
	static int current_vector = FIRST_EXTERNAL_VECTOR;
	int cpu, err;

	if (cfg->move_in_progress)
		return -EBUSY;

	/* Return ENOSPC if vectors on all CPUs in mask are already taken */
	err = -ENOSPC;

	/* This IRQ is already assigned to the CPU from mask. Exit quietly */
	if (cfg->dest != BAD_EPICID && cpumask_test_cpu(cfg->dest, mask) &&
				cpumask_test_cpu(cfg->dest, cpu_online_mask))
		return 0;

	/* Only try and allocate irqs on cpus that are present */
	for_each_cpu_and(cpu, mask, cpu_online_mask) {
		int vector;

		/* Start the search from the current_vector */
		vector = current_vector;
next:
		vector += 1;

		/*
		 * No good vectors found between current_vector and
		 * first_system_vector. Continue search from
		 * FIRST_EXTERNAL_VECTOR
		 */
		if (vector >= first_system_vector)
			vector = FIRST_EXTERNAL_VECTOR;

		/*
		 * Ran out of availible vectors on current CPU. Search on the
		 * next one from mask
		 */
		if (vector == current_vector)
			continue;

		/* This vector was already taken by setup_PIC_vector_handler */
		if (test_bit(vector, used_vectors))
			goto next;

		/* This vector was previously taken by this function */
		if (per_cpu(vector_irq, cpu)[vector] > VECTOR_UNDEFINED)
			goto next;

		/* Found one! Next time start searching from this vector */
		current_vector = vector;

		/* This IRQ was previously assigned to a different CPU */
		if (cfg->vector) {
			cfg->old_dest = cfg->dest;
			if (cpumask_test_cpu(cfg->old_dest, cpu_online_mask))
				cfg->move_in_progress = 1;
			if (cfg->move_in_progress) {
				epic_printk("Started move vect 0x%x to 0x%x\n",
						cfg->vector, vector);
			}
		}
		per_cpu(vector_irq, cpu)[vector] = irq;
		cfg->vector = vector;
		cfg->dest = cpu;
		err = 0;
		break;
	}
	return err;
}

static int epic_assign_irq_vector(int irq, struct epic_irq_cfg *cfg,
					const struct cpumask *mask)
{
	int err;
	unsigned long flags;

	raw_spin_lock_irqsave(&vector_lock, flags);
	err = __epic_assign_irq_vector(irq, cfg, mask);
	raw_spin_unlock_irqrestore(&vector_lock, flags);

	return err;
}

int __ioepic_set_affinity(struct irq_data *data, const struct cpumask *mask,
			  unsigned int *dest_id)
{
	struct epic_irq_cfg *cfg = irq_data_get_irq_chip_data(data);
	unsigned int irq = data->irq;
	int err;

	if (!IS_ENABLED(CONFIG_SMP))
		return -1;

	if (!cpumask_intersects(mask, cpu_online_mask))
		return -EINVAL;

	if (cfg->passthrough)
		return -EPERM;

	err = epic_assign_irq_vector(irq, cfg, mask);
	if (err)
		return err;

	*dest_id = cfg->dest;

	cpumask_copy(irq_data_get_affinity_mask(data), mask);

	return 0;
}

static int native_ioepic_set_affinity(struct irq_data *data,
			       const struct cpumask *mask,
			       bool force)
{
	unsigned int dest;
	unsigned long flags;
	int ret;

	if (!IS_ENABLED(CONFIG_SMP))
		return -1;

	raw_spin_lock_irqsave(&ioepic_lock, flags);
	ret = __ioepic_set_affinity(data, mask, &dest);
	if (!ret) {
		epic_printk("native_ioepic_set_affinity: writing to IO-EPIC\n");
		__target_IO_EPIC_irq(data->chip_data, dest);
		ret = IRQ_SET_MASK_OK_NOCOPY;
	}
	raw_spin_unlock_irqrestore(&ioepic_lock, flags);
	return ret;
}

static int ioepic_retrigger_irq(struct irq_data *data)
{
	struct epic_irq_cfg *cfg = irq_data_get_irq_chip_data(data);
	unsigned long flags;

	raw_spin_lock_irqsave(&vector_lock, flags);
	if (cpumask_test_cpu(cfg->dest, cpu_online_mask))
		epic_send_IPI(cfg->dest, cfg->vector);
	else
		pr_warn("Tried to retrigger IRQ %d, but CPU is offline\n",
				data->irq);
	raw_spin_unlock_irqrestore(&vector_lock, flags);

	return 1;
}

static unsigned int startup_ioepic_irq(struct irq_data *data)
{
	epic_printk("Starting up IO-EPIC irq %u\n", data->irq);

	if (!data->chip_data)
		epic_printk("ERROR: No chip data on this IRQ!\n");

	unmask_ioepic_irq(data);

	return 0;
}

#ifdef CONFIG_E2K
#include <asm/e2k-iommu.h>

static void io_epic_reset_pin(unsigned int epic, unsigned int pin);
static void ioepic_setup_pin_passthrough(struct ioepic_vcpu_info *info, struct epic_irq_cfg *cfg)
{
	struct ioepic_pt_pin *pt_pin, *tmp;

	if (info->valid) {
		/*
		 * Host and guest pin numbers always match.
		 * Passthrough of the same pin from several host IOEPICs to one VM isn't supported
		 */
		list_for_each_entry_safe(pt_pin, tmp, info->ioepic_pt_pin, list) {
			if (pt_pin->pin == cfg->pin) {
				WARN(true, "failed to pass ioepic node %d pin %d (already passing ioepic node %d pin %d\n)",
					cfg->node, cfg->pin, pt_pin->node, pt_pin->pin);
				return;
			}
		}

		pt_pin = kmalloc(sizeof(struct ioepic_pt_pin), GFP_KERNEL);
		pt_pin->node = cfg->node;
		pt_pin->pin = cfg->pin;
		INIT_LIST_HEAD(&pt_pin->list);
		list_add_tail(&pt_pin->list, info->ioepic_pt_pin);

		io_epic_reset_pin(cfg->epic, cfg->pin);
	} else {
		list_for_each_entry_safe(pt_pin, tmp, info->ioepic_pt_pin, list) {
			if (pt_pin->pin == cfg->pin && pt_pin->node == cfg->node) {
				list_del(&pt_pin->list);
				kfree(pt_pin);
				break;
			}
		}

		ioepic_initialize_pin(cfg);
	}

	cfg->passthrough = info->valid;

	pr_info("%s(): %s IOEPIC passthrough (node %d pin %d)\n", __func__,
		info->valid ? "set" : "reset", cfg->node, cfg->pin);
}

int ioepic_node_pin_to_irq(unsigned int pin, unsigned int node);
bool ioepic_try_setup_pin_range_passthrough(struct ioepic_vcpu_info *info,
		struct epic_irq_cfg *irq_cfg, int min, int max)
{
	int irq, pin;
	struct epic_irq_cfg *cfg;

	if (min <= irq_cfg->pin && irq_cfg->pin <= max) {
		for (pin = min; pin <= max; pin++) {
			irq = ioepic_node_pin_to_irq(pin, irq_cfg->node);
			cfg = irq_get_chip_data(irq);
			ioepic_setup_pin_passthrough(info, cfg);
		}

		return true;
	}

	return false;
}

static int ioepic_set_vcpu_affinity(struct irq_data *data, void *vcpu_info)
{
	struct ioepic_vcpu_info *info = vcpu_info;
	struct epic_irq_cfg *cfg = irq_data_get_irq_chip_data(data);

	if (cfg->pin > ioepics[cfg->epic].nr_registers) {
		WARN(true, "error setting ioepic passthrough for pin %d", cfg->pin);
		return -EINVAL;
	}

	if (16 <= cfg->pin && cfg->pin <= 19) {
		pr_info("%s(): do not pass ioepic intx (node %d pin %d)\n", __func__,
			cfg->node, cfg->pin);
		return -EACCES;
	}

	/* Ethernet 1G and GPIO/MPV require multiple IOEPIC interrupts */
	if (!ioepic_try_setup_pin_range_passthrough(info, cfg, 3, 7) &&
			!ioepic_try_setup_pin_range_passthrough(info, cfg, 9, 13) &&
			!ioepic_try_setup_pin_range_passthrough(info, cfg, 23, 27))
		ioepic_setup_pin_passthrough(info, cfg);

	return 0;
}
#endif

struct irq_chip ioepic_chip __read_mostly = {
	.name			= "IO-EPIC",
	.irq_startup		= startup_ioepic_irq,
	.irq_mask		= mask_ioepic_irq,
	.irq_unmask		= unmask_ioepic_irq,
	.irq_ack		= ack_epic_edge,
	.irq_eoi		= ack_epic_level,
	.irq_set_affinity	= native_ioepic_set_affinity,
	.irq_retrigger		= ioepic_retrigger_irq,
#ifdef CONFIG_E2K
	.irq_set_vcpu_affinity	= ioepic_set_vcpu_affinity,
#endif
};

void __epic_setup_vector_irq(int cpu)
{
	/* Initialize vector_irq on a new cpu */
	int irq, vector;
	struct epic_irq_cfg *cfg;

	/*
	 * vector_lock will make sure that we don't run into irq vector
	 * assignments that might be happening on another cpu in parallel,
	 * while we setup our initial vector to irq mappings.
	 */
	raw_spin_lock(&vector_lock);
	/* Mark the inuse vectors */
	for_each_active_irq(irq) {
		if (!irqchip_is_ioepic(irq_get_chip(irq)))
			continue;

		cfg = irq_get_chip_data(irq);
		if (!cfg)
			continue;

		if (cpu != cfg->dest)
			continue;
		vector = cfg->vector;
		per_cpu(vector_irq, cpu)[vector] = irq;
	}
	/* Mark the free vectors */
	for (vector = 0; vector < NR_VECTORS; ++vector) {
		irq = per_cpu(vector_irq, cpu)[vector];
		if (irq <= VECTOR_UNDEFINED)
			continue;

		if (!irqchip_is_ioepic(irq_get_chip(irq)))
			continue;

		cfg = irq_get_chip_data(irq);
		if (cpu != cfg->dest)
			per_cpu(vector_irq, cpu)[vector] = VECTOR_UNDEFINED;
	}
	raw_spin_unlock(&vector_lock);
}

/*
 * Function to set the IO-EPIC physical IDs based on the values stored in the
 * MP table. Panic if these values are invalid for any reason.
 */
void __init_recv setup_ioepic_ids_from_mpc_nocheck(void)
{
	int ioepic_idx;
	int mpc_id;
	int mpc_node;
	union IO_EPIC_ID reg_id;
	unsigned long flags;

	/*
	 * Set the IOEPIC ID to the value stored in the MP table.
	 */
	for (ioepic_idx = 0; ioepic_idx < nr_ioepics; ioepic_idx++) {
		/* Read the IOEPIC ID register value */
		raw_spin_lock_irqsave(&ioepic_lock, flags);
		reg_id.raw = io_epic_read(ioepic_idx, IOEPIC_ID);
		raw_spin_unlock_irqrestore(&ioepic_lock, flags);

		mpc_id = mpc_ioepic_id(ioepic_idx);
		mpc_node = mpc_ioepic_nodeid(ioepic_idx);

		/*
		 * Update the ID register according to the right value
		 * from the MPC table if they are different.
		 */
		if (mpc_id == reg_id.bits.id && mpc_node == reg_id.bits.nodeid)
			continue;

		epic_printk("Changing IO-EPIC physical ID to %d, node to %d\n",
			mpc_id, mpc_node);

		reg_id.bits.id = mpc_id;
		reg_id.bits.nodeid = mpc_node;
		raw_spin_lock_irqsave(&ioepic_lock, flags);
		io_epic_write(ioepic_idx, IOEPIC_ID, reg_id.raw);
		raw_spin_unlock_irqrestore(&ioepic_lock, flags);
	}
}

static struct epic_irq_cfg *alloc_irq_cfg(int node)
{
	struct epic_irq_cfg *cfg;

	cfg = kzalloc_node(sizeof(*cfg), GFP_KERNEL, node);
	if (!cfg)
		return NULL;

	/* 0 is a valid destination id, can't use it */
	cfg->dest = BAD_EPICID;

	return cfg;
}

static struct epic_irq_cfg *alloc_irq_and_cfg_at(unsigned int at, int node)
{
	int res = irq_alloc_desc_at(at, node);
	struct epic_irq_cfg *cfg;

	if (res < 0) {
		if (res != -EEXIST)
			return NULL;
		cfg = irq_get_chip_data(at);
		if (cfg)
			return cfg;
	}

	cfg = alloc_irq_cfg(node);
	if (cfg)
		irq_set_chip_data(at, cfg);
	else
		irq_free_desc(at);

	return cfg;
}

static void __epic_clear_irq_vector(int irq, struct epic_irq_cfg *cfg)
{
	int vector;

	BUG_ON(!cfg->vector);

	vector = cfg->vector;
	if (cpumask_test_cpu(cfg->dest, cpu_online_mask))
		per_cpu(vector_irq, cfg->dest)[vector] = VECTOR_UNDEFINED;

	cfg->vector = 0;
	cfg->dest = BAD_EPICID;

	if (likely(!cfg->move_in_progress))
		return;

	cfg->move_in_progress = 0;
}

static void ioepic_register_intr(unsigned int irq, struct epic_irq_cfg *cfg)
{
	bool fasteoi;

	if (cfg->trigger == IOEPIC_AUTO || cfg->trigger == IOEPIC_LEVEL) {
		irq_set_status_flags(irq, IRQ_LEVEL);
		fasteoi = true;
	} else {
		irq_clear_status_flags(irq, IRQ_LEVEL);
		fasteoi = false;
	}

	irq_set_chip_and_handler_name(irq, &ioepic_chip,
					fasteoi ? handle_fasteoi_irq : handle_edge_irq,
					fasteoi ? "fasteoi" : "edge");
}

static void setup_ioepic_irq(unsigned int irq, struct epic_irq_cfg *cfg)
{
	if (epic_assign_irq_vector(irq, cfg, cpu_online_mask))
		return;
	if (cfg->dest == BAD_EPICID) {
		pr_warn("Failed to obtain dest epicid for ioepic %d, pin %d\n",
			mpc_ioepic_id(cfg->epic), cfg->pin);
		__epic_clear_irq_vector(irq, cfg);
		return;
	}

	epic_printk("IOEPIC[%d]: Set routing entry (%d-%d -> 0x%x -> IRQ %d Mode:%i Dest:%d SID:0x%x)\n",
		    cfg->epic, mpc_ioepic_id(cfg->epic), cfg->pin,
		    cfg->vector, irq, cfg->trigger, cfg->dest, cfg->rid);

	ioepic_register_intr(irq, cfg);

	ioepic_initialize_pin(cfg);
}

/*
 * Find the IRQ entry number of a certain pin
 */
static int find_irq_entry(int ioepic_idx, int pin, int type)
{
	int i;

	for (i = 0; i < mp_irq_entries; i++)
		if (mp_irqs[i].irqtype == type &&
		   (mp_irqs[i].dstapic == mpc_ioepic_id(ioepic_idx) &&
		    mp_irqs[i].dstirq == pin))
			return i;

	return -1;
}

static int pin_2_irq(int idx, int epic, int pin)
{
	int irq;
	int bus = mp_irqs[idx].srcbus;
	unsigned int gsi_base = mp_ioepic_gsi_base(epic);

	/*
	 * Debugging check, we are in big trouble if this message pops up!
	 */
	if (mp_irqs[idx].dstirq != pin)
		pr_err("broken BIOS or MPTABLE parser, ayiee!!\n");

	/*
	 * ISA device interrupts are allowed only for the IO-EPIC
	 * on BSP. If boot passes such interrupts for other IO-EPICs
	 * then their IRQ numbers are calculated as for PCI devices.
	 * For example, system timer interrupt number is 26 on
	 * the second IO EPIC but it is masked
	 */
	if (test_bit(bus, mp_bus_not_pci) && epic == 0) {
		irq = mp_irqs[idx].srcbusirq;
	} else {
		irq = gsi_base + pin;
	}

	return irq;
}

/*
 * Only two types of MP-table interrupts are supported: mp_FixINT and mp_INT.
 * mp_FixINT are interrupts from EIOHub devices, directly connected to IOEPIC.
 * mp_INT are PCI INTx (boot passes them for each bus, QEMU also passes them for virtio).
 * Boot also passes mp_INT for system timer.
 *
 * mp_FixINT always passes correct bus in srcbus and devfn in srcbusirq fields.
 * mp_INT may pass incorrect bus (ISA for system timer) or incorrect devfn (for INTx).
 */

#define	I2C_SPI_IOEPIC_DEVFN	PCI_DEVFN(2, 1)
static unsigned int irq_requester_id(int idx, int epic)
{
	int bus, devfn;
	union IO_EPIC_REQ_ID rid;

	if (mp_irqs[idx].irqtype == mp_FixINT) {
		bus = mp_irqs[idx].srcbus;
		devfn = mp_irqs[idx].srcbusirq;
	} else {
		bus = mpc_ioepic_bus(epic);
		devfn = I2C_SPI_IOEPIC_DEVFN;
	}

	rid.raw = 0;
	rid.bits.bus = bus;
	rid.bits.dev = PCI_SLOT(devfn);
	rid.bits.fn = PCI_FUNC(devfn);

	return rid.raw;
}

/* Support both IOEPIC v1 and v2 by writing INT_CTRL twice (for RW and RW1C bits) */
static void io_epic_reset_pin(unsigned int epic, unsigned int pin)
{
	union IO_EPIC_INT_CTRL reg;

	reg.raw = 0;
	reg.bits.mask = 1;
	io_epic_write(epic, IOEPIC_TABLE_INT_CTRL(pin), reg.raw);

	reg.bits.delivery_status = 1;
	reg.bits.software_int = 1;
	io_epic_write(epic, IOEPIC_TABLE_INT_CTRL(pin), reg.raw);

	io_epic_write(epic, IOEPIC_TABLE_MSG_DATA(pin), 0);
	io_epic_write(epic, IOEPIC_TABLE_ADDR_HIGH(pin), 0);
	io_epic_write(epic, IOEPIC_TABLE_ADDR_LOW(pin), 0);
}

static void io_epic_reset_pin_rid(unsigned int epic, unsigned int pin)
{
	io_epic_reset_pin(epic, pin);
	io_epic_write(epic, IOEPIC_INT_RID(pin), 0);
}

void __init ioepic_check_trigger(struct epic_irq_cfg *cfg)
{
	if (cfg->pin < IO_EPIC_NR_REGS && cfg->trigger != pin_to_trigger[cfg->pin])
		epic_printk("IOEPIC%d, pin %d: trigger type mismatch\n",
			cfg->epic, cfg->pin);
}

/*
 * Main reason to read mptable is to get RID for each IRQ. It also helps to:
 * - Get IOEPIC node
 * - Double-check trigger value
 */
static void __init __setup_io_epic_irqs(unsigned int ioepic_idx)
{
	int idx;
	struct epic_irq_cfg *cfg;
	unsigned int pin, irq;
	unsigned int node = mpc_ioepic_nodeid(ioepic_idx);

	for (pin = 0; pin < ioepics[ioepic_idx].nr_registers; pin++) {
		idx = find_irq_entry(ioepic_idx, pin, mp_INT);
		if (idx == -1)
			idx = find_irq_entry(ioepic_idx, pin, mp_FixINT);

		if (idx == -1) {
			/* Some of the registers aren't reset by hardware */
			io_epic_reset_pin_rid(ioepic_idx, pin);
			continue;
		}

		irq = pin_2_irq(idx, ioepic_idx, pin);

		cfg = alloc_irq_and_cfg_at(irq, node);
		if (!cfg) {
			WARN(true, "Failed to allocate IOEPIC IRQ descriptor\n");
			continue;
		}

		cfg->epic = ioepic_idx;
		cfg->pin = pin;
		cfg->trigger = irq_trigger(idx);
		cfg->node = node;
		cfg->rid = irq_requester_id(idx, ioepic_idx);

		ioepic_check_trigger(cfg);

		setup_ioepic_irq(irq, cfg);
	}
}

static void __init setup_io_epic_irqs(void)
{
	unsigned int ioepic_idx;

	epic_printk("Initializing IO-EPIC IRQs\n");

	for (ioepic_idx = 0; ioepic_idx < nr_ioepics; ioepic_idx++)
		__setup_io_epic_irqs(ioepic_idx);
}

/*
 * In IO-APIC this is done in arch_early_irq_init. There is no reason to
 * allocate saved_registers that early though. saved_registers can only be used
 * after the device initcall "ioepic_init_ops", which comes much later than
 * init_IRQ()
 */
static inline void alloc_ioepic_saved_registers(void)
{
	int i;

	for (i = 0; i < nr_ioepics; i++) {
		ioepics[i].saved_registers =
			kzalloc(sizeof(struct IO_EPIC_route_entry) *
				ioepics[i].nr_registers, GFP_KERNEL);
		if (!ioepics[i].saved_registers)
			pr_err("IOEPIC %d: suspend/resume impossible!\n", i);
	}
}

void __init setup_io_epic(void)
{
	/*
	 * Set up IO-EPIC IRQ routing.
	 */
	setup_ioepic_ids_from_mpc_nocheck();
	setup_io_epic_irqs();
	alloc_ioepic_saved_registers();
}

void __init mp_register_ioepic(int ver, int id, int node, unsigned long address,
				u32 gsi_base)
{
	int idx = nr_ioepics;
	unsigned long flags;
	struct mp_ioepic_gsi *gsi_cfg;
	union IO_EPIC_ID reg_id;
	union IO_EPIC_VERSION reg_version;


	if (nr_ioepics > MAX_IO_EPICS) {
		pr_warn("Max # of IO-EPICs (%d) reached, ignoring %d\n",
			MAX_IO_EPICS, nr_ioepics);
		return;
	}

	if (!address) {
		pr_warn("NULL IO-EPIC address in MP-table, ignoring %d",
			nr_ioepics);
		return;
	}

	ioepics[idx].mp_config.epicaddr = address;

	raw_spin_lock_irqsave(&ioepic_lock, flags);
	reg_id.raw = io_epic_read(idx, IOEPIC_ID);
	reg_version.raw = io_epic_read(idx, IOEPIC_VERSION);
	raw_spin_unlock_irqrestore(&ioepic_lock, flags);

	if (reg_id.raw == -1 && reg_version.raw == -1)
		pr_warn("IO-EPIC (mpc_id %d) is unusable\n", id);

	/* Get id, node and PCI bus from MP-table; get version from the register */
	ioepics[idx].mp_config.epicid = id;
	ioepics[idx].mp_config.nodeid = node;
	ioepics[idx].mp_config.epicver = reg_version.bits.version;
	ioepics[idx].mp_config.bus = mp_ioepic_find_bus(id);

	/*
	 * Build basic GSI lookup table to facilitate gsi->io_epic lookups
	 * and to prevent reprogramming of IO-EPIC pins (PCI GSIs).
	 */
	gsi_cfg = &ioepics[idx].gsi_config;
	gsi_cfg->gsi_base = gsi_base;
	gsi_cfg->gsi_end = gsi_base + reg_version.bits.entries - 1;

	/*
	 * The number of IO-EPIC IRQ registers (== #pins):
	 */
	ioepics[idx].nr_registers = reg_version.bits.entries;

	if (gsi_cfg->gsi_end >= gsi_top)
		gsi_top = gsi_cfg->gsi_end + 1;

	pr_info("IOEPIC[%d]: epic_id %d, node %d, bus %d, version %d, address 0x%lx, entries %d, GSI %d-%d\n",
		idx, id, node, mpc_ioepic_bus(idx), reg_version.bits.version, address,
		reg_version.bits.entries, gsi_cfg->gsi_base, gsi_cfg->gsi_end);

	nr_ioepics++;
}

/*
 * Only used for mp_INT intsrc MP-table entries. Currently only passed by qemu
 * for virtio
 */
int io_epic_get_PCI_irq_vector(int bus, int slot, int pin)
{
	int ioepic_idx, i, best_guess = -1;

	epic_printk("io_epic_get_PCI_irq_vector() bus:%d, slot:%d, pin:%d\n",
		    bus, slot, pin);
	if (test_bit(bus, mp_bus_not_pci)) {
		epic_printk("PCI BIOS passed nonexistent PCI bus %d!\n", bus);
		return -1;
	}

	for (i = 0; i < mp_irq_entries; i++) {
		int lbus = mp_irqs[i].srcbus, found = 0;

		for (ioepic_idx = 0; ioepic_idx < nr_ioepics; ioepic_idx++)
			if (mpc_ioepic_id(ioepic_idx) == mp_irqs[i].dstapic) {
				found = 1;
				break;
		}
		if (!found)
			continue;

		if (!test_bit(lbus, mp_bus_not_pci) &&
		    !mp_irqs[i].irqtype &&
		    (bus == lbus) &&
		    (slot == ((mp_irqs[i].srcbusirq >> 2) & 0x1f))) {
			int irq = pin_2_irq(i, ioepic_idx, mp_irqs[i].dstirq);

			epic_printk("Found our bus & pin -> IRQ %d\n", irq);

			if (pin == (mp_irqs[i].srcbusirq & 3)) {
				epic_printk("pin == src bus irq == %d\n", pin);
				return irq;
			}
			/*
			 * Use the first all-but-pin matching entry as a
			 * best-guess fuzzy result for broken mptables.
			 */
			if (best_guess < 0) {
				epic_printk("Use the first all-but-pin matching entry as a best-guess fuzzy result IRQ %d\n",
						irq);
				best_guess = irq;
			}
		}
	}
	epic_printk("io_epic_get_PCI_irq_vector() Return IRQ %d\n",
			best_guess);
	return best_guess;
}
EXPORT_SYMBOL(io_epic_get_PCI_irq_vector);

int io_epic_get_fix_irq_vector(int domain, int bus, int slot, int func, int irq)
{
	int i;

	epic_printk("io_epic_get_fix_irq_vector() bus:%d, irq:%d\n",
		bus, irq);

	for (i = 0; i < mp_irq_entries; i++) {
		int lbus = mp_irqs[i].srcbus, found = 0, ioepic_idx;

		for (ioepic_idx = 0; ioepic_idx < nr_ioepics; ioepic_idx++)
			if (mpc_ioepic_id(ioepic_idx) == mp_irqs[i].dstapic &&
				mpc_ioepic_nodeid(ioepic_idx) == domain) {
				found = 1;
				break;
		}
		if (!found)
			continue;

		if ((!test_bit(lbus, mp_bus_not_pci)) &&
			(mp_irqs[i].irqtype == mp_FixINT) &&
			(bus == lbus) &&
			(PCI_SLOT(mp_irqs[i].srcbusirq) == slot) &&
			(PCI_FUNC(mp_irqs[i].srcbusirq) == func) &&
			((irq == mp_irqs[i].dstirq) || irq == 0)) {
			irq = pin_2_irq(i, ioepic_idx, mp_irqs[i].dstirq);
			epic_printk("Found our bus %d slot %d func %d IRQ %d\n",
				lbus, slot, func, irq);
			return irq;
		} else if ((((test_bit(lbus, mp_bus_not_pci)) &&
			(test_bit(bus, mp_bus_not_pci)) &&
			(mp_irqs[i].irqtype == mp_FixINT)) ||
			((test_bit(lbus, mp_bus_not_pci)) &&
			(mp_irqs[i].irqtype == mp_INT) &&
			(irq != 0))) &&
			(irq == mp_irqs[i].srcbusirq)) {
			irq = pin_2_irq(i, ioepic_idx, mp_irqs[i].dstirq);
			epic_printk("Found our bus %d, src IRQ %d -> dst IRQ %d\n",
				lbus, mp_irqs[i].srcbusirq, irq);
			return irq;
		}
	}
	epic_printk("io_epic_get_fix_irq_vector() could not find IRQ\n");
	return -1;
}
EXPORT_SYMBOL(io_epic_get_fix_irq_vector);

int ioepic_suspend(void)
{
	int epic, pin;
	int err = 0;

	for (epic = 0; epic < nr_ioepics; epic++) {
		if (!ioepics[epic].saved_registers) {
			err = -ENOMEM;
			continue;
		}

		for (pin = 0; pin < ioepics[epic].nr_registers; pin++)
			ioepics[epic].saved_registers[pin] =
				ioepic_read_entry(epic, pin);
	}

	return err;
}

static void ioepic_resume_id(int ioepic_idx)
{
	unsigned long flags;
	union IO_EPIC_ID reg_id;

	raw_spin_lock_irqsave(&ioepic_lock, flags);
	reg_id.raw = io_epic_read(ioepic_idx, 0);
	if (reg_id.bits.id != mpc_ioepic_id(ioepic_idx)) {
		reg_id.bits.id = mpc_ioepic_id(ioepic_idx);
		io_epic_write(ioepic_idx, 0, reg_id.raw);
	}
	raw_spin_unlock_irqrestore(&ioepic_lock, flags);
}

/*
 * Restore IO EPIC entries which was saved in the ioepic structure.
 */
int restore_ioepic_entries(void)
{
	int epic, pin;

	for (epic = 0; epic < nr_ioepics; epic++) {
		if (!ioepics[epic].saved_registers)
			continue;

		for (pin = 0; pin < ioepics[epic].nr_registers; pin++)
			ioepic_write_entry(epic, pin,
					   ioepics[epic].saved_registers[pin]);
	}
	return 0;
}

static void ioepic_resume(void)
{
	int ioepic_idx;

	for (ioepic_idx = nr_ioepics - 1; ioepic_idx >= 0; ioepic_idx--)
		ioepic_resume_id(ioepic_idx);

	restore_ioepic_entries();
}

static struct syscore_ops ioepic_syscore_ops = {
	.suspend = ioepic_suspend,
	.resume = ioepic_resume,
};

static int __init ioepic_init_ops(void)
{
	register_syscore_ops(&ioepic_syscore_ops);

	return 0;
}

device_initcall(ioepic_init_ops);

void native_io_epic_print_entries(unsigned int epic, unsigned int nr_entries)
{
	int i;

	pr_info("NR Dest Mask Trig Stat Deli Vect  Sid\n");

	for (i = 0; i < nr_entries; i++) {
		struct IO_EPIC_route_entry entry;

		entry = ioepic_read_entry(epic, i);

		pr_info("%-2d %-4d %1d    %1d    %1d    %1d    0x%-3x 0x%-4x\n",
			i,
			cepic_id_full_to_short(entry.addr_low.bits.dst),
			entry.int_ctrl.bits.mask,
			entry.int_ctrl.bits.trigger,
			entry.int_ctrl.bits.delivery_status,
			entry.msg_data.bits.dlvm,
			entry.msg_data.bits.vector,
			entry.rid.raw);
	}
}

void print_IO_EPIC(int ioepic_idx)
{
	union IO_EPIC_ID reg_id;
	union IO_EPIC_VERSION reg_version;
	unsigned long flags;

	raw_spin_lock_irqsave(&ioepic_lock, flags);
	reg_id.raw = io_epic_read(ioepic_idx, IOEPIC_ID);
	reg_version.raw = io_epic_read(ioepic_idx, IOEPIC_VERSION);
	raw_spin_unlock_irqrestore(&ioepic_lock, flags);

	pr_info("Printing the registers of IO-EPIC#%d:\n",
		mpc_ioepic_id(ioepic_idx));
	pr_info(".... IOEPIC_ID: 0x%x\n", reg_id.raw);
	pr_info("....... physical IOEPIC id: %d\n", reg_id.bits.id);
	pr_info("....... node id: %d\n", reg_id.bits.nodeid);

	pr_info(".... IOEPIC_VERSION: 0x%x\n", reg_version.raw);
	pr_info("....... max redirection entries: %d\n",
		reg_version.bits.entries);
	pr_info("....... IO EPIC version: 0x%x\n",
		reg_version.bits.version);

	pr_info(".... IRQ redirection table:\n");

	native_io_epic_print_entries(ioepic_idx,
		ioepics[ioepic_idx].nr_registers);
}

void print_IO_EPICs(void)
{
	int ioepic_idx;
	struct epic_irq_cfg *cfg;
	unsigned int irq;
	struct irq_chip *chip;

	pr_info("Number of MP IRQ sources: %d\n", mp_irq_entries);
	for (ioepic_idx = 0; ioepic_idx < nr_ioepics; ioepic_idx++)
		pr_info("Number of IO-EPIC #%d registers: %d.\n",
		       mpc_ioepic_id(ioepic_idx),
		       ioepics[ioepic_idx].nr_registers);

	for (ioepic_idx = 0; ioepic_idx < nr_ioepics; ioepic_idx++)
		print_IO_EPIC(ioepic_idx);

	pr_info("IRQ -> ioepic:pin\n");
	for_each_active_irq(irq) {
		chip = irq_get_chip(irq);
		if (chip != &ioepic_chip)
			continue;

		cfg = irq_get_chip_data(irq);
		if (!cfg)
			continue;
		pr_info("%d -> %d:%d\n", irq, cfg->epic, cfg->pin);
	}
}

static inline void mask_msi_ioepic_irq(struct irq_data *data)
{
	unsigned long flags;
	struct irq_cfg *cfg = irq_data_get_irq_chip_data(data);

	raw_spin_lock_irqsave(&ioepic_lock, flags);
	__mask_ioepic_pin(ioapic_cfg_get_idx(cfg), ioapic_cfg_get_pin(cfg));
	raw_spin_unlock_irqrestore(&ioepic_lock, flags);
}

static inline void unmask_msi_ioepic_irq(struct irq_data *data)
{
	unsigned long flags;
	struct irq_cfg *cfg = irq_data_get_irq_chip_data(data);

	raw_spin_lock_irqsave(&ioepic_lock, flags);
	__unmask_ioepic_pin(ioapic_cfg_get_idx(cfg), ioapic_cfg_get_pin(cfg));
	raw_spin_unlock_irqrestore(&ioepic_lock, flags);

}

void ack_msi_ioepic_edge(struct irq_data *data)
{
	ack_apic_edge(data);
}

void ack_msi_ioepic_level(struct irq_data *data)
{
	struct irq_cfg *cfg = irq_data_get_irq_chip_data(data);

	ack_apic_edge(data);
	ioepic_level_eoi(ioapic_cfg_get_idx(cfg), ioapic_cfg_get_pin(cfg));
}

static void msi_ioepic_set_affinity_pin(unsigned int epic, unsigned int pin,
					unsigned int vector, unsigned int dest)
{
	unsigned int msg_data;
	unsigned int addr_low;
	bool masked;

	/* Mask the interrupt in IOEPIC */
	masked = __mask_ioepic_pin(epic, pin);

	msg_data = io_epic_read(epic, IOEPIC_TABLE_MSG_DATA(pin));
	addr_low = io_epic_read(epic, IOEPIC_TABLE_ADDR_LOW(pin));

	/*
	 * IOH and IOH2 have a bug. We must duplicate
	 * destination into data. Fortunately it's possible
	 */
	msg_data = MSI_DATA_VECTOR(vector) | MSI_ADDR_DEST_ID(dest);

	addr_low &= ~MSI_ADDR_DEST_ID_MASK;
	addr_low |= MSI_ADDR_DEST_ID(dest);

	io_epic_write(epic, IOEPIC_TABLE_MSG_DATA(pin), msg_data);
	io_epic_write(epic, IOEPIC_TABLE_ADDR_LOW(pin), addr_low);

	/* Unmask the interrupt, if it was masked here */
	if (masked)
		__unmask_ioepic_pin(epic, pin);

}

static int
msi_ioepic_set_affinity(struct irq_data *data, const struct cpumask *mask,
			bool force)
{
	unsigned int dest;
	unsigned long flags;
	struct irq_cfg *cfg = irq_data_get_irq_chip_data(data);
	unsigned int pin = ioapic_cfg_get_pin(cfg);
	unsigned int epic = ioapic_cfg_get_idx(cfg);
	int ret;

	/* Let IOAPIC find a new vector and dest id */
	if ((ret = __ioapic_set_affinity(data, mask, &dest))) {
		pr_err("%s(): IOAPIC driver failed %d\n", __func__, ret);
		return ret;
	}

	raw_spin_lock_irqsave(&ioepic_lock, flags);

	/* Write changes to IOEPIC */
	msi_ioepic_set_affinity_pin(epic, pin, cfg->vector, dest);

	raw_spin_unlock_irqrestore(&ioepic_lock, flags);

	return IRQ_SET_MASK_OK_NOCOPY;
}

/*
 * IRQ Chip for MSI from IOEPIC to IOAPIC
 */
struct irq_chip ioepic_to_apic_chip = {
	.name			= "MSI-IOEPIC",
	.irq_unmask		= unmask_msi_ioepic_irq,
	.irq_mask		= mask_msi_ioepic_irq,
	.irq_ack		= ack_msi_ioepic_edge,
	.irq_eoi		= ack_msi_ioepic_level,
	.irq_set_affinity	= msi_ioepic_set_affinity,
	.irq_retrigger		= ioapic_retrigger_irq
};

/*
 * io_epic_get_PCI_irq_vector is broken (srcbusirq >> 2 instead of 3)
 * Also selects incorrect irq if one bus:dev:func has several irqs
 */
#if 0
int ioepic_pin_to_irq_num(unsigned int pin, struct pci_dev *dev)
{
	return io_epic_get_PCI_irq_vector(dev->bus->number,
		PCI_SLOT(dev->devfn), pin);
}
#else
int ioepic_node_pin_to_irq(unsigned int pin, unsigned int node)
{
	unsigned int ioepic_idx;

	for (ioepic_idx = 0; ioepic_idx < nr_ioepics; ioepic_idx++)
		if (node == mpc_ioepic_nodeid(ioepic_idx))
			return mp_ioepic_gsi_base(ioepic_idx) + pin;

	return -1;
}

int ioepic_pin_to_irq_num(unsigned int pin, struct pci_dev *dev)
{
	return ioepic_node_pin_to_irq(pin, dev_to_node(&dev->dev));
}
#endif

/* Skip MP-table lookup on APIC machines */
int ioepic_pin_to_msi_ioapic_irq(unsigned int pin, struct pci_dev *dev)
{
	unsigned int dev_node = dev_to_node(&dev->dev);
	unsigned int ioepic_idx;

	for (ioepic_idx = 0; ioepic_idx < nr_ioepics; ioepic_idx++)
		if (dev_node == mpc_ioepic_nodeid(ioepic_idx))
			return mp_ioepic_gsi_base(ioepic_idx) + pin;

	return -1;
}
/*
 * Drivers should call this before request_irq() to find out the real IRQ they
 * are working with.
 */
int ioepic_pin_to_irq(unsigned int pin, struct pci_dev *dev)
{
	int irq = ioepic_pin_to_irq_pic(pin, dev);

	epic_printk("Device %x:%x devfn 0x%x requested IOEPIC pin %d to IRQ %d\n",
		dev->vendor, dev->device, dev->devfn, pin, irq);

	return irq;
}
EXPORT_SYMBOL(ioepic_pin_to_irq);


static void __init msi_ioepic_write_entry(unsigned int epic, unsigned int pin,
			unsigned int trigger, struct msi_msg *msg)
{
	struct IO_EPIC_route_entry entry;

	memset(&entry, 0, sizeof(entry));

	entry.msg_data.raw = msg->data;
	entry.addr_high = msg->address_hi;
	entry.addr_low.raw = msg->address_lo;

	entry.int_ctrl.bits.trigger = trigger;
	entry.int_ctrl.bits.mask = 1;

	ioepic_write_entry(epic, pin, entry);
}

static int __init setup_msi_ioepic_irq(struct pci_dev *pdev,
				unsigned int epic, unsigned int pin)
{
	struct msi_msg msg;
	int ret;
	irq_flow_handler_t hdl;
	struct irq_cfg *cfg;
	unsigned int irq = mp_ioepic_gsi_base(epic) + pin;
	unsigned int trigger = pin_to_trigger[pin];

	/* Add IOEPIC pin to IOAPIC's chip data */
	cfg = irq_get_chip_data(irq);
	__add_pin_to_irq_node(cfg, 0, epic, pin);

	ret = msi_compose_msg(pdev, irq, &msg, -1);
	if (ret < 0)
		return ret;

	msi_ioepic_write_entry(epic, pin, trigger, &msg);

	hdl = trigger ? handle_fasteoi_irq : handle_edge_irq;

	irq_set_chip_and_handler_name(irq, &ioepic_to_apic_chip, hdl,
					trigger ? "level" : "edge");

	epic_printk("EIOH: IOEPIC irq %d for MSI/MSI-X\n", irq);

	return 0;
}

static int __init alloc_msi_ioepic_irqs(unsigned int idx)
{
	unsigned int irq;

	/* Alloc an array of IOAPIC MSI IRQs on 0 node */
	irq = __create_irqs(get_nr_irqs_gsi(), IO_EPIC_NR_REGS, 0);
	if (!irq) {
		destroy_irqs(irq, IO_EPIC_NR_REGS);
		return 1;
	}

	ioepics[idx].gsi_config.gsi_base = irq;
	ioepics[idx].gsi_config.gsi_end = irq + IO_EPIC_NR_REGS - 1;

	return 0;
}

static struct {
	unsigned short dev_id, devfn;
} eioh_dev_table[IO_EPIC_NR_REGS] __initdata = {
	/* 0 - IPMB */
	{ },
	/* 1 - SCI */
	{ PCI_DEVICE_ID_MCST_SPMC },
	/* 2 - System Timer */
	{ },
	/* 3 - Ethernet0_tx0 */
	{ PCI_DEVICE_ID_MCST_MGB, PCI_DEVFN(1, 0) },
	/* 4 - Ethernet0_tx1 */
	{ },
	/* 5 - Ethernet0_rx0 */
	{ },
	/* 6 - Ethernet0_rx1 */
	{ },
	/* 7 - Ethernet0_sys */
	{ },
	/* 8 - HDA (eioh) */
	{ PCI_DEVICE_ID_MCST_HDA },
	/* 9 - Mpv_timers0 */
	{ PCI_DEVICE_ID_MCST_GPIO_MPV_EIOH},
	/* 10 - Mpv_timers1 */
	{ },
	/* 11 - Mpv_timers2 */
	{ },
	/* 12 - GPIO0 */
	{ },
	/* 13 - GPIO1 */
	{ },
	/* 14 - Serial Port */
	{ PCI_DEVICE_ID_MCST_SERIAL },
	/* 15 - I2C/SPI */
	{ PCI_DEVICE_ID_MCST_I2C_SPI_EPIC },
	/* 16 - PCI IRQ A - legacy PCIE */
	{ },
	/* 17 - PCI IRQ B - legacy PCIE */
	{ },
	/* 18 - PCI IRQ C - legacy PCIE */
	{ },
	/* 19 - PCI IRQ D - legacy PCIE */
	{ },
	/* 20 - WD Timer */
	{ },
	/* 21 - SATA */
	{ PCI_DEVICE_ID_MCST_SATA },
	/* 22 - SERR */
	{ },
	/* 23 - Ethernet1_tx0 */
	{PCI_DEVICE_ID_MCST_MGB, PCI_DEVFN(1, 1) },
	/* 24 - Ethernet1_tx1 */
	{ },
	/* 25 - Ethernet1_rx0 */
	{ },
	/* 26 - Ethernet1_rx1 */
	{ },
	/* 27 - Ethernet1_sys */
	{ },
	/* 28 - USB */
	{ PCI_DEVICE_ID_MCST_USB_3_0 },
	/* 29 - WLCC */
	{ },
	/* 30 - can2_0_int (only sapfir-1, for other not used) */
	{ PCI_DEVICE_ID_MCST_ELCAN, PCI_DEVFN(0xb, 1) },
	/* 31 - usb_chrg_int (charging interrupt from usb3) */
	{ },
	/* 47-32 SOC_IRQ[15:0] */
	{ }, { }, { }, { },
	{ }, { }, { }, { },
	{ }, { }, { }, { },
	{ }, { }, { }, { },
	/* 48 - usb1_smi (only sapfir-1, for other not used) */
	{ },
	/* 49 - usb1_int (only sapfir-1, for other not used) */
	{ PCI_DEVICE_ID_MCST_OHCI },
	/* 50 - can2_1_int (only sapfir-1, for other not used) */
	{ PCI_DEVICE_ID_MCST_ELCAN, PCI_DEVFN(0xb, 2) },
};

static void __init fixup_eioh_dev_irq(struct pci_dev *eioh_dev)
{
	unsigned int devfn =  eioh_dev->devfn;
	unsigned short dev_vendor = eioh_dev->vendor;
	unsigned short dev_id = eioh_dev->device;
	unsigned short vendor = PCI_VENDOR_ID_MCST_TMP;
	int pin, i;

	if (dev_vendor != vendor)
		pr_err("EIOH: PCI vendor id mismatch. Expected %x:%x, got %x:%x. devfn 0x%x\n",
			vendor, dev_id, dev_vendor, dev_id, devfn);
	else
		epic_printk("EIOH: Found device %x:%x, devfn 0x%x\n",
			vendor, dev_id, devfn);

	for (pin = -1, i = 0; i < ARRAY_SIZE(eioh_dev_table); i++) {
		if (dev_id != eioh_dev_table[i].dev_id)
			continue;
		if (0 == eioh_dev_table[i].devfn ||
				devfn == eioh_dev_table[i].devfn) {
			pin = i;
			break;
		}
	}
	/* Fixup pin and irq in pci_dev */
	if (pin >= 0) {
		int irq = ioepic_pin_to_irq(pin, eioh_dev);
		if (irq >= 0) {
			epic_printk("EIOH: Fixup pin %d->%d and IRQ %d->%d\n",
				eioh_dev->pin, pin, eioh_dev->irq, irq);
			eioh_dev->pin = pin;
			eioh_dev->irq = irq;
			return;
		}
	}

	epic_printk("EIOH: Default pin %d, IRQ %d\n", eioh_dev->pin,
		eioh_dev->irq);
}

static int __init __setup_msi_ioepic(void)
{
	struct pci_dev *pdev_ioepic = NULL;
	struct pci_dev *pdev_ioapic = NULL;
	unsigned int ioepic_idx;
	unsigned int pin;
	unsigned int ioepic_base_addr;

	/* Find all IOEPICs and save their base addresses in mp_config */
	while ((pdev_ioepic = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
			PCI_DEVICE_ID_MCST_I2C_SPI_EPIC, pdev_ioepic))) {
		union IO_EPIC_VERSION reg_version;

		pci_set_master(pdev_ioepic);
		/* Read IOEPIC base address from BAR3 of I2C/SPI */
		pci_read_config_dword(pdev_ioepic, PCI_BASE_ADDRESS_3,
				&ioepic_base_addr);
		epic_printk("EIOH: Found IOEPIC#%d base: 0x%x\n", nr_ioepics,
					ioepic_base_addr);
		ioepics[nr_ioepics].mp_config.epicaddr = ioepic_base_addr;
		ioepics[nr_ioepics].mp_config.nodeid =
			dev_to_node(&pdev_ioepic->dev);
		ioepics[nr_ioepics].ioepic = pdev_ioepic;

		reg_version.raw = io_epic_read(nr_ioepics, IOEPIC_VERSION);
		ioepics[nr_ioepics].mp_config.epicver = reg_version.bits.version;

		nr_ioepics++;
	}

	if (!nr_ioepics) {
		epic_printk("EIOH: Could not find I2C/SPI IOEPIC device\n");
		return 1;
	}

	/* Find IOAPIC I2C/SPI device on node 0 */
	pdev_ioapic = NULL;
	while ((pdev_ioapic = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
				PCI_DEVICE_ID_MCST_I2C_SPI, pdev_ioapic))) {
		if (dev_to_node(&pdev_ioapic->dev)) {
			epic_printk("EIOH: Skip IOAPIC I2C/SPI on node %d\n",
				dev_to_node(&pdev_ioapic->dev));
			continue;
		}
		break;
	}

	if (!pdev_ioapic) {
		while ((pdev_ioapic = pci_get_device(PCI_VENDOR_ID_ELBRUS,
				PCI_DEVICE_ID_MCST_I2CSPI, pdev_ioapic))) {
			if (dev_to_node(&pdev_ioapic->dev)) {
				epic_printk("EIOH: Skip IOAPIC I2C/SPI on node %d\n",
					dev_to_node(&pdev_ioapic->dev));
				continue;
			}
			break;
		}
	}

	if (!pdev_ioapic) {
		epic_printk("EIOH: Could not find I2C/SPI IOAPIC device\n");
		return 1;
	}


	for (ioepic_idx = 0; ioepic_idx < nr_ioepics; ioepic_idx++) {
		if (alloc_msi_ioepic_irqs(ioepic_idx)) {
			epic_printk("EIOH: Failed to alloc MSI IRQs for IOEPIC#%d\n",
					ioepic_idx);
			return 1;
		}

		for (pin = 0; pin < IO_EPIC_NR_REGS; pin++)
			setup_msi_ioepic_irq(pdev_ioapic, ioepic_idx, pin);
	}

	for (ioepic_idx = 0; ioepic_idx < nr_ioepics; ioepic_idx++) {
		struct pci_dev *dev = NULL;
		for_each_pci_dev(dev) {
			if (dev->bus->number ==
				ioepics[ioepic_idx].ioepic->bus->number)
				fixup_eioh_dev_irq(dev);
		}
	}

	return 0;
}

/* Only setup IOEPIC this way, if this is an APIC system */
static int __init setup_msi_ioepic(void)
{
	if (!cpu_has_epic())
		return __setup_msi_ioepic();
	else
		return 0;
}
subsys_initcall_sync(setup_msi_ioepic);

static void __init fixup_iohub2_dev_irq(struct pci_dev *iohub2_dev)
{
	unsigned int devfn =  iohub2_dev->devfn;
	unsigned short dev_vendor = iohub2_dev->vendor;
	unsigned short dev_id = iohub2_dev->device;
	unsigned short vendor = PCI_VENDOR_ID_MCST_TMP;
	unsigned short id;
	int pin;
	int irq;

	/* pin == -1: skip fixup for this device */
	switch (devfn) {
	case PCI_DEVFN(0, 0): /* PCI bridge */
		id = PCI_DEVICE_ID_MCST_PCI_BRIDGE;
		pin = -1;
		break;
	case PCI_DEVFN(1, 0): /* Ethernet_0 */
		id = PCI_DEVICE_ID_MCST_ETH;
		pin = 4;
		break;
	case PCI_DEVFN(1, 1): /* Ethernet_1 */
		id = PCI_DEVICE_ID_MCST_ETH;
		pin = 10;
		break;
	case PCI_DEVFN(1, 2): /* Ethernet_2 */
		id = PCI_DEVICE_ID_MCST_ETH;
		pin = 14;
		break;
	case PCI_DEVFN(2, 0): /* IDE */
		id = PCI_DEVICE_ID_MCST_IDE_SDHCI;
		pin = 11;
		break;
	case PCI_DEVFN(2, 1): /* I2C/SPI+IOAPIC */
		id = PCI_DEVICE_ID_MCST_I2C_SPI;
		pin = 15; /* Also 0 (PIC), 8 (WD Timer), 2 (System Timer) */
		break;
	case PCI_DEVFN(2, 2): /* Serial Port (ieee1284 + rs232) */
		id = PCI_DEVICE_ID_MCST_PARALLEL_SERIAL;
		pin = 3;
		break;
	case PCI_DEVFN(2, 3): /* HDA */
		id = PCI_DEVICE_ID_MCST_HDA;
		pin = 5;
		break;
	case PCI_DEVFN(2, 4): /* GPIO+MPV */
		id = PCI_DEVICE_ID_MCST_GPIO_MPV;
		pin = 6; /* Also 9 (Mpv_timers12), 7 (GPIO0), 11 (GPIO1) */
		break;
	case PCI_DEVFN(3, 0): /* SATA 3.0 */
		id = PCI_DEVICE_ID_MCST_SATA;
		pin = 20;
		break;
	case PCI_DEVFN(3, 1): /* SATA 3.0 */
		id = PCI_DEVICE_ID_MCST_SATA;
		pin = 21;
		break;
	case PCI_DEVFN(4, 0): /* PCIe 2.0 x4/x1/x1 */
		id = PCI_DEVICE_ID_MCST_PCIe1;
		pin = -1;
		break;
	case PCI_DEVFN(5, 0): /* PCIe 2.0 x2/x1 */
		id = PCI_DEVICE_ID_MCST_PCIe1;
		pin = -1;
		break;
	case PCI_DEVFN(6, 0): /* PCIe 2.0 x1 */
		id = PCI_DEVICE_ID_MCST_PCIe1;
		pin = -1;
		break;
	case PCI_DEVFN(7, 0): /* PCIe 2.0 x1 */
		id = PCI_DEVICE_ID_MCST_PCIe1;
		pin = -1;
		break;
	case PCI_DEVFN(8, 0): /* PCIe 2.0 x16/x8 */
		id = PCI_DEVICE_ID_MCST_PCIe8;
		pin = -1;
		break;
	case PCI_DEVFN(9, 0): /* PCIe 2.0 x8 */
		id = PCI_DEVICE_ID_MCST_PCIe8;
		pin = 1;
		break;
	case PCI_DEVFN(10, 0): /* OHCI-USB 2.0 */
		id = PCI_DEVICE_ID_MCST_OHCI;
		pin = 12;
		break;
	case PCI_DEVFN(10, 1): /* EHCI-USB 2.0 */
		id = PCI_DEVICE_ID_MCST_EHCI;
		pin = 12;
		break;
	case PCI_DEVFN(11, 0): /* OHCI-USB 2.0 */
		id = PCI_DEVICE_ID_MCST_OHCI;
		pin = 13;
		break;
	case PCI_DEVFN(11, 1): /* EHCI-USB 2.0 */
		id = PCI_DEVICE_ID_MCST_EHCI;
		pin = 13;
		break;
	case PCI_DEVFN(12, 0): /* SPMC */
		id = PCI_DEVICE_ID_MCST_SPMC;
		pin = -1;
		break;
	default:
		pr_err("IOHUB2: Found unknown device %x:%x, devfn 0x%x\n",
			dev_vendor, dev_id, devfn);
		return;
	}

	if (dev_vendor != vendor || dev_id != id)
		pr_err("IOHUB2: PCI vendor/device id mismatch. Expected %x:%x, got %x:%x. devfn 0x%x\n",
			vendor, id, dev_vendor, dev_id, devfn);
	else
		epic_printk("IOHUB2: Found device %x:%x, devfn 0x%x\n",
			vendor, id, devfn);

	/* Fixup pin and irq in pci_dev */
	if (pin >= 0) {
		irq = mp_ioapic_gsi_routing(0)->gsi_base + pin;
		epic_printk("IOHUB2: Fixup pin %d->%d and IRQ %d->%d\n",
			iohub2_dev->pin, pin, iohub2_dev->irq, irq);
		iohub2_dev->pin = pin;
		iohub2_dev->irq = irq;
		return;
	}

	epic_printk("IOHUB2: Default pin %d, IRQ %d\n", iohub2_dev->pin,
		iohub2_dev->irq);
}


/* TODO This currently only works with one IOHUB2 / IOAPIC */
static int __init __setup_epic_ioapic(void)
{
	struct pci_dev *pdev_ioapic = NULL;
	struct pci_dev *dev = NULL;

	/* Find IOAPIC I2C/SPI device */
	pdev_ioapic = NULL;
	while ((pdev_ioapic = pci_get_device(PCI_VENDOR_ID_MCST_TMP,
				PCI_DEVICE_ID_MCST_I2C_SPI, pdev_ioapic)))
		break;

	if (!pdev_ioapic) {
		epic_printk("IOHUB2: Could not find I2C/SPI IOAPIC device\n");
		return 1;
	}

	pci_set_master(pdev_ioapic);

	for_each_pci_dev(dev) {
		if (dev->bus->number == pdev_ioapic->bus->number)
			fixup_iohub2_dev_irq(dev);
	}

	return 0;
}
/* Only setup IOAPIC this way, if this is an EPIC system */
static int __init setup_epic_ioapic(void)
{
	if (cpu_has_epic())
		return __setup_epic_ioapic();
	else
		return 0;
}
subsys_initcall_sync(setup_epic_ioapic);

/*
 * Dynamic irq allocate and deallocation
 */
unsigned int __epic_create_irqs(unsigned int from, unsigned int count, int node, unsigned int rid)
{
	struct epic_irq_cfg **cfg;
	unsigned long flags;
	int irq, i;
	int gsi_irqs = get_nr_irqs_gsi();

	if (from < gsi_irqs)
		from = gsi_irqs;

	cfg = kzalloc_node(count * sizeof(cfg[0]), GFP_KERNEL, node);
	if (!cfg)
		return 0;

	irq = irq_alloc_descs_from(from, count, node);
	if (irq < 0)
		goto out_cfgs;

	for (i = 0; i < count; i++) {
		cfg[i] = alloc_irq_cfg(node);
		if (!cfg[i])
			goto out_irqs;
		cfg[i]->rid = rid;
		cfg[i]->node = node;
	}

	raw_spin_lock_irqsave(&vector_lock, flags);
	for (i = 0; i < count; i++)
		if (__epic_assign_irq_vector(irq + i, cfg[i], cpu_online_mask))
			goto out_vecs;
	raw_spin_unlock_irqrestore(&vector_lock, flags);

	for (i = 0; i < count; i++) {
		irq_set_chip_data(irq + i, cfg[i]);
		irq_clear_status_flags(irq + i, IRQ_NOREQUEST);
	}

	kfree(cfg);
	return irq;

out_vecs:
	for (i--; i >= 0; i--)
		__epic_clear_irq_vector(irq + i, cfg[i]);
	raw_spin_unlock_irqrestore(&vector_lock, flags);
out_irqs:
	for (i = 0; i < count; i++) {
		if (cfg[i]) {
			irq_set_chip_data(irq + i, NULL);
			kfree(cfg[i]);
		}
		irq_free_desc(irq + i);
	}
out_cfgs:
	kfree(cfg);
	return 0;
}

unsigned int epic_create_irq_nr(unsigned int from, int node, unsigned int rid)
{
	return __epic_create_irqs(from, 1, node, rid);
}

void epic_destroy_irq(unsigned int irq)
{
	struct epic_irq_cfg *cfg = irq_get_chip_data(irq);
	unsigned long flags;

	irq_set_status_flags(irq, IRQ_NOREQUEST|IRQ_NOPROBE);

	raw_spin_lock_irqsave(&vector_lock, flags);
	__epic_clear_irq_vector(irq, cfg);
	raw_spin_unlock_irqrestore(&vector_lock, flags);

	if (cfg) {
		irq_set_chip_data(irq, NULL);
		kfree(cfg);
	}
	irq_free_desc(irq);
}

void epic_destroy_irqs(unsigned int irq, unsigned int count)
{
	unsigned int i;

	for (i = 0; i < count; i++)
		epic_destroy_irq(irq + i);
}

/*
 * MSI message composition
 */
void native_epic_compose_msi_msg(unsigned int msi_addr_lo,
				unsigned int msi_addr_hi,
				unsigned int irq,
				struct msi_msg *msg)
{
	struct epic_irq_cfg *cfg = irq_get_chip_data(irq);
	union IO_EPIC_MSG_ADDR_LOW addr_low;
	union IO_EPIC_MSG_DATA data;

	addr_low.raw = 0;
	addr_low.bits.MSI = msi_addr_lo >> 20;
	addr_low.bits.dst = cpu_to_full_cepic_id(cfg->dest);

	data.raw = 0;
	data.bits.vector = cfg->vector;

	msg->address_hi = msi_addr_hi;
	msg->address_lo = addr_low.raw;
	msg->data = data.raw;

	epic_printk("MSI irq %d : addr_hi = 0x%08x, addr_lo = 0x%08x, data = 0x%08x\n",
		irq, msg->address_hi, msg->address_lo, msg->data);
}

int epic_msi_compose_msg(struct pci_dev *pdev, unsigned int irq,
			 struct msi_msg *msg)
{
	struct epic_irq_cfg *cfg;
	int err;
	struct iohub_sysdata *sd = pdev->bus->sysdata;

#ifdef CONFIG_E2K
	if (e2k_msi_disabled)
		return -ENXIO;
#endif
	cfg = irq_get_chip_data(irq);
	err = epic_assign_irq_vector(irq, cfg, cpu_online_mask);
	if (err)
		return err;

	native_epic_compose_msi_msg(sd->pci_msi_addr_lo, sd->pci_msi_addr_hi, irq, msg);

	return 0;
}

static int
epic_msi_set_affinity(struct irq_data *data, const struct cpumask *mask,
			bool force)
{
	struct epic_irq_cfg *cfg = irq_data_get_irq_chip_data(data);
	struct msi_msg msg;
	unsigned int dest;
	int ret;

	union IO_EPIC_MSG_ADDR_LOW addr_low;
	union IO_EPIC_MSG_DATA msg_data;

	ret = __ioepic_set_affinity(data, mask, &dest);
	if (ret)
		return ret;

	__get_cached_msi_msg(data->common->msi_desc, &msg);

	addr_low.raw = msg.address_lo;
	addr_low.bits.dst = cpu_to_full_cepic_id(cfg->dest);

	msg_data.raw = msg.data;
	msg_data.bits.vector = cfg->vector;

	msg.address_lo = addr_low.raw;
	msg.data = msg_data.raw;

	pci_write_msi_msg(data->irq, &msg);

	return IRQ_SET_MASK_OK_NOCOPY;
}

#ifdef CONFIG_E2K
static int epic_msi_set_vcpu_affinity(struct irq_data *data, void *vcpu_info)
{
	struct ioepic_vcpu_info *info = vcpu_info;
	struct epic_irq_cfg *cfg = irq_data_get_irq_chip_data(data);

	pci_msi_mask_irq(data);

	/* Restore host MSI configuration, when shutting down irq bypass */
	if (!info->valid) {
		unsigned int msi_addr_lo;
		unsigned int msi_addr_hi;

		get_io_epic_msi(cfg->node, &msi_addr_lo, &msi_addr_hi);
		native_epic_compose_msi_msg(msi_addr_lo, msi_addr_hi, data->irq, &info->msi);
		info->msi_valid = true;
	}

	if (!info->msi_valid)
		return -EINVAL;

	/*
	 * e2k does not support interrupt remapping: write guest vector and dest_id to device
	 * This might cause problems with VFIO (which assumes interrupt remapping)
	 */
	pci_write_msi_msg(data->irq, &info->msi);

	cfg->passthrough = info->valid;

	pci_msi_unmask_irq(data);

	return 0;
}

#endif

/*
 * IRQ Chip for MSI PCI/PCI-X/PCI-Express Devices,
 * which implement the MSI or MSI-X Capability Structure.
 */
static struct irq_chip msi_chip = {
	.name			= "PCI-MSI",
	.irq_unmask		= pci_msi_unmask_irq,
	.irq_mask		= pci_msi_mask_irq,
	.irq_ack		= ack_epic_edge,
	.irq_set_affinity	= epic_msi_set_affinity,
	.irq_retrigger		= ioepic_retrigger_irq,
#ifdef CONFIG_E2K
	.irq_set_vcpu_affinity	= epic_msi_set_vcpu_affinity
#endif
};

int epic_setup_msi_irq(struct pci_dev *dev, struct msi_desc *msidesc,
		  unsigned int irq_base, unsigned int irq_offset)
{
	struct irq_chip *chip = &msi_chip;
	struct msi_msg msg;
	unsigned int irq = irq_base + irq_offset;
	int ret;

	ret = epic_msi_compose_msg(dev, irq, &msg);
	if (ret < 0)
		return ret;

	irq_set_msi_desc_off(irq_base, irq_offset, msidesc);

	/*
	 * MSI-X message is written per-IRQ, the offset is always 0.
	 * MSI message denotes a contiguous group of IRQs, written for 0th IRQ.
	 */
	if (!irq_offset)
		pci_write_msi_msg(irq, &msg);

	irq_set_chip_and_handler_name(irq, chip, handle_edge_irq, "edge");

	dev_dbg(&dev->dev, "irq %d for MSI/MSI-X\n", irq);

	return 0;
}

int native_setup_msi_irqs_epic(struct pci_dev *dev, int nvec, int type)
{
	unsigned int irq, irq_want;
	struct msi_desc *msidesc;
	int node, ret;

	/* Multiple MSI vectors only supported with interrupt remapping */
	if (type == PCI_CAP_ID_MSI && nvec > 1)
		return 1;

	node = dev_to_node(&dev->dev);
	irq_want = get_nr_irqs_gsi();
	list_for_each_entry(msidesc, dev_to_msi_list(&dev->dev), list) {
		irq = epic_create_irq_nr(irq_want, node, dev->bus->number << 8 | dev->devfn);
		if (irq == 0)
			return -ENOSPC;

		irq_want = irq + 1;

		ret = epic_setup_msi_irq(dev, msidesc, irq, 0);
		if (ret < 0)
			goto error;
	}
	return 0;

error:
	epic_destroy_irq(irq);
	return ret;
}

void native_teardown_msi_irq_epic(unsigned int irq)
{
	epic_destroy_irq(irq);
}

static bool irqchip_is_ioepic(struct irq_chip *chip)
{
	return chip == &ioepic_chip || chip == &msi_chip;
}

void fixup_irqs_epic(void)
{
	unsigned int vector;

	/*
	 * We can remove mdelay() and then send spuriuous interrupts to
	 * new cpu targets for all the irqs that were handled previously by
	 * this cpu. While it works, I have seen spurious interrupt messages
	 * (nothing wrong but still...).
	 *
	 * So for now, retain mdelay(1) and check the IRR and then send those
	 * interrupts to new targets as this cpu is already offlined...
	 */
	mdelay(1);

	for (vector = FIRST_EXTERNAL_VECTOR; vector < NR_VECTORS; vector++) {
		unsigned int irr;

		if (__this_cpu_read(vector_irq[vector]) < 0)
			continue;

		irr = epic_read_w(CEPIC_PMIRR + vector / 32 * 0x4);
		if (irr  & (1 << (vector % 32))) {
			unsigned int irq = __this_cpu_read(vector_irq[vector]);
			struct irq_desc *desc = irq_to_desc(irq);
			struct irq_data *data = irq_desc_get_irq_data(desc);
			struct irq_chip *chip = irq_data_get_irq_chip(data);
			raw_spin_lock(&desc->lock);
			if (chip->irq_retrigger)
				chip->irq_retrigger(data);
			raw_spin_unlock(&desc->lock);
		}
		__this_cpu_write(vector_irq[vector], -1);
	}
}

/* Reset IOEPIC registers (for kexec) */
void reset_io_epic(void)
{
	unsigned int epic, pin;

	for (epic = 0; epic < nr_ioepics; epic++)
		for (pin = 0; pin < ioepics[epic].nr_registers; pin++)
			io_epic_reset_pin_rid(epic, pin);
}
