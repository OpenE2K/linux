#ifndef __ASM_L_PIC_H
#define __ASM_L_PIC_H

/*
 * Choose between PICs in arch/l. If CONFIG_EPIC=n, APIC is chosen statically
 * If CONFIG_EPIC=y (only on e2k), choose dynamically based on CPU_FEAT_EPIC
 */

extern int first_system_vector;
extern int apic_get_vector(void);

#ifdef CONFIG_EPIC

#include <asm/apic.h>
#include <asm/epic.h>
#include <asm/machdep.h>


static inline unsigned int read_pic_id(void)
{
	if (cpu_has_epic())
		return read_epic_id();
	else
		return read_apic_id();
}

extern void epic_processor_info(int epicid, int version,
					unsigned int cepic_freq);
extern int generic_processor_info(int apicid, int version);
static inline void pic_processor_info(int picid, int picver, unsigned int freq)
{
	if (cpu_has_epic())
		epic_processor_info(picid, picver, freq);
	else
		generic_processor_info(picid, picver);
}

extern int get_cepic_timer_frequency(void);
static inline int get_pic_timer_frequency(void)
{
	if (cpu_has_epic())
		return get_cepic_timer_frequency();
	else
		return -1;	/* standard constant value */
}


/* IO-APIC definitions */
struct irq_data;
extern void ioapic_ack_epic_edge(struct irq_data *data);
extern void ack_apic_edge(struct irq_data *data);
static inline void ioapic_ack_pic_edge(struct irq_data *data)
{
	if (cpu_has_epic())
		ioapic_ack_epic_edge(data);
	else
		ack_apic_edge(data);
}

extern void ioapic_ack_epic_level(struct irq_data *data);
extern void ack_apic_level(struct irq_data *data);
static inline void ioapic_ack_pic_level(struct irq_data *data)
{
	if (cpu_has_epic())
		ioapic_ack_epic_level(data);
	else
		ack_apic_level(data);
}

struct irq_chip;
extern struct irq_chip ioepic_to_apic_chip;
static inline bool irqchip_is_ioepic_to_apic(struct irq_chip *chip)
{
	return chip == &ioepic_to_apic_chip;
}

/* IRQ definitions */
#ifdef CONFIG_IRQ_WORK
extern void epic_irq_work_raise(void);
extern void apic_irq_work_raise(void);
static inline void pic_irq_work_raise(void)
{
	if (cpu_has_epic())
		epic_irq_work_raise();
	else
		apic_irq_work_raise();
}
#endif

#ifdef CONFIG_SMP
extern void epic_send_call_function_ipi_mask(const struct cpumask *mask);
extern void apic_send_call_function_ipi_mask(const struct cpumask *mask);
static inline void pic_send_call_function_ipi_mask(const struct cpumask *mask)
{
	if (cpu_has_epic())
		epic_send_call_function_ipi_mask(mask);
	else
		apic_send_call_function_ipi_mask(mask);
}

extern void epic_send_call_function_single_ipi(int cpu);
extern void apic_send_call_function_single_ipi(int cpu);
static inline void pic_send_call_function_single_ipi(int cpu)
{
	if (cpu_has_epic())
		epic_send_call_function_single_ipi(cpu);
	else
		apic_send_call_function_single_ipi(cpu);
}

extern void epic_smp_send_reschedule(int cpu);
extern void apic_smp_send_reschedule(int cpu);
static inline void pic_send_reschedule(int cpu)
{
	if (cpu_has_epic())
		epic_smp_send_reschedule(cpu);
	else
		apic_smp_send_reschedule(cpu);
}
#endif

struct pt_regs;
extern noinline notrace void epic_do_nmi(struct pt_regs *regs);
extern noinline notrace void apic_do_nmi(struct pt_regs *regs);
static inline void pic_do_nmi(struct pt_regs *regs)
{
	if (cpu_has_epic())
		epic_do_nmi(regs);
	else
		apic_do_nmi(regs);
}

static inline void ack_pic_irq(void)
{
	if (cpu_has_epic())
		ack_epic_irq();
	else
		ack_APIC_irq();
}

/* For do_postpone_tick() */
extern void cepic_timer_interrupt(void);
extern void local_apic_timer_interrupt(void);
static inline void local_pic_timer_interrupt(void)
{
	if (cpu_has_epic())
		cepic_timer_interrupt();
	else
		local_apic_timer_interrupt();
}

extern int print_local_APICs(bool force);
extern int print_epics(bool force);
static inline int print_local_pics(bool force)
{
	if (cpu_has_epic())
		return print_epics(force);
	else
		return print_local_APICs(force);
}

struct pci_dev;
extern int native_setup_msi_irqs_epic(struct pci_dev *dev, int nvec, int type);
extern int native_setup_msi_irqs_apic(struct pci_dev *dev, int nvec, int type);
static inline int setup_msi_irqs_pic(struct pci_dev *dev, int nvec, int type)
{
	if (cpu_has_epic())
		return native_setup_msi_irqs_epic(dev, nvec, type);
	else
		return native_setup_msi_irqs_apic(dev, nvec, type);
}

extern void native_teardown_msi_irq_epic(unsigned int irq);
extern void native_teardown_msi_irq_apic(unsigned int irq);
static inline void teardown_msi_irq_pic(unsigned int irq)
{
	if (cpu_has_epic())
		native_teardown_msi_irq_epic(irq);
	else
		native_teardown_msi_irq_apic(irq);
}

extern void __init_recv setup_secondary_epic_clock(void);
extern void setup_secondary_APIC_clock(void);
static inline void __init_recv setup_secondary_pic_clock(void)
{
	if (cpu_has_epic())
		setup_secondary_epic_clock();
	else
		setup_secondary_APIC_clock();
}

extern int epic_get_vector(void);
static inline int pic_get_vector(void)
{
	if (cpu_has_epic())
		return epic_get_vector();
	else
		return apic_get_vector();
}

extern int ioepic_pin_to_irq_num(unsigned int pin, struct pci_dev *dev);
extern int ioepic_pin_to_msi_ioapic_irq(unsigned int pin, struct pci_dev *dev);
static inline int ioepic_pin_to_irq_pic(unsigned int pin, struct pci_dev *dev)
{
	if (cpu_has_epic())
		return ioepic_pin_to_irq_num(pin, dev);
	else
		return ioepic_pin_to_msi_ioapic_irq(pin, dev);
}

static inline void __init setup_boot_pic_clock(void)
{
	if (cpu_has_epic())
		setup_boot_epic_clock();
	else
		setup_boot_APIC_clock();
}

extern void __init init_apic_mappings(void);
static inline void __init init_pic_mappings(void)
{
	if (!cpu_has_epic())
		return init_apic_mappings();
}

extern void setup_cepic(void);

#else /* !(CONFIG_EPIC) */

#include <asm/apic.h>

static inline unsigned int read_pic_id(void)
{
	return read_apic_id();
}

extern int generic_processor_info(int apicid, int version);
static inline void pic_processor_info(int picid, int picver, unsigned int freq)
{
	generic_processor_info(picid, picver);
}

static inline int get_pic_timer_frequency(void)
{
	return -1;	/* standard constant value */
}

/* IO-APIC definitions */
struct irq_data;
extern void ack_apic_edge(struct irq_data *data);
static inline void ioapic_ack_pic_edge(struct irq_data *data)
{
	ack_apic_edge(data);
}

extern void ack_apic_level(struct irq_data *data);
static inline void ioapic_ack_pic_level(struct irq_data *data)
{
	ack_apic_level(data);
}

struct irq_chip;
static inline bool irqchip_is_ioepic_to_apic(struct irq_chip *chip)
{
	return 0;
}

/* IRQ definitions */
extern void apic_irq_work_raise(void);
static inline void pic_irq_work_raise(void)
{
	apic_irq_work_raise();
}

extern void apic_send_call_function_ipi_mask(const struct cpumask *mask);
static inline void pic_send_call_function_ipi_mask(const struct cpumask *mask)
{
	apic_send_call_function_ipi_mask(mask);
}

extern void apic_send_call_function_single_ipi(int cpu);
static inline void pic_send_call_function_single_ipi(int cpu)
{
	apic_send_call_function_single_ipi(cpu);
}

extern void apic_smp_send_reschedule(int cpu);
static inline void pic_send_reschedule(int cpu)
{
	apic_smp_send_reschedule(cpu);
}

struct pt_regs;
extern noinline notrace void apic_do_nmi(struct pt_regs *regs);
static inline void pic_do_nmi(struct pt_regs *regs)
{
	apic_do_nmi(regs);
}

static inline void ack_pic_irq(void)
{
	ack_APIC_irq();
}

/* For do_postpone_tick() */
extern void local_apic_timer_interrupt(void);
static inline void local_pic_timer_interrupt(void)
{
	local_apic_timer_interrupt();
}

extern int print_local_APICs(bool force);
static inline int print_local_pics(bool force)
{
	return print_local_APICs(force);
}

struct pci_dev;
extern int native_setup_msi_irqs_apic(struct pci_dev *dev, int nvec, int type);
static inline int setup_msi_irqs_pic(struct pci_dev *dev, int nvec, int type)
{
	return native_setup_msi_irqs_apic(dev, nvec, type);
}

extern void native_teardown_msi_irq_apic(unsigned int irq);
static inline void teardown_msi_irq_pic(unsigned int irq)
{
	native_teardown_msi_irq_apic(irq);
}

static inline void __init setup_boot_pic_clock(void)
{
	setup_boot_APIC_clock();
}

extern void __init init_apic_mappings(void);
static inline void __init init_pic_mappings(void)
{
	return init_apic_mappings();
}
#endif	/* !(CONFIG_EPIC) */
#endif	/* __ASM_L_PIC_H */
