#ifndef __ASM_L_IO_PIC_H
#define __ASM_L_IO_PIC_H

/*
 * Choose between IO-PICs in arch/l. If CONFIG_EPIC=n, IO-APIC is chosen
 * statically. If CONFIG_EPIC=y (only on e2k), use both IO-APIC and IO-EPIC
 * calls, depending on nr_ioapics and nr_ioepics variables
 */

#ifdef CONFIG_EPIC

#include <asm/io_apic.h>
#include <asm/io_epic.h>

struct io_apic_irq_attr;
extern int io_epic_get_PCI_irq_vector(int bus, int devfn, int pin);
extern int IO_APIC_get_PCI_irq_vector(int domain, int bus, int devfn, int pin,
					struct io_apic_irq_attr *irq_attr);
static inline int IO_PIC_get_PCI_irq_vector(int domain, int bus, int slot,
				int pin, struct io_apic_irq_attr *irq_attr)
{
	int pic_irq = -1;

	if (nr_ioepics)
		pic_irq = io_epic_get_PCI_irq_vector(bus, slot, pin);

	if (pic_irq == -1 && nr_ioapics)
		pic_irq = IO_APIC_get_PCI_irq_vector(domain, bus, slot, pin,
								irq_attr);
	return pic_irq;
}

extern int io_epic_get_fix_irq_vector(int domain, int bus, int slot, int func,
	int irq);
extern int IO_APIC_get_fix_irq_vector(int domain, int bus, int slot, int func,
					int irq);
static inline int IO_PIC_get_fix_irq_vector(int domain, int bus, int slot,
							int func, int irq)
{
	int pic_irq = -1;

	if (nr_ioepics)
		pic_irq = io_epic_get_fix_irq_vector(domain, bus, slot, func,
			irq);

	if (pic_irq == -1 && nr_ioapics)
		pic_irq = IO_APIC_get_fix_irq_vector(domain, bus, slot, func,
							irq);
	return pic_irq;
}

extern void __epic_setup_vector_irq(int cpu);
extern void __apic_setup_vector_irq(int cpu);
static inline void __pic_setup_vector_irq(int cpu)
{
	if (nr_ioepics)
		__epic_setup_vector_irq(cpu);
	if (nr_ioapics)
		__apic_setup_vector_irq(cpu);
}

extern void fixup_irqs_epic(void);
extern void fixup_irqs_apic(void);
static inline void fixup_irqs_pic(void)
{
	if (nr_ioepics)
		fixup_irqs_epic();
	if (nr_ioapics)
		fixup_irqs_apic();
}

extern void print_IO_APICs(void);
extern void print_IO_EPICs(void);
static inline void print_IO_PICs(void)
{
	if (nr_ioepics)
		print_IO_EPICs();
	if (nr_ioapics)
		print_IO_APICs();
}

#else /* !(CONFIG_EPIC) */

#include <asm/io_apic.h>

struct io_apic_irq_attr;
extern int IO_APIC_get_PCI_irq_vector(int domain, int bus, int devfn, int pin,
					struct io_apic_irq_attr *irq_attr);
static inline int IO_PIC_get_PCI_irq_vector(int domain, int bus, int slot,
				int pin, struct io_apic_irq_attr *irq_attr)
{
	return IO_APIC_get_PCI_irq_vector(domain, bus, slot, pin, irq_attr);
}

extern int IO_APIC_get_fix_irq_vector(int domain, int bus, int slot, int func,
					int irq);
static inline int IO_PIC_get_fix_irq_vector(int domain, int bus, int slot,
							int func, int irq)
{
	return IO_APIC_get_fix_irq_vector(domain, bus, slot, func, irq);
}

extern void __apic_setup_vector_irq(int cpu);
static inline void __pic_setup_vector_irq(int cpu)
{
	__apic_setup_vector_irq(cpu);
}

extern void fixup_irqs_apic(void);
static inline void fixup_irqs_pic(void)
{
	fixup_irqs_apic();
}

extern void print_IO_APICs(void);
static inline void print_IO_PICs(void)
{
	print_IO_APICs();
}

#endif	/* !(CONFIG_EPIC) */
#endif	/* __ASM_L_IO_PIC_H */
