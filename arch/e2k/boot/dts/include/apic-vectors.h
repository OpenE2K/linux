#ifndef _APIC_VECTORS_H
#define _APIC_VECTORS_H

/*
 * Linux IRQ vector layout.
 *
 * There are 256 IDT entries (per CPU - each entry is 8 bytes) which can
 * be defined by Linux. They are used as a jump table by the CPU when a
 * given vector is triggered - by a CPU-external, CPU-internal or
 * software-triggered event.
 *
 * Linux sets the kernel code address each entry jumps to early during
 * bootup, and never changes them. This is the general layout of the
 * IDT entries:
 *
 *  Vectors   0 ...  31 : system traps and exceptions - hardcoded events
 *  Vectors  32 ... 127 : device interrupts
 *  Vector  128         : legacy int80 syscall interface
 *  Vectors 129 ... 237 : device interrupts
 *  Vectors 238 ... 255 : special interrupts
 *
 * This file enumerates the exact layout of them:
 */

/*
 * Reserve the lowest usable vector (and hence lowest priority)  0x20 for
 * triggering cleanup after irq migration. 0x21-0x2f will still be used
 * for device interrupts.
 */
#define IRQ_MOVE_CLEANUP_VECTOR		0x20

#define SPURIOUS_APIC_VECTOR		0xff
#define ERROR_APIC_VECTOR		0xfe
#define RESCHEDULE_VECTOR		0xfd
#define CALL_FUNCTION_VECTOR		0xfc
/* VIRQ vector to emulate SysRq on guest kernel */
#define	SYSRQ_SHOWSTATE_APIC_VECTOR	0xfa
/* VIRQ vector to emulate NMI on guest kernel */
#define	KVM_NMI_APIC_VECTOR		0xee
#define CALL_FUNCTION_SINGLE_VECTOR	0xfb
#define RDMA_INTERRUPT_VECTOR		0xf9
#define LVT3_INTERRUPT_VECTOR		0xf8
#define LVT4_INTERRUPT_VECTOR		0xf7
#define IRQ_WORK_VECTOR			0xf6

#define MANAGED_IRQ_SHUTDOWN_VECTOR	0xef

#define LOCAL_TIMER_VECTOR		0xee

#endif
